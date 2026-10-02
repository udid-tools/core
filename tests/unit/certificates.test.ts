import { createHash, createHmac } from "node:crypto";

import * as asn1js from "asn1js";
import { AuthenticatedSafe, CertBag, PFX, SafeContents } from "pkijs";
import { beforeAll, describe, expect, it } from "vitest";

import { decodeBinaryInput, loadSigningMaterial } from "../../src/certificates/index.js";
import { decodePem } from "../../src/certificates/binary-input.js";
import { UdidToolsError } from "../../src/errors.js";
import { resolveLimits } from "../../src/limits.js";
import type { SigningOptions } from "../../src/types.js";
import {
  certificatePem,
  certificateDer,
  createEcPkcs12,
  createPkcs12,
  createSyntheticIdentity,
  type SyntheticIdentity,
} from "../helpers/synthetic-identity.js";

function repeated(value: Uint8Array, length: number): Uint8Array {
  const result = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    result[index] = value[index % value.byteLength] ?? 0;
  }
  return result;
}

function addBigEndian(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.byteLength);
  let carry = 0;
  for (let index = left.byteLength - 1; index >= 0; index -= 1) {
    const sum = (left[index] ?? 0) + (right[index] ?? 0) + carry;
    result[index] = sum & 0xff;
    carry = sum >>> 8;
  }
  return result;
}

function pkcs12Kdf(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
  purpose: number,
  length: number,
  hashAlgorithm: "sha1" | "sha256"
): Uint8Array {
  const hashLength = hashAlgorithm === "sha1" ? 20 : 32;
  const blockLength = 64;
  const password = Buffer.from(`${passphrase}\u0000`, "utf16le");
  password.swap16();
  const diversifier = new Uint8Array(blockLength).fill(purpose);
  const saltBlock =
    salt.byteLength === 0
      ? new Uint8Array()
      : repeated(salt, blockLength * Math.ceil(salt.byteLength / blockLength));
  const passwordBlock =
    password.byteLength === 0
      ? new Uint8Array()
      : repeated(password, blockLength * Math.ceil(password.byteLength / blockLength));
  const source = new Uint8Array(saltBlock.byteLength + passwordBlock.byteLength);
  source.set(saltBlock);
  source.set(passwordBlock, saltBlock.byteLength);
  const output = new Uint8Array(Math.ceil(length / hashLength) * hashLength);

  for (let block = 0; block < output.byteLength / hashLength; block += 1) {
    let digest = createHash(hashAlgorithm).update(diversifier).update(source).digest();
    for (let iteration = 1; iteration < iterations; iteration += 1) {
      digest = createHash(hashAlgorithm).update(digest).digest();
    }
    output.set(digest, block * hashLength);

    const b = repeated(Uint8Array.from(digest), blockLength);
    const one = new Uint8Array(blockLength);
    one[blockLength - 1] = 1;
    for (let offset = 0; offset < source.byteLength; offset += blockLength) {
      const chunk = source.subarray(offset, offset + blockLength);
      source.set(addBigEndian(addBigEndian(chunk, b), one), offset);
    }
  }

  return output.subarray(0, length);
}

function rewritePfx(input: Uint8Array, passphrase: string, mutate: (pfx: PFX) => void): Uint8Array {
  const pfx = PFX.fromBER(Uint8Array.from(input).buffer);
  mutate(pfx);
  if (pfx.authSafe.content instanceof asn1js.OctetString && pfx.macData !== undefined) {
    const content = Uint8Array.from(new Uint8Array(pfx.authSafe.content.getValue()));
    const digestOid = pfx.macData.mac.digestAlgorithm.algorithmId;
    const hashAlgorithm = digestOid === "1.3.14.3.2.26" ? "sha1" : "sha256";
    const key = pkcs12Kdf(
      passphrase,
      Uint8Array.from(new Uint8Array(pfx.macData.macSalt.valueBlock.valueHexView)),
      pfx.macData.iterations ?? 1,
      3,
      hashAlgorithm === "sha1" ? 20 : 32,
      hashAlgorithm
    );
    pfx.macData.mac.digest = new asn1js.OctetString({
      valueHex: Uint8Array.from(createHmac(hashAlgorithm, key).update(content).digest()).buffer,
    });
  }
  return Uint8Array.from(new Uint8Array(pfx.toSchema().toBER(false)));
}

function rewriteAuthenticatedSafe(
  input: Uint8Array,
  passphrase: string,
  mutate: (authenticatedSafe: AuthenticatedSafe) => void
): Uint8Array {
  return rewritePfx(input, passphrase, (pfx) => {
    if (!(pfx.authSafe.content instanceof asn1js.OctetString)) {
      throw new Error("Expected an authenticated safe content octet string.");
    }
    const authenticatedSafe = AuthenticatedSafe.fromBER(pfx.authSafe.content.getValue());
    mutate(authenticatedSafe);
    pfx.authSafe.content = new asn1js.OctetString({
      valueHex: authenticatedSafe.toSchema().toBER(false),
    });
  });
}

function rewriteSafeContents(
  input: Uint8Array,
  passphrase: string,
  mutate: (safeContents: SafeContents) => void
): Uint8Array {
  return rewriteAuthenticatedSafe(input, passphrase, (authenticatedSafe) => {
    for (const contentInfo of authenticatedSafe.safeContents) {
      if (
        contentInfo.contentType !== "1.2.840.113549.1.7.1" ||
        !(contentInfo.content instanceof asn1js.OctetString)
      ) {
        continue;
      }
      const safeContents = SafeContents.fromBER(contentInfo.content.getValue());
      mutate(safeContents);
      contentInfo.content = new asn1js.OctetString({
        valueHex: safeContents.toSchema().toBER(false),
      });
    }
  });
}

describe("certificate inputs and PKCS#12 identities", () => {
  let identity: SyntheticIdentity;
  let pkcs12: Uint8Array;

  beforeAll(() => {
    identity = createSyntheticIdentity();
    // The actual signer certificate is intentionally not first. Selection must
    // be based on the RSA public key, never certificate bag order.
    pkcs12 = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.unrelatedCertificate, identity.leafCertificate, identity.rootCertificate],
      "correct horse battery staple"
    );
  });

  it("strictly decodes base64 and returns a defensive copy", () => {
    const limits = resolveLimits(undefined);
    const decoded = decodeBinaryInput(
      { encoding: "base64", value: Buffer.from("hello").toString("base64") },
      limits
    );
    expect(Buffer.from(decoded).toString("utf8")).toBe("hello");

    const original = new Uint8Array([1, 2, 3]);
    const copied = decodeBinaryInput(original, limits);
    copied[0] = 9;
    expect(original[0]).toBe(1);
  });

  it("rejects malformed and over-limit binary inputs without echoing input", () => {
    const limits = resolveLimits({ maxCertificateBytes: 2 });
    expect(() => decodeBinaryInput({ encoding: "base64", value: "not-base64" }, limits)).toThrow(
      UdidToolsError
    );

    try {
      decodeBinaryInput(new Uint8Array([1, 2, 3]), limits);
      expect.unreachable("Expected the configured limit to be enforced");
    } catch (error) {
      expect(error).toBeInstanceOf(UdidToolsError);
      expect((error as UdidToolsError).code).toBe("INPUT_TOO_LARGE");
      expect((error as Error).message).not.toContain("1,2,3");
    }

    expect(() =>
      decodePem(
        "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
        resolveLimits({ maxStringBytes: 8 })
      )
    ).toThrow(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));
  });

  it("rejects empty, non-canonical, oversized, and malformed encoded inputs", () => {
    const limits = resolveLimits(undefined);
    expect(() => decodeBinaryInput(new Uint8Array(), limits)).toThrow(
      expect.objectContaining({ code: "INVALID_CERTIFICATE" })
    );
    expect(() => decodeBinaryInput({ encoding: "base64", value: "AB==" }, limits)).toThrow(
      expect.objectContaining({ code: "INVALID_CERTIFICATE" })
    );
    expect(() =>
      decodeBinaryInput({ encoding: "base64", value: "AAAA" }, resolveLimits({ maxStringBytes: 3 }))
    ).toThrow(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));
    expect(() =>
      decodeBinaryInput({ encoding: "pem", value: "not a PEM document" }, limits)
    ).toThrow(expect.objectContaining({ code: "INVALID_CERTIFICATE" }));
    expect(() =>
      decodeBinaryInput(
        {
          encoding: "pem",
          value: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
        },
        limits,
        { pemLabels: ["CERTIFICATE"] }
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_CERTIFICATE" }));
  });

  it("rejects invalid runtime shapes even when JavaScript bypasses TypeScript", () => {
    const limits = resolveLimits(undefined);
    expect(() => decodeBinaryInput(null as unknown as Uint8Array, limits)).toThrow(
      expect.objectContaining({ code: "INVALID_CERTIFICATE" })
    );
    expect(() =>
      decodeBinaryInput({ encoding: "hex", value: "00" } as unknown as Uint8Array, limits)
    ).toThrow(expect.objectContaining({ code: "INVALID_CERTIFICATE" }));
  });

  it("finds the signer certificate by its public key and deduplicates the chain", () => {
    const signing: SigningOptions = {
      certificateChain: [
        { encoding: "pem", value: certificatePem(identity.leafCertificate) },
        { encoding: "pem", value: certificatePem(identity.rootCertificate) },
      ],
      identity: {
        data: pkcs12,
        passphrase: "correct horse battery staple",
        type: "pkcs12",
      },
    };

    const material = loadSigningMaterial(signing, resolveLimits(undefined));
    expect(
      Buffer.from(material.signerCertificate.serialNumber.valueBlock.valueHexView).toString("hex")
    ).toBe("02");
    expect(Buffer.from(material.privateKey.export({ format: "der", type: "pkcs8" }))).toEqual(
      Buffer.from(identity.leafKeys.privateKey.export({ format: "der", type: "pkcs8" }))
    );
    expect(material.certificates).toHaveLength(3);
    expect(material.warnings).toContainEqual(
      expect.objectContaining({ code: "DUPLICATE_CERTIFICATE_IGNORED" })
    );
  });

  it("returns a stable passphrase error without exposing the passphrase", () => {
    try {
      loadSigningMaterial(
        {
          identity: {
            data: pkcs12,
            passphrase: "super-secret-wrong-passphrase",
            type: "pkcs12",
          },
        },
        resolveLimits(undefined)
      );
      expect.unreachable("Expected the wrong passphrase to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(UdidToolsError);
      expect((error as UdidToolsError).code).toBe("INCORRECT_PASSPHRASE");
      expect((error as Error).message).not.toContain("super-secret-wrong-passphrase");
    }
  });

  it("enforces PKCS#12 and certificate-count limits before crypto work", () => {
    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: pkcs12,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits({ maxInputBytes: pkcs12.byteLength - 1 })
      )
    ).toThrow(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));

    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: pkcs12,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits({ maxCertificates: 2 })
      )
    ).toThrow(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));
  });

  it("rejects malformed and incomplete PKCS#12 identities", () => {
    expect(() =>
      loadSigningMaterial(
        { identity: { data: new Uint8Array([0x30, 0x00]), type: "pkcs12" } },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));
    expect(() =>
      loadSigningMaterial(
        { identity: { data: new Uint8Array([0xff]), type: "pkcs12" } },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));

    const certificateOnly = createPkcs12(
      null,
      [identity.leafCertificate, identity.rootCertificate],
      "passphrase"
    );
    expect(() =>
      loadSigningMaterial(
        {
          identity: { data: certificateOnly, passphrase: "passphrase", type: "pkcs12" },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "MISSING_SIGNING_MATERIAL" }));

    const keyOnly = createPkcs12(identity.leafKeys.privateKey, null, "passphrase");
    expect(() =>
      loadSigningMaterial(
        {
          identity: { data: keyOnly, passphrase: "passphrase", type: "pkcs12" },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "MISSING_SIGNING_MATERIAL" }));
  });

  it("validates runtime signing configuration and the beta algorithm boundary", () => {
    const limits = resolveLimits(undefined);
    expect(() => loadSigningMaterial({} as SigningOptions, limits)).toThrow(
      expect.objectContaining({ code: "MISSING_SIGNING_MATERIAL" })
    );
    expect(() =>
      loadSigningMaterial({ identity: null } as unknown as SigningOptions, limits)
    ).toThrow(expect.objectContaining({ code: "MISSING_SIGNING_MATERIAL" }));
    expect(() =>
      loadSigningMaterial(
        { identity: { data: pkcs12, type: "pem" } } as unknown as SigningOptions,
        limits
      )
    ).toThrow(expect.objectContaining({ code: "UNSUPPORTED_ALGORITHM" }));
    expect(() =>
      loadSigningMaterial(
        {
          identity: { data: pkcs12, passphrase: 42, type: "pkcs12" },
        } as unknown as SigningOptions,
        limits
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      loadSigningMaterial(
        {
          digestAlgorithm: "sha512",
          identity: { data: pkcs12, type: "pkcs12" },
        } as unknown as SigningOptions,
        limits
      )
    ).toThrow(expect.objectContaining({ code: "UNSUPPORTED_ALGORITHM" }));
    expect(() =>
      loadSigningMaterial(
        {
          certificateChain: "not-an-array",
          identity: { data: pkcs12, type: "pkcs12" },
        } as unknown as SigningOptions,
        limits
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));

    const weakIdentity = createSyntheticIdentity({ leafKeyBits: 1_024 });
    const weakPkcs12 = createPkcs12(
      weakIdentity.leafKeys.privateKey,
      [weakIdentity.leafCertificate, weakIdentity.rootCertificate],
      "passphrase"
    );
    expect(() =>
      loadSigningMaterial(
        {
          identity: { data: weakPkcs12, passphrase: "passphrase", type: "pkcs12" },
        },
        limits
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PRIVATE_KEY" }));

    const ecPkcs12 = createEcPkcs12("passphrase");
    expect(() =>
      loadSigningMaterial(
        { identity: { data: ecPkcs12, passphrase: "passphrase", type: "pkcs12" } },
        limits
      )
    ).toThrow(expect.objectContaining({ code: "UNSUPPORTED_ALGORITHM" }));
  });

  it("rejects ambiguous identities and expired signing certificates", () => {
    const mismatched = rewriteSafeContents(
      createPkcs12(
        identity.leafKeys.privateKey,
        [identity.leafCertificate, identity.unrelatedCertificate],
        "passphrase"
      ),
      "passphrase",
      (safeContents) => {
        const leafDer = Buffer.from(certificateDer(identity.leafCertificate));
        safeContents.safeBags = safeContents.safeBags.filter(
          (bag) =>
            !(
              bag.bagValue instanceof CertBag &&
              bag.bagValue.certValue instanceof asn1js.OctetString &&
              Buffer.from(new Uint8Array(bag.bagValue.certValue.getValue())).equals(leafDer)
            )
        );
      }
    );
    expect(() =>
      loadSigningMaterial(
        { identity: { data: mismatched, passphrase: "passphrase", type: "pkcs12" } },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "CERTIFICATE_KEY_MISMATCH" }));

    const ambiguous = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate, identity.leafCertificate],
      "passphrase"
    );
    expect(() =>
      loadSigningMaterial(
        { identity: { data: ambiguous, passphrase: "passphrase", type: "pkcs12" } },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));

    const expiredIdentity = createSyntheticIdentity();
    expiredIdentity.leafCertificate.notAfter.value = new Date(Date.now() - 1_000);
    const expired = createPkcs12(
      expiredIdentity.leafKeys.privateKey,
      [expiredIdentity.leafCertificate, expiredIdentity.rootCertificate],
      "passphrase"
    );
    expect(() =>
      loadSigningMaterial(
        { identity: { data: expired, passphrase: "passphrase", type: "pkcs12" } },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_CERTIFICATE" }));
  });

  it("warns about certificates that are not valid yet or expire soon", () => {
    const futureIdentity = createSyntheticIdentity();
    futureIdentity.leafCertificate.notBefore.value = new Date(Date.now() + 24 * 60 * 60 * 1_000);
    futureIdentity.leafCertificate.notAfter.value = new Date(Date.now() + 7 * 24 * 60 * 60 * 1_000);
    const future = createPkcs12(
      futureIdentity.leafKeys.privateKey,
      [futureIdentity.leafCertificate, futureIdentity.rootCertificate],
      "passphrase"
    );
    const material = loadSigningMaterial(
      { identity: { data: future, passphrase: "passphrase", type: "pkcs12" } },
      resolveLimits(undefined)
    );
    expect(material.warnings.map((warning) => warning.code)).toEqual(
      expect.arrayContaining(["CERTIFICATE_NOT_YET_VALID", "CERTIFICATE_EXPIRES_SOON"])
    );
  });

  it("accepts a canonical base64 PKCS#12 identity", () => {
    const material = loadSigningMaterial(
      {
        identity: {
          data: { encoding: "base64", value: Buffer.from(pkcs12).toString("base64") },
          passphrase: "correct horse battery staple",
          type: "pkcs12",
        },
      },
      resolveLimits(undefined)
    );
    expect(
      Buffer.from(material.signerCertificate.serialNumber.valueBlock.valueHexView).toString("hex")
    ).toBe("02");
  });

  it("accepts plaintext key bags and SHA-256 PKCS#12 MACs", () => {
    const plaintextKeyBag = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate, identity.rootCertificate],
      "passphrase",
      { keyEncryption: "none", macAlgorithm: "sha256" }
    );
    const material = loadSigningMaterial(
      { identity: { data: plaintextKeyBag, passphrase: "passphrase", type: "pkcs12" } },
      resolveLimits(undefined)
    );
    expect(material.signerCertificate.serialNumber.valueBlock.valueDec).toBe(2);
  });

  it("rejects PKCS#12 identities without a MAC or with encrypted safe contents", () => {
    const withoutMac = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate],
      "passphrase",
      { includeMac: false }
    );
    expect(() =>
      loadSigningMaterial(
        { identity: { data: withoutMac, passphrase: "passphrase", type: "pkcs12" } },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));

    const encryptedSafeContents = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate],
      "passphrase",
      { certificateEncryption: "pbe-sha1-3des" }
    );
    expect(() =>
      loadSigningMaterial(
        {
          identity: { data: encryptedSafeContents, passphrase: "passphrase", type: "pkcs12" },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));
  });

  it("rejects an authenticated safe with an unsupported content type", () => {
    const unsupported = rewritePfx(pkcs12, "correct horse battery staple", (pfx) => {
      pfx.authSafe.contentType = "1.2.840.113549.1.7.6";
    });
    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: unsupported,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));
  });

  it("rejects unsupported PKCS#12 MAC and key-encryption algorithms", () => {
    const unsupportedMac = rewritePfx(pkcs12, "correct horse battery staple", (pfx) => {
      pfx.macData!.mac.digestAlgorithm.algorithmId = "1.2.3.4";
    });
    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: unsupportedMac,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));

    const unsupportedKeyEncryption = rewriteSafeContents(
      pkcs12,
      "correct horse battery staple",
      (safeContents) => {
        const keyBag = safeContents.safeBags.find(
          (bag) => bag.bagId === "1.2.840.113549.1.12.10.1.2"
        );
        if (keyBag !== undefined) {
          (
            keyBag.bagValue as { encryptionAlgorithm: { algorithmId: string } }
          ).encryptionAlgorithm.algorithmId = "1.2.3.4";
        }
      }
    );
    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: unsupportedKeyEncryption,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));
  });

  it("rejects malformed PKCS#12 PBE parameters and certificate bags", () => {
    const invalidParameterVariants = [
      (bag: { bagValue: unknown }) => {
        (
          bag.bagValue as { encryptionAlgorithm: { algorithmParams: unknown } }
        ).encryptionAlgorithm.algorithmParams = new asn1js.Null();
      },
      (bag: { bagValue: unknown }) => {
        (
          bag.bagValue as { encryptionAlgorithm: { algorithmParams: unknown } }
        ).encryptionAlgorithm.algorithmParams = new asn1js.Sequence({
          value: [new asn1js.Integer({ value: 1 }), new asn1js.Integer({ value: 1 })],
        });
      },
      (bag: { bagValue: unknown }) => {
        (
          bag.bagValue as { encryptionAlgorithm: { algorithmParams: unknown } }
        ).encryptionAlgorithm.algorithmParams = new asn1js.Sequence({
          value: [
            new asn1js.OctetString({ valueHex: new Uint8Array([1]).buffer }),
            new asn1js.Integer({ value: 0 }),
          ],
        });
      },
    ];

    for (const mutateParameters of invalidParameterVariants) {
      const malformed = rewriteSafeContents(
        pkcs12,
        "correct horse battery staple",
        (safeContents) => {
          const keyBag = safeContents.safeBags.find(
            (bag) => bag.bagId === "1.2.840.113549.1.12.10.1.2"
          );
          if (keyBag !== undefined) mutateParameters(keyBag);
        }
      );
      expect(() =>
        loadSigningMaterial(
          {
            identity: {
              data: malformed,
              passphrase: "correct horse battery staple",
              type: "pkcs12",
            },
          },
          resolveLimits(undefined)
        )
      ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));
    }

    const malformedCertificateBag = rewriteSafeContents(
      pkcs12,
      "correct horse battery staple",
      (safeContents) => {
        for (const bag of safeContents.safeBags) {
          if (bag.bagValue instanceof CertBag) {
            bag.bagValue = new CertBag({
              certId: "1.2.3.4",
              certValue: bag.bagValue.certValue,
            });
          }
        }
      }
    );
    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: malformedCertificateBag,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_PKCS12" }));
  });

  it("enforces the PKCS#12 private-key count limit", () => {
    const duplicateKey = rewriteSafeContents(
      pkcs12,
      "correct horse battery staple",
      (safeContents) => {
        const keyBag = safeContents.safeBags.find(
          (bag) => bag.bagId === "1.2.840.113549.1.12.10.1.2"
        );
        if (keyBag !== undefined) safeContents.safeBags.push(keyBag);
      }
    );
    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: duplicateKey,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits({ maxCertificates: 1 })
      )
    ).toThrow(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));
  });

  it("rejects malformed and oversized certificates in an explicit chain", () => {
    expect(() =>
      loadSigningMaterial(
        {
          certificateChain: [{ encoding: "base64", value: "MAA=" }],
          identity: {
            data: pkcs12,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "INVALID_CERTIFICATE" }));

    expect(() =>
      loadSigningMaterial(
        {
          identity: {
            data: pkcs12,
            passphrase: "correct horse battery staple",
            type: "pkcs12",
          },
        },
        resolveLimits({ maxCertificateBytes: 100 })
      )
    ).toThrow(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));
  });
});
