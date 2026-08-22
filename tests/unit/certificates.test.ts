import { beforeAll, describe, expect, it } from "vitest";
import forge from "node-forge";

import { decodeBinaryInput, loadSigningMaterial } from "../../src/certificates/index.js";
import { decodePem } from "../../src/certificates/binary-input.js";
import { UdidToolsError } from "../../src/errors.js";
import { resolveLimits } from "../../src/limits.js";
import type { SigningOptions } from "../../src/types.js";
import {
  certificatePem,
  createPkcs12,
  createSyntheticIdentity,
  type SyntheticIdentity,
} from "../helpers/synthetic-identity.js";

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
    expect(material.signerCertificate.serialNumber).toBe("02");
    expect(material.privateKey.n.compareTo(identity.leafKeys.privateKey.n)).toBe(0);
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

  it("rejects a PKCS#12 identity whose key has no matching certificate", () => {
    const mismatched = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.unrelatedCertificate, identity.rootCertificate],
      "passphrase"
    );

    expect(() =>
      loadSigningMaterial(
        {
          identity: { data: mismatched, passphrase: "passphrase", type: "pkcs12" },
        },
        resolveLimits(undefined)
      )
    ).toThrow(expect.objectContaining({ code: "CERTIFICATE_KEY_MISMATCH" }));
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
  });

  it("rejects ambiguous identities and expired signing certificates", () => {
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
    expiredIdentity.leafCertificate.validity.notAfter = new Date(Date.now() - 1_000);
    expiredIdentity.leafCertificate.sign(
      expiredIdentity.rootKeys.privateKey,
      forge.md.sha256.create()
    );
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
    futureIdentity.leafCertificate.validity.notBefore = new Date(Date.now() + 24 * 60 * 60 * 1_000);
    futureIdentity.leafCertificate.validity.notAfter = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1_000
    );
    futureIdentity.leafCertificate.sign(
      futureIdentity.rootKeys.privateKey,
      forge.md.sha256.create()
    );
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
    expect(material.signerCertificate.serialNumber).toBe("02");
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
