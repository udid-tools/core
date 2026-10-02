import * as asn1js from "asn1js";
import { Certificate, ContentInfo, SignedData } from "pkijs";
import { beforeAll, describe, expect, it } from "vitest";

import { loadSigningMaterial, type SigningMaterial } from "../../src/certificates/index.js";
import { inspectAndVerifyCms, signCms } from "../../src/cms/index.js";
import { resolveLimits } from "../../src/limits.js";
import {
  certificateDer,
  cloneCertificate,
  createCms,
  createPkcs12,
  createSyntheticIdentity,
  type SyntheticIdentity,
} from "../helpers/synthetic-identity.js";

const CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";

function rewriteSignedData(
  input: Uint8Array,
  mutate: (signedData: SignedData) => void
): Uint8Array {
  const parsed = asn1js.fromBER(Uint8Array.from(input).buffer);
  const contentInfo = new ContentInfo({ schema: parsed.result });
  const signedData = new SignedData({ schema: contentInfo.content });
  mutate(signedData);
  const modified = new ContentInfo({
    content: signedData.toSchema(true),
    contentType: "1.2.840.113549.1.7.2",
  });
  return Uint8Array.from(new Uint8Array(modified.toSchema().toBER(false)));
}

function createSubjectKeyIdentifierCms(
  payload: Uint8Array,
  privateKey: SyntheticIdentity["leafKeys"]["privateKey"],
  signerCertificate: Certificate,
  options: {
    readonly constructed?: boolean;
    readonly embeddedCertificates?: readonly Certificate[];
  } = {}
): Uint8Array {
  const original = createCms(
    payload,
    privateKey,
    signerCertificate,
    options.embeddedCertificates ?? [signerCertificate]
  );
  const parsed = asn1js.fromBER(Uint8Array.from(original).buffer);
  const contentInfo = new ContentInfo({ schema: parsed.result });
  const signedData = new SignedData({ schema: contentInfo.content });
  const parsedCertificate = asn1js.fromBER(
    Uint8Array.from(certificateDer(signerCertificate)).buffer
  );
  const certificate = new Certificate({ schema: parsedCertificate.result });
  const extension = certificate.extensions?.find((candidate) => candidate.extnID === "2.5.29.14");
  if (extension === undefined) {
    throw new Error("Synthetic certificate subject key identifier is missing");
  }
  const parsedIdentifier = asn1js.fromBER(extension.extnValue.getValue());
  if (!(parsedIdentifier.result instanceof asn1js.OctetString)) {
    throw new Error("Synthetic certificate subject key identifier is malformed");
  }
  const signerInfo = signedData.signerInfos[0];
  if (signerInfo === undefined) {
    throw new Error("Synthetic CMS signer info is missing");
  }

  signedData.version = 3;
  signerInfo.version = 3;
  signerInfo.sid = options.constructed
    ? new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.OctetString({ valueHex: parsedIdentifier.result.getValue() })],
      })
    : new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 0 },
        valueHex: parsedIdentifier.result.getValue(),
      });

  const modified = new ContentInfo({
    content: signedData.toSchema(true),
    contentType: "1.2.840.113549.1.7.2",
  });
  return Uint8Array.from(new Uint8Array(modified.toSchema().toBER(false)));
}

describe("CMS signing and verification", () => {
  let identity: SyntheticIdentity;
  let material: SigningMaterial;
  let signed: Uint8Array;
  const content = new TextEncoder().encode('<?xml version="1.0"?><plist><dict/></plist>');

  beforeAll(() => {
    identity = createSyntheticIdentity();
    const pkcs12 = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate, identity.rootCertificate],
      "test-passphrase"
    );
    material = loadSigningMaterial(
      {
        identity: { data: pkcs12, passphrase: "test-passphrase", type: "pkcs12" },
      },
      resolveLimits(undefined)
    );
    signed = signCms(content, material);
  });

  it("produces attached SignedData with required authenticated attributes", () => {
    const parsed = asn1js.fromBER(Uint8Array.from(signed).buffer);
    expect(parsed.offset).toBe(signed.byteLength);
    const contentInfo = new ContentInfo({ schema: parsed.result });
    const signedData = new SignedData({ schema: contentInfo.content });
    expect(Buffer.from(signedData.encapContentInfo.eContent!.getValue())).toEqual(
      Buffer.from(content)
    );

    const attributes = signedData.signerInfos[0]?.signedAttrs?.attributes.map(
      (attribute) => attribute.type
    );
    expect(attributes).toEqual(
      expect.arrayContaining([CONTENT_TYPE_OID, MESSAGE_DIGEST_OID, SIGNING_TIME_OID])
    );
  });

  it("verifies the attached signature and exposes signer information", async () => {
    const inspected = await inspectAndVerifyCms(
      signed,
      { mode: "signature" },
      resolveLimits(undefined)
    );

    expect(inspected.content).toEqual(content);
    expect(inspected.signature.valid).toBe(true);
    expect(inspected.signature.trusted).toBeNull();
    expect(inspected.signature.signers).toHaveLength(1);
    expect(inspected.signature.signers[0]?.subject).toContain("UDID Tools Synthetic Signer");
    expect(inspected.signature.signers[0]?.sha256Fingerprint).toMatch(/^[0-9A-F]{64}$/u);
    expect(inspected.warnings).toContainEqual(
      expect.objectContaining({ code: "SIGNER_TRUST_NOT_CHECKED" })
    );
  });

  it("resolves a standards-compliant subject-key-identifier signer", async () => {
    const skiCms = createSubjectKeyIdentifierCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate
    );
    const inspected = await inspectAndVerifyCms(
      skiCms,
      { mode: "signature" },
      resolveLimits(undefined)
    );

    expect(inspected.signature.valid).toBe(true);
    expect(inspected.signature.signers[0]?.serialNumber).toBe("02");

    const unverified = await inspectAndVerifyCms(
      skiCms,
      { mode: "none" },
      resolveLimits(undefined)
    );
    expect(unverified.signature.valid).toBeNull();
    expect(unverified.signature.signers[0]?.serialNumber).toBe("02");
  });

  it("resolves constructed SKI signers across irrelevant and malformed certificates", async () => {
    const withoutSki = cloneCertificate(identity.unrelatedCertificate);
    if (withoutSki.extensions !== undefined) {
      withoutSki.extensions = withoutSki.extensions.filter(
        (extension) => extension.extnID !== "2.5.29.14"
      );
    }

    const malformedSki = cloneCertificate(identity.unrelatedCertificate);
    const malformedExtension = malformedSki.extensions?.find(
      (extension) => extension.extnID === "2.5.29.14"
    );
    if (malformedExtension === undefined)
      throw new Error("Synthetic subject key identifier is missing");
    malformedExtension.extnValue = new asn1js.OctetString({
      valueHex: Uint8Array.from([0xff]).buffer,
    });

    const wrongTypeSki = cloneCertificate(identity.unrelatedCertificate);
    const wrongTypeExtension = wrongTypeSki.extensions?.find(
      (extension) => extension.extnID === "2.5.29.14"
    );
    if (wrongTypeExtension === undefined)
      throw new Error("Synthetic subject key identifier is missing");
    wrongTypeExtension.extnValue = new asn1js.OctetString({
      valueHex: new asn1js.Null().toBER(false),
    });

    const differentLengthSki = cloneCertificate(identity.unrelatedCertificate);
    const differentLengthExtension = differentLengthSki.extensions?.find(
      (extension) => extension.extnID === "2.5.29.14"
    );
    if (differentLengthExtension === undefined)
      throw new Error("Synthetic subject key identifier is missing");
    differentLengthExtension.extnValue = new asn1js.OctetString({
      valueHex: new asn1js.OctetString({ valueHex: Uint8Array.from([1, 2]).buffer }).toBER(false),
    });

    const constructedCms = createSubjectKeyIdentifierCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate,
      {
        constructed: true,
        embeddedCertificates: [
          withoutSki,
          malformedSki,
          wrongTypeSki,
          differentLengthSki,
          identity.leafCertificate,
        ],
      }
    );
    const inspected = await inspectAndVerifyCms(
      constructedCms,
      { mode: "none" },
      resolveLimits(undefined)
    );
    expect(inspected.signature.signers[0]?.serialNumber).toBe("02");

    for (const unresolvableCertificate of [
      withoutSki,
      malformedSki,
      wrongTypeSki,
      differentLengthSki,
    ]) {
      const unresolvableCms = createSubjectKeyIdentifierCms(
        content,
        identity.leafKeys.privateKey,
        identity.leafCertificate,
        { constructed: true, embeddedCertificates: [unresolvableCertificate] }
      );
      await expect(
        inspectAndVerifyCms(unresolvableCms, { mode: "none" }, resolveLimits(undefined))
      ).rejects.toMatchObject({ code: "MALFORMED_CMS" });
    }
  });

  it("uses only caller-provided trust anchors for chain validation", async () => {
    const trusted = await inspectAndVerifyCms(
      signed,
      {
        mode: "trust-chain",
        trustAnchors: [certificateDer(identity.rootCertificate)],
      },
      resolveLimits(undefined)
    );
    expect(trusted.signature.trusted).toBe(true);

    await expect(
      inspectAndVerifyCms(
        signed,
        {
          mode: "trust-chain",
          trustAnchors: [certificateDer(identity.unrelatedCertificate)],
        },
        resolveLimits(undefined)
      )
    ).rejects.toMatchObject({ code: "UNTRUSTED_SIGNER" });
  });

  it("represents intentionally skipped verification as unknown", async () => {
    const inspected = await inspectAndVerifyCms(signed, { mode: "none" }, resolveLimits(undefined));
    expect(inspected.signature.valid).toBeNull();
    expect(inspected.signature.trusted).toBeNull();
    expect(inspected.content).toEqual(content);
  });

  it("rejects tampered SignedData", async () => {
    const tampered = Uint8Array.from(signed);
    const contentOffset = Buffer.from(tampered).indexOf(Buffer.from(content));
    expect(contentOffset).toBeGreaterThanOrEqual(0);
    const tamperIndex = contentOffset + content.byteLength - 2;
    tampered[tamperIndex] = (tampered[tamperIndex] ?? 0) ^ 1;

    await expect(
      inspectAndVerifyCms(tampered, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "INVALID_SIGNATURE" });
  });

  it("verifies RSA/SHA-1 and still rejects tampering", async () => {
    const sha1 = createCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate,
      [identity.leafCertificate],
      { digestAlgorithm: "sha1" }
    );

    const inspected = await inspectAndVerifyCms(
      sha1,
      { mode: "signature" },
      resolveLimits(undefined)
    );
    expect(inspected.signature.valid).toBe(true);

    const tampered = Uint8Array.from(sha1);
    const contentOffset = Buffer.from(tampered).indexOf(Buffer.from(content));
    expect(contentOffset).toBeGreaterThanOrEqual(0);
    tampered[contentOffset + content.byteLength - 2] =
      (tampered[contentOffset + content.byteLength - 2] ?? 0) ^ 1;
    await expect(
      inspectAndVerifyCms(tampered, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "INVALID_SIGNATURE" });
  });

  it("strictly rejects trailing DER garbage and excessive ASN.1 nesting", async () => {
    const withTrailingGarbage = new Uint8Array(signed.byteLength + 1);
    withTrailingGarbage.set(signed);
    withTrailingGarbage[withTrailingGarbage.length - 1] = 0;

    await expect(
      inspectAndVerifyCms(withTrailingGarbage, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    // The bytes encode nested indefinite-length SEQUENCEs. The preflight must
    // reject this at the configured maxDepth before PKI.js/asn1js sees it.
    const nested = new Uint8Array([
      0x30, 0x80, 0x30, 0x80, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    await expect(
      inspectAndVerifyCms(nested, { mode: "signature" }, resolveLimits({ maxAsn1Depth: 2 }))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    await expect(
      inspectAndVerifyCms(signed, { mode: "signature" }, resolveLimits({ maxAsn1Nodes: 1 }))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });
  });

  it("rejects empty, oversized, malformed, and non-SignedData inputs", async () => {
    await expect(
      inspectAndVerifyCms(new Uint8Array(), { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    await expect(
      inspectAndVerifyCms(
        signed,
        { mode: "signature" },
        resolveLimits({ maxInputBytes: signed.byteLength - 1 })
      )
    ).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });

    await expect(
      inspectAndVerifyCms(
        new Uint8Array([0x30, 0x00]),
        { mode: "signature" },
        resolveLimits(undefined)
      )
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    const plainContentInfo = new ContentInfo({
      content: new asn1js.OctetString({ valueHex: Uint8Array.from([1, 2, 3]).buffer }),
      contentType: "1.2.840.113549.1.7.1",
    });
    const notSignedData = Uint8Array.from(new Uint8Array(plainContentInfo.toSchema().toBER(false)));
    await expect(
      inspectAndVerifyCms(notSignedData, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });
  });

  it("requires signers, embedded certificates, and attached content", async () => {
    const noSigners = createCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate,
      [],
      { signerCount: 0 }
    );
    await expect(
      inspectAndVerifyCms(noSigners, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    const noCertificates = createCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate,
      []
    );
    await expect(
      inspectAndVerifyCms(noCertificates, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    const detached = createCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate,
      [identity.leafCertificate],
      { detached: true }
    );
    await expect(
      inspectAndVerifyCms(detached, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });

    const wrongContentType = rewriteSignedData(signed, (signedData) => {
      signedData.encapContentInfo.eContentType = "1.2.840.113549.1.7.6";
    });
    await expect(
      inspectAndVerifyCms(wrongContentType, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });
  });

  it("enforces content, certificate, and signer resource limits", async () => {
    await expect(
      inspectAndVerifyCms(
        signed,
        { mode: "signature" },
        resolveLimits({ maxOutputBytes: content.byteLength - 1 })
      )
    ).rejects.toMatchObject({ code: "OUTPUT_TOO_LARGE" });

    await expect(
      inspectAndVerifyCms(
        signed,
        { mode: "signature" },
        resolveLimits({ maxCertificateBytes: 100 })
      )
    ).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });

    await expect(
      inspectAndVerifyCms(signed, { mode: "signature" }, resolveLimits({ maxCertificates: 1 }))
    ).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });

    const twoSigners = createCms(
      content,
      identity.leafKeys.privateKey,
      identity.leafCertificate,
      [identity.leafCertificate],
      { signerCount: 2 }
    );
    await expect(
      inspectAndVerifyCms(twoSigners, { mode: "signature" }, resolveLimits({ maxCertificates: 1 }))
    ).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });
  });

  it("rejects unsupported signer algorithms and invalid signing material", async () => {
    const unsupported = rewriteSignedData(signed, (signedData) => {
      const signer = signedData.signerInfos[0];
      if (signer === undefined) {
        throw new Error("Synthetic CMS signer is missing");
      }
      signer.digestAlgorithm.algorithmId = "2.16.840.1.101.3.4.2.3";
    });
    await expect(
      inspectAndVerifyCms(unsupported, { mode: "signature" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "UNSUPPORTED_ALGORITHM" });

    expect(() => signCms(content, material, "sha512" as unknown as "sha256")).toThrow(
      expect.objectContaining({ code: "UNSUPPORTED_ALGORITHM" })
    );

    expect(() =>
      signCms(content, {
        ...material,
        privateKey: {} as SigningMaterial["privateKey"],
      })
    ).toThrow(expect.objectContaining({ code: "PROFILE_SIGNING_FAILED" }));
  });

  it("rejects unresolved signers when verification is explicitly skipped", async () => {
    const unresolved = createCms(content, identity.leafKeys.privateKey, identity.leafCertificate, [
      identity.unrelatedCertificate,
    ]);
    await expect(
      inspectAndVerifyCms(unresolved, { mode: "none" }, resolveLimits(undefined))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });
  });

  it("validates trust-chain configuration and caller-provided certificate inputs", async () => {
    await expect(
      inspectAndVerifyCms(
        signed,
        { mode: "trust-chain", trustAnchors: [] },
        resolveLimits(undefined)
      )
    ).rejects.toMatchObject({ code: "INVALID_CONFIGURATION" });

    await expect(
      inspectAndVerifyCms(
        signed,
        {
          mode: "trust-chain",
          trustAnchors: [certificateDer(identity.rootCertificate)],
        },
        resolveLimits({ maxCertificates: 2 })
      )
    ).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });

    await expect(
      inspectAndVerifyCms(
        signed,
        { mode: "trust-chain", trustAnchors: [new Uint8Array([0x30, 0x00])] },
        resolveLimits(undefined)
      )
    ).rejects.toMatchObject({ code: "INVALID_CERTIFICATE" });

    const withExplicitIntermediate = await inspectAndVerifyCms(
      signed,
      {
        intermediates: [certificateDer(identity.rootCertificate)],
        mode: "trust-chain",
        trustAnchors: [certificateDer(identity.rootCertificate)],
      },
      resolveLimits(undefined)
    );
    expect(withExplicitIntermediate.signature.trusted).toBe(true);
  });
});
