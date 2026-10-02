import { createHash, createSign } from "node:crypto";

import * as asn1js from "asn1js";
import {
  AlgorithmIdentifier,
  Attribute,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedAndUnsignedAttributes,
  SignedData,
  SignerInfo,
} from "pkijs";

import { UdidToolsError } from "../errors.js";
import type { SigningMaterial } from "../certificates/index.js";

export type CmsDigestAlgorithm = "sha256";

const CONTENT_TYPE_ATTRIBUTE_OID = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST_ATTRIBUTE_OID = "1.2.840.113549.1.9.4";
const SIGNING_TIME_ATTRIBUTE_OID = "1.2.840.113549.1.9.5";
const DATA_CONTENT_TYPE_OID = "1.2.840.113549.1.7.1";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";

/** Creates attached CMS/PKCS#7 SignedData using RSA PKCS#1 v1.5 and SHA-256. */
export function signCms(
  content: Uint8Array,
  material: SigningMaterial,
  digestAlgorithm: CmsDigestAlgorithm = "sha256"
): Uint8Array {
  const requestedDigest: unknown = digestAlgorithm;
  if (requestedDigest !== "sha256") {
    throw new UdidToolsError(
      "UNSUPPORTED_ALGORITHM",
      "Only RSA with SHA-256 is supported in this beta release."
    );
  }

  try {
    const digest = createHash("sha256").update(content).digest();
    const signedAttrs = new SignedAndUnsignedAttributes({
      attributes: [
        new Attribute({
          type: CONTENT_TYPE_ATTRIBUTE_OID,
          values: [new asn1js.ObjectIdentifier({ value: DATA_CONTENT_TYPE_OID })],
        }),
        new Attribute({
          type: MESSAGE_DIGEST_ATTRIBUTE_OID,
          values: [new asn1js.OctetString({ valueHex: digest })],
        }),
        new Attribute({
          type: SIGNING_TIME_ATTRIBUTE_OID,
          values: [new asn1js.UTCTime({ valueDate: new Date() })],
        }),
      ],
      type: 0,
    });
    const signedAttributesDer = Uint8Array.from(
      new Uint8Array(signedAttrs.toSchema().toBER(false))
    );
    signedAttributesDer[0] = 0x31;

    const signer = createSign("RSA-SHA256");
    signer.update(signedAttributesDer);
    const signature = signer.sign(material.privateKey);
    const signedData = new SignedData({
      certificates: [...material.certificates],
      digestAlgorithms: [
        new AlgorithmIdentifier({ algorithmId: SHA256_OID, algorithmParams: new asn1js.Null() }),
      ],
      encapContentInfo: new EncapsulatedContentInfo({
        eContent: new asn1js.OctetString({ valueHex: Uint8Array.from(content).buffer }),
        eContentType: DATA_CONTENT_TYPE_OID,
      }),
      signerInfos: [
        new SignerInfo({
          digestAlgorithm: new AlgorithmIdentifier({
            algorithmId: SHA256_OID,
            algorithmParams: new asn1js.Null(),
          }),
          sid: new IssuerAndSerialNumber({
            issuer: material.signerCertificate.issuer,
            serialNumber: material.signerCertificate.serialNumber,
          }),
          signature: new asn1js.OctetString({ valueHex: signature }),
          signatureAlgorithm: new AlgorithmIdentifier({
            algorithmId: RSA_ENCRYPTION_OID,
            algorithmParams: new asn1js.Null(),
          }),
          signedAttrs,
          version: 1,
        }),
      ],
      version: 1,
    });
    const contentInfo = new ContentInfo({
      content: signedData.toSchema(true),
      contentType: ContentInfo.SIGNED_DATA,
    });
    return Uint8Array.from(new Uint8Array(contentInfo.toSchema().toBER(false)));
  } catch {
    throw new UdidToolsError("PROFILE_SIGNING_FAILED", "The profile could not be signed.");
  }
}
