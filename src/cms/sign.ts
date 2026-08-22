import forge from "node-forge";

import { UdidToolsError } from "../errors.js";
import type { SigningMaterial } from "../certificates/index.js";
import { binaryStringToBytes, bytesToBinaryString } from "../certificates/binary-input.js";

export type CmsDigestAlgorithm = "sha256";

const CONTENT_TYPE_ATTRIBUTE_OID = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST_ATTRIBUTE_OID = "1.2.840.113549.1.9.4";
const SIGNING_TIME_ATTRIBUTE_OID = "1.2.840.113549.1.9.5";
const DATA_CONTENT_TYPE_OID = "1.2.840.113549.1.7.1";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";

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
    const signedData = forge.pkcs7.createSignedData();
    signedData.content = forge.util.createBuffer(bytesToBinaryString(content), "raw");

    for (const certificate of material.certificates) {
      signedData.addCertificate(certificate);
    }

    signedData.addSigner({
      authenticatedAttributes: [
        {
          type: CONTENT_TYPE_ATTRIBUTE_OID,
          value: DATA_CONTENT_TYPE_OID,
        },
        {
          type: MESSAGE_DIGEST_ATTRIBUTE_OID,
        },
        {
          type: SIGNING_TIME_ATTRIBUTE_OID,
        },
      ],
      certificate: material.signerCertificate,
      digestAlgorithm: SHA256_OID,
      key: material.privateKey,
    });

    signedData.sign({ detached: false });
    return binaryStringToBytes(forge.asn1.toDer(signedData.toAsn1()).getBytes());
  } catch {
    throw new UdidToolsError("PROFILE_SIGNING_FAILED", "The profile could not be signed.");
  }
}
