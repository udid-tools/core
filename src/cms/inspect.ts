import { Buffer } from "node:buffer";
import { createHash, webcrypto } from "node:crypto";

import * as asn1js from "asn1js";
import {
  Certificate,
  CertificateChainValidationEngine,
  ContentInfo,
  CryptoEngine,
  IssuerAndSerialNumber,
  SignedData,
  type ICryptoEngine,
} from "pkijs";

import { decodeBinaryInput } from "../certificates/binary-input.js";
import { preflightDer } from "../certificates/der.js";
import { UdidToolsError, type UdidToolsWarning } from "../errors.js";
import type { ResourceLimits } from "../limits.js";
import type { CertificateInfo, CertificateInput, ResponseVerificationOptions } from "../types.js";

const CMS_SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
const CMS_DATA_OID = "1.2.840.113549.1.7.1";
const SHA1_OID = "1.3.14.3.2.26";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
const SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5";
const SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11";
const SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";
const CERTIFICATE_PEM_LABELS = ["CERTIFICATE", "X509 CERTIFICATE"] as const;
const MAX_CERTIFICATE_NAME_CHARACTERS = 4_096;

export interface InspectedCms {
  readonly content: Uint8Array;
  readonly signature: {
    readonly present: true;
    readonly signers: readonly CertificateInfo[];
    readonly trusted: boolean | null;
    readonly valid: boolean | null;
  };
  readonly warnings: readonly UdidToolsWarning[];
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function parseAsn1(bytes: Uint8Array, limits: ResourceLimits): asn1js.AsnType {
  const parsed = asn1js.fromBER(toArrayBuffer(bytes), {
    maxContentLength: limits.maxInputBytes,
    maxDepth: limits.maxAsn1Depth,
    maxNodes: limits.maxAsn1Nodes,
  });

  if (parsed.offset === -1 || parsed.offset !== bytes.byteLength) {
    throw new UdidToolsError("MALFORMED_CMS", "The CMS input contains malformed ASN.1 data.");
  }

  return parsed.result;
}

function parseCertificate(bytes: Uint8Array, limits: ResourceLimits): Certificate {
  try {
    preflightDer(bytes, limits);
    return new Certificate({ schema: parseAsn1(bytes, limits) });
  } catch {
    throw new UdidToolsError("INVALID_CERTIFICATE", "A verification certificate is malformed.");
  }
}

function parseCertificateInput(input: CertificateInput, limits: ResourceLimits): Certificate {
  const bytes = decodeBinaryInput(input, limits, {
    errorCode: "INVALID_CERTIFICATE",
    inputKind: "Verification certificate",
    maxBytes: limits.maxCertificateBytes,
    pemLabels: CERTIFICATE_PEM_LABELS,
  });
  return parseCertificate(bytes, limits);
}

function certificateDer(certificate: Certificate): Uint8Array {
  return Uint8Array.from(new Uint8Array(certificate.toSchema(true).toBER(false)));
}

function certificateFingerprint(certificate: Certificate): string {
  return createHash("sha256").update(certificateDer(certificate)).digest("hex");
}

function deduplicateCertificates(certificates: readonly Certificate[]): readonly Certificate[] {
  const seen = new Set<string>();
  return certificates.filter((certificate) => {
    const fingerprint = certificateFingerprint(certificate);
    if (seen.has(fingerprint)) {
      return false;
    }
    seen.add(fingerprint);
    return true;
  });
}

function sanitizeCertificateText(value: string): string {
  let printable = "";
  for (const character of value) {
    const codeUnit = character.charCodeAt(0);
    printable += codeUnit <= 0x1f || codeUnit === 0x7f ? "�" : character;
  }
  return printable.length <= MAX_CERTIFICATE_NAME_CHARACTERS
    ? printable
    : `${printable.slice(0, MAX_CERTIFICATE_NAME_CHARACTERS)}…`;
}

function distinguishedNameToString(certificateName: Certificate["subject"]): string {
  return sanitizeCertificateText(
    certificateName.typesAndValues
      .map((entry) => `${entry.type}=${entry.value.toString()}`)
      .join(", ")
  );
}

function toCertificateInfo(certificate: Certificate): CertificateInfo {
  return {
    issuer: distinguishedNameToString(certificate.issuer),
    notAfter: new Date(certificate.notAfter.value),
    notBefore: new Date(certificate.notBefore.value),
    serialNumber: Buffer.from(certificate.serialNumber.valueBlock.valueHexView)
      .toString("hex")
      .toUpperCase(),
    sha256Fingerprint: certificateFingerprint(certificate).toUpperCase(),
    subject: distinguishedNameToString(certificate.subject),
  };
}

function ensureCertificateLimits(
  certificates: readonly Certificate[],
  limits: ResourceLimits
): void {
  if (certificates.length > limits.maxCertificates) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "The CMS contains too many certificates.", {
      details: { maxCertificates: limits.maxCertificates },
    });
  }

  for (const certificate of certificates) {
    if (certificateDer(certificate).byteLength > limits.maxCertificateBytes) {
      throw new UdidToolsError("INPUT_TOO_LARGE", "A CMS certificate is too large.", {
        details: { maxBytes: limits.maxCertificateBytes },
      });
    }
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function subjectKeyIdentifier(certificate: Certificate, limits: ResourceLimits): Uint8Array | null {
  const extension = certificate.extensions?.find(
    (candidate) => candidate.extnID === SUBJECT_KEY_IDENTIFIER_OID
  );
  if (extension === undefined) {
    return null;
  }

  const encoded = Uint8Array.from(new Uint8Array(extension.extnValue.getValue()));
  try {
    preflightDer(encoded, limits);
    const parsed = parseAsn1(encoded, limits);
    if (!(parsed instanceof asn1js.OctetString)) {
      return null;
    }
    return Uint8Array.from(new Uint8Array(parsed.getValue()));
  } catch {
    return null;
  }
}

function signerSubjectKeyIdentifier(identifier: unknown): Uint8Array | null {
  if (
    identifier instanceof asn1js.Primitive &&
    identifier.idBlock.tagClass === 3 &&
    identifier.idBlock.tagNumber === 0
  ) {
    return Uint8Array.from(identifier.valueBlock.valueHexView);
  }

  if (
    identifier instanceof asn1js.Constructed &&
    identifier.idBlock.tagClass === 3 &&
    identifier.idBlock.tagNumber === 0
  ) {
    const value = identifier.valueBlock.value[0];
    return value instanceof asn1js.OctetString
      ? Uint8Array.from(new Uint8Array(value.getValue()))
      : null;
  }

  return null;
}

function findSignerCertificate(
  signedData: SignedData,
  signerIndex: number,
  certificates: readonly Certificate[],
  limits: ResourceLimits
): Certificate | null {
  const signerInfo = signedData.signerInfos[signerIndex];
  if (signerInfo === undefined) {
    return null;
  }

  const signerIdentifier: unknown = signerInfo.sid;
  if (signerIdentifier instanceof IssuerAndSerialNumber) {
    return (
      certificates.find(
        (certificate) =>
          certificate.issuer.isEqual(signerIdentifier.issuer) &&
          equalBytes(
            certificate.serialNumber.valueBlock.valueHexView,
            signerIdentifier.serialNumber.valueBlock.valueHexView
          )
      ) ?? null
    );
  }

  const expected = signerSubjectKeyIdentifier(signerIdentifier);
  if (expected !== null) {
    return (
      certificates.find((certificate) => {
        const actual = subjectKeyIdentifier(certificate, limits);
        return actual !== null && equalBytes(actual, expected);
      }) ?? null
    );
  }

  return null;
}

function isSupportedSignerAlgorithm(digestAlgorithm: string, signatureAlgorithm: string): boolean {
  if (
    digestAlgorithm === SHA1_OID &&
    (signatureAlgorithm === RSA_ENCRYPTION_OID || signatureAlgorithm === SHA1_WITH_RSA_OID)
  ) {
    return true;
  }
  if (
    digestAlgorithm === SHA256_OID &&
    (signatureAlgorithm === RSA_ENCRYPTION_OID || signatureAlgorithm === SHA256_WITH_RSA_OID)
  ) {
    return true;
  }
  return false;
}

function assertSupportedSignerAlgorithms(signedData: SignedData): void {
  for (const signerInfo of signedData.signerInfos) {
    if (
      !isSupportedSignerAlgorithm(
        signerInfo.digestAlgorithm.algorithmId,
        signerInfo.signatureAlgorithm.algorithmId
      )
    ) {
      throw new UdidToolsError(
        "UNSUPPORTED_ALGORITHM",
        "Only RSA CMS signatures using SHA-1 or SHA-256 are supported.",
        {
          details: {
            digestAlgorithm: signerInfo.digestAlgorithm.algorithmId,
            signatureAlgorithm: signerInfo.signatureAlgorithm.algorithmId,
          },
        }
      );
    }
  }
}

function cryptoEngine(): ICryptoEngine {
  return new CryptoEngine({
    crypto: webcrypto,
    name: "node-webcrypto",
    subtle: webcrypto.subtle,
  });
}

async function verifySignatures(
  signedData: SignedData,
  embeddedCertificates: readonly Certificate[],
  limits: ResourceLimits,
  engine: ICryptoEngine
): Promise<readonly Certificate[]> {
  assertSupportedSignerAlgorithms(signedData);
  const signers: Certificate[] = [];

  for (let signer = 0; signer < signedData.signerInfos.length; signer += 1) {
    try {
      const result = await signedData.verify(
        { checkChain: false, extendedMode: true, signer },
        engine
      );
      if (result.signatureVerified !== true || !(result.signerCertificate instanceof Certificate)) {
        throw new UdidToolsError("INVALID_SIGNATURE", "A CMS signature is invalid.");
      }
      signers.push(result.signerCertificate);
    } catch (error) {
      if (error instanceof UdidToolsError) {
        throw error;
      }

      throw new UdidToolsError("INVALID_SIGNATURE", "A CMS signature is invalid.");
    }
  }

  // PKI.js should resolve each signer from the embedded set. This explicit
  // cross-check prevents a future verifier behavior change from silently using
  // certificate material outside the parsed CMS container.
  for (const signer of signers) {
    const fingerprint = certificateFingerprint(signer);
    if (
      !embeddedCertificates.some(
        (certificate) => certificateFingerprint(certificate) === fingerprint
      )
    ) {
      throw new UdidToolsError("MALFORMED_CMS", "A CMS signer certificate is not embedded.");
    }
    if (certificateDer(signer).byteLength > limits.maxCertificateBytes) {
      throw new UdidToolsError("INPUT_TOO_LARGE", "A CMS signer certificate is too large.");
    }
  }

  return signers;
}

async function verifyTrustChains(
  signers: readonly Certificate[],
  embeddedCertificates: readonly Certificate[],
  intermediates: readonly Certificate[],
  trustAnchors: readonly Certificate[],
  engine: ICryptoEngine
): Promise<void> {
  for (const signer of signers) {
    const validation = new CertificateChainValidationEngine({
      certs: [
        ...deduplicateCertificates([
          signer,
          ...embeddedCertificates,
          ...intermediates,
          ...trustAnchors,
        ]),
      ],
      checkDate: new Date(),
      trustedCerts: [...trustAnchors],
    });

    const result = await validation.verify({ passedWhenNotRevValues: true }, engine);
    if (!result.result) {
      throw new UdidToolsError("UNTRUSTED_SIGNER", "The CMS signer is not trusted.", {
        details: { resultCode: result.resultCode },
      });
    }
  }
}

function extractAttachedContent(signedData: SignedData, limits: ResourceLimits): Uint8Array {
  if (signedData.encapContentInfo.eContentType !== CMS_DATA_OID) {
    throw new UdidToolsError("MALFORMED_CMS", "The attached CMS content type must be CMS Data.");
  }

  const encapsulated = signedData.encapContentInfo.eContent;
  if (!(encapsulated instanceof asn1js.OctetString)) {
    throw new UdidToolsError("MALFORMED_CMS", "Attached CMS content is required.");
  }

  const content = Uint8Array.from(new Uint8Array(encapsulated.getValue()));
  if (content.byteLength > limits.maxOutputBytes) {
    throw new UdidToolsError("OUTPUT_TOO_LARGE", "The attached CMS content is too large.", {
      details: { maxBytes: limits.maxOutputBytes },
    });
  }

  return content;
}

function embeddedX509Certificates(signedData: SignedData): readonly Certificate[] {
  return (signedData.certificates ?? []).filter(
    (certificate): certificate is Certificate => certificate instanceof Certificate
  );
}

/** Parses attached CMS, optionally verifies every signature and caller-supplied trust chain. */
export async function inspectAndVerifyCms(
  input: Uint8Array,
  verification: ResponseVerificationOptions,
  limits: ResourceLimits
): Promise<InspectedCms> {
  if (input.byteLength === 0) {
    throw new UdidToolsError("MALFORMED_CMS", "The CMS input must not be empty.");
  }
  if (input.byteLength > limits.maxInputBytes) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "The CMS input is too large.", {
      details: { maxBytes: limits.maxInputBytes },
    });
  }

  let signedData: SignedData;
  try {
    // node-forge provides a separate strict DER parser with a per-call depth
    // limit. Running it first rejects trailing garbage and avoids exposing the
    // PKI.js/asn1js parser to obviously pathological nesting.
    preflightDer(input, limits);
    const contentInfo = new ContentInfo({ schema: parseAsn1(input, limits) });
    if (contentInfo.contentType !== CMS_SIGNED_DATA_OID) {
      throw new UdidToolsError("MALFORMED_CMS", "The CMS input is not SignedData.");
    }
    signedData = new SignedData({ schema: contentInfo.content });
  } catch (error) {
    if (error instanceof UdidToolsError) {
      throw error;
    }

    throw new UdidToolsError("MALFORMED_CMS", "The CMS input could not be decoded.");
  }

  if (signedData.signerInfos.length === 0) {
    throw new UdidToolsError("MALFORMED_CMS", "The CMS input has no signers.");
  }
  if (signedData.signerInfos.length > limits.maxCertificates) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "The CMS input has too many signers.");
  }

  const content = extractAttachedContent(signedData, limits);
  const embeddedCertificates = embeddedX509Certificates(signedData);
  ensureCertificateLimits(embeddedCertificates, limits);

  if (embeddedCertificates.length === 0) {
    throw new UdidToolsError("MALFORMED_CMS", "The CMS input has no X.509 certificates.");
  }

  if (verification.mode === "none") {
    const signers = signedData.signerInfos.map((_, index) =>
      findSignerCertificate(signedData, index, embeddedCertificates, limits)
    );
    if (signers.some((signer) => signer === null)) {
      throw new UdidToolsError("MALFORMED_CMS", "A CMS signer certificate could not be resolved.");
    }

    return {
      content,
      signature: {
        present: true,
        signers: signers
          .filter((signer): signer is Certificate => signer !== null)
          .map(toCertificateInfo),
        trusted: null,
        valid: null,
      },
      warnings: [
        {
          code: "SIGNER_TRUST_NOT_CHECKED",
          message: "CMS signature and signer trust were not checked.",
        },
      ],
    };
  }

  const engine = cryptoEngine();
  const signers = await verifySignatures(signedData, embeddedCertificates, limits, engine);
  if (verification.mode === "signature") {
    return {
      content,
      signature: {
        present: true,
        signers: signers.map(toCertificateInfo),
        trusted: null,
        valid: true,
      },
      warnings: [
        {
          code: "SIGNER_TRUST_NOT_CHECKED",
          message: "The CMS signature is valid, but signer trust was not checked.",
        },
      ],
    };
  }

  if (verification.trustAnchors.length === 0) {
    throw new UdidToolsError(
      "INVALID_CONFIGURATION",
      "Trust-chain verification requires at least one trust anchor."
    );
  }

  const totalExternalCertificates =
    verification.trustAnchors.length + (verification.intermediates?.length ?? 0);
  if (embeddedCertificates.length + totalExternalCertificates > limits.maxCertificates) {
    throw new UdidToolsError(
      "INPUT_TOO_LARGE",
      "Too many verification certificates were provided.",
      {
        details: { maxCertificates: limits.maxCertificates },
      }
    );
  }

  const trustAnchors = verification.trustAnchors.map((input) =>
    parseCertificateInput(input, limits)
  );
  const intermediates = (verification.intermediates ?? []).map((input) =>
    parseCertificateInput(input, limits)
  );
  await verifyTrustChains(signers, embeddedCertificates, intermediates, trustAnchors, engine);

  return {
    content,
    signature: {
      present: true,
      signers: signers.map(toCertificateInfo),
      trusted: true,
      valid: true,
    },
    warnings: [],
  };
}
