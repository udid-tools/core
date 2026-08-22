import { createHash } from "node:crypto";

import forge from "node-forge";

import { UdidToolsError, type UdidToolsWarning } from "../errors.js";
import type { ResourceLimits } from "../limits.js";
import type { BinaryInput, CertificateInput, SigningOptions } from "../types.js";
import { decodeBinaryInput } from "./binary-input.js";
import { parseDerForForge, preflightDer } from "./der.js";

const CERTIFICATE_PEM_LABELS = ["CERTIFICATE", "X509 CERTIFICATE"] as const;
const PKCS12_PEM_LABELS = ["PKCS12", "PFX"] as const;
const EXPIRY_WARNING_WINDOW_MS = 30 * 24 * 60 * 60 * 1_000;
const KEY_BAG_OID = "1.2.840.113549.1.12.10.1.1";
const PKCS8_SHROUDED_KEY_BAG_OID = "1.2.840.113549.1.12.10.1.2";
const CERTIFICATE_BAG_OID = "1.2.840.113549.1.12.10.1.3";
const MINIMUM_SIGNING_RSA_BITS = 2_048;

export interface SigningMaterial {
  readonly certificates: readonly forge.pki.Certificate[];
  readonly privateKey: forge.pki.rsa.PrivateKey;
  readonly signerCertificate: forge.pki.Certificate;
  readonly warnings: readonly UdidToolsWarning[];
}

function asErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "";
}

interface RuntimeSigningIdentity {
  readonly data?: unknown;
  readonly passphrase?: unknown;
  readonly type?: unknown;
}

function getRuntimeSigningIdentity(signing: SigningOptions): RuntimeSigningIdentity | null {
  const candidate: unknown = signing;
  if (typeof candidate !== "object" || candidate === null || !("identity" in candidate)) {
    return null;
  }

  const identity: unknown = candidate.identity;
  if (typeof identity !== "object" || identity === null) {
    return null;
  }

  return identity;
}

function parseCertificateDer(bytes: Uint8Array, limits: ResourceLimits): forge.pki.Certificate {
  try {
    const asn1 = parseDerForForge(bytes, limits);
    return forge.pki.certificateFromAsn1(asn1, true);
  } catch {
    throw new UdidToolsError("INVALID_CERTIFICATE", "A certificate could not be decoded.");
  }
}

function certificateDer(certificate: forge.pki.Certificate): Uint8Array {
  const binary = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
  return Uint8Array.from(forge.util.binary.raw.decode(binary));
}

function certificateFingerprint(certificate: forge.pki.Certificate): string {
  return createHash("sha256").update(certificateDer(certificate)).digest("hex");
}

function parseCertificateInput(
  input: CertificateInput,
  limits: ResourceLimits
): forge.pki.Certificate {
  const bytes = decodeBinaryInput(input, limits, {
    errorCode: "INVALID_CERTIFICATE",
    inputKind: "Certificate",
    maxBytes: limits.maxCertificateBytes,
    pemLabels: CERTIFICATE_PEM_LABELS,
  });

  return parseCertificateDer(bytes, limits);
}

function isRsaPrivateKey(key: forge.pki.PrivateKey): key is forge.pki.rsa.PrivateKey {
  const candidate = key as Partial<forge.pki.rsa.PrivateKey>;
  return (
    candidate.n !== undefined &&
    candidate.e !== undefined &&
    candidate.d !== undefined &&
    typeof candidate.sign === "function"
  );
}

function isRsaPublicKey(key: forge.pki.PublicKey): key is forge.pki.rsa.PublicKey {
  const candidate = key as Partial<forge.pki.rsa.PublicKey>;
  return (
    candidate.n !== undefined && candidate.e !== undefined && typeof candidate.verify === "function"
  );
}

function keyMatchesCertificate(
  privateKey: forge.pki.rsa.PrivateKey,
  certificate: forge.pki.Certificate
): boolean {
  if (!isRsaPublicKey(certificate.publicKey)) {
    return false;
  }

  return (
    privateKey.n.compareTo(certificate.publicKey.n) === 0 &&
    privateKey.e.compareTo(certificate.publicKey.e) === 0
  );
}

function getBags(p12: forge.pkcs12.Pkcs12Pfx, bagType: string): readonly forge.pkcs12.Bag[] {
  return p12.getBags({ bagType })[bagType] ?? [];
}

function parsePkcs12(signing: SigningOptions, limits: ResourceLimits): forge.pkcs12.Pkcs12Pfx {
  const identity = getRuntimeSigningIdentity(signing);
  if (identity?.data === undefined) {
    throw new UdidToolsError(
      "MISSING_SIGNING_MATERIAL",
      "A PKCS#12 signing identity is required when signing is configured."
    );
  }

  if (identity.type !== "pkcs12") {
    throw new UdidToolsError(
      "UNSUPPORTED_ALGORITHM",
      "Only PKCS#12 signing identities are supported in this beta release."
    );
  }

  if (identity.passphrase !== undefined && typeof identity.passphrase !== "string") {
    throw new UdidToolsError("INVALID_CONFIGURATION", "The PKCS#12 passphrase must be a string.");
  }

  const bytes = decodeBinaryInput(identity.data as BinaryInput, limits, {
    errorCode: "INVALID_PKCS12",
    inputKind: "PKCS#12 identity",
    maxBytes: limits.maxInputBytes,
    pemLabels: PKCS12_PEM_LABELS,
  });

  let asn1: forge.asn1.Asn1;
  try {
    asn1 = preflightDer(bytes, limits);
  } catch {
    throw new UdidToolsError("INVALID_PKCS12", "The PKCS#12 identity is malformed.");
  }

  try {
    return forge.pkcs12.pkcs12FromAsn1(asn1, true, identity.passphrase);
  } catch (error) {
    const message = asErrorMessage(error);
    if (message.includes("MAC could not be verified") || message.includes("Invalid password")) {
      throw new UdidToolsError("INCORRECT_PASSPHRASE", "The PKCS#12 passphrase is incorrect.");
    }

    throw new UdidToolsError("INVALID_PKCS12", "The PKCS#12 identity could not be decoded.");
  }
}

function validateSignerCertificate(
  certificate: forge.pki.Certificate,
  now: Date
): readonly UdidToolsWarning[] {
  if (certificate.validity.notAfter.getTime() <= now.getTime()) {
    throw new UdidToolsError("INVALID_CERTIFICATE", "The signing certificate has expired.", {
      details: { notAfter: certificate.validity.notAfter.toISOString() },
    });
  }

  const warnings: UdidToolsWarning[] = [];
  if (certificate.validity.notBefore.getTime() > now.getTime()) {
    warnings.push({
      code: "CERTIFICATE_NOT_YET_VALID",
      details: { notBefore: certificate.validity.notBefore.toISOString() },
      message: "The signing certificate is not valid yet.",
    });
  }

  if (certificate.validity.notAfter.getTime() - now.getTime() <= EXPIRY_WARNING_WINDOW_MS) {
    warnings.push({
      code: "CERTIFICATE_EXPIRES_SOON",
      details: { notAfter: certificate.validity.notAfter.toISOString() },
      message: "The signing certificate expires within 30 days.",
    });
  }

  return warnings;
}

function deduplicateCertificates(certificates: readonly forge.pki.Certificate[]): {
  readonly certificates: readonly forge.pki.Certificate[];
  readonly duplicateCount: number;
} {
  const seen = new Set<string>();
  const unique: forge.pki.Certificate[] = [];
  let duplicateCount = 0;

  for (const certificate of certificates) {
    const fingerprint = certificateFingerprint(certificate);
    if (seen.has(fingerprint)) {
      duplicateCount += 1;
      continue;
    }

    seen.add(fingerprint);
    unique.push(certificate);
  }

  return { certificates: unique, duplicateCount };
}

export function loadSigningMaterial(
  signing: SigningOptions,
  limits: ResourceLimits
): SigningMaterial {
  const digestAlgorithm: unknown = (signing as unknown as { readonly digestAlgorithm?: unknown })
    .digestAlgorithm;
  if (digestAlgorithm !== undefined && digestAlgorithm !== "sha256") {
    throw new UdidToolsError(
      "UNSUPPORTED_ALGORITHM",
      "Only RSA with SHA-256 is supported in this beta release."
    );
  }

  const chainCandidate: unknown = signing.certificateChain;
  if (chainCandidate !== undefined && !Array.isArray(chainCandidate)) {
    throw new UdidToolsError(
      "INVALID_CONFIGURATION",
      "The signing certificate chain must be an array."
    );
  }
  const additionalInputs = (chainCandidate ?? []) as readonly CertificateInput[];
  const p12 = parsePkcs12(signing, limits);
  const keyBags = [...getBags(p12, PKCS8_SHROUDED_KEY_BAG_OID), ...getBags(p12, KEY_BAG_OID)];
  const certificateBags = getBags(p12, CERTIFICATE_BAG_OID);

  if (keyBags.length > limits.maxCertificates) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "The PKCS#12 identity contains too many keys.", {
      details: { maxKeys: limits.maxCertificates },
    });
  }

  if (certificateBags.length + additionalInputs.length > limits.maxCertificates) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "Too many certificates were provided.", {
      details: { maxCertificates: limits.maxCertificates },
    });
  }

  const allPrivateKeys = keyBags.flatMap((bag) => {
    const key = bag.key as forge.pki.PrivateKey | null | undefined;
    return key === undefined || key === null ? [] : [key];
  });
  if (allPrivateKeys.length === 0) {
    throw new UdidToolsError(
      "MISSING_SIGNING_MATERIAL",
      "The PKCS#12 identity does not contain a private key."
    );
  }

  const privateKeys = allPrivateKeys.filter(isRsaPrivateKey);
  if (privateKeys.length === 0) {
    throw new UdidToolsError(
      "UNSUPPORTED_ALGORITHM",
      "The PKCS#12 identity does not contain a supported RSA private key."
    );
  }

  const p12Certificates = certificateBags.flatMap((bag) => {
    const certificate = bag.cert as forge.pki.Certificate | null | undefined;
    return certificate === undefined || certificate === null ? [] : [certificate];
  });
  if (p12Certificates.length === 0) {
    throw new UdidToolsError(
      "MISSING_SIGNING_MATERIAL",
      "The PKCS#12 identity does not contain a signer certificate."
    );
  }

  for (const certificate of p12Certificates) {
    if (certificateDer(certificate).byteLength > limits.maxCertificateBytes) {
      throw new UdidToolsError("INPUT_TOO_LARGE", "A certificate exceeds the configured limit.", {
        details: { maxBytes: limits.maxCertificateBytes },
      });
    }
  }

  const matches = privateKeys.flatMap((privateKey) =>
    p12Certificates
      .filter((certificate) => keyMatchesCertificate(privateKey, certificate))
      .map((signerCertificate) => ({ privateKey, signerCertificate }))
  );

  if (matches.length === 0) {
    throw new UdidToolsError(
      "CERTIFICATE_KEY_MISMATCH",
      "No certificate in the PKCS#12 identity matches its RSA private key."
    );
  }

  if (matches.length > 1) {
    throw new UdidToolsError(
      "INVALID_PKCS12",
      "The PKCS#12 identity contains multiple matching signer identities."
    );
  }

  const match = matches[0];
  if (match === undefined) {
    throw new UdidToolsError("INTERNAL_ERROR", "The signing identity could not be selected.");
  }
  if (match.privateKey.n.bitLength() < MINIMUM_SIGNING_RSA_BITS) {
    throw new UdidToolsError(
      "INVALID_PRIVATE_KEY",
      "The RSA signing key must be at least 2048 bits."
    );
  }

  const additionalCertificates = additionalInputs.map((input) =>
    parseCertificateInput(input, limits)
  );
  const orderedCertificates = [
    match.signerCertificate,
    ...p12Certificates.filter((certificate) => certificate !== match.signerCertificate),
    ...additionalCertificates,
  ];
  const deduplicated = deduplicateCertificates(orderedCertificates);
  const warnings = [...validateSignerCertificate(match.signerCertificate, new Date())];

  if (deduplicated.duplicateCount > 0) {
    warnings.push({
      code: "DUPLICATE_CERTIFICATE_IGNORED",
      details: { count: deduplicated.duplicateCount },
      message: "Duplicate certificates were ignored.",
    });
  }

  return {
    certificates: deduplicated.certificates,
    privateKey: match.privateKey,
    signerCertificate: match.signerCertificate,
    warnings,
  };
}
