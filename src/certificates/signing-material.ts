import {
  createHash,
  createHmac,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

import * as asn1js from "asn1js";
import {
  AuthenticatedSafe,
  Certificate,
  CertBag,
  PKCS8ShroudedKeyBag,
  PrivateKeyInfo,
  PFX,
  SafeContents,
} from "pkijs";

import { UdidToolsError, type UdidToolsWarning } from "../errors.js";
import type { ResourceLimits } from "../limits.js";
import type { BinaryInput, CertificateInput, SigningOptions } from "../types.js";
import { decodeBinaryInput } from "./binary-input.js";
import { preflightDer } from "./der.js";

const CERTIFICATE_PEM_LABELS = ["CERTIFICATE", "X509 CERTIFICATE"] as const;
const PKCS12_PEM_LABELS = ["PKCS12", "PFX"] as const;
const EXPIRY_WARNING_WINDOW_MS = 30 * 24 * 60 * 60 * 1_000;
const KEY_BAG_OID = "1.2.840.113549.1.12.10.1.1";
const PKCS8_SHROUDED_KEY_BAG_OID = "1.2.840.113549.1.12.10.1.2";
const CERTIFICATE_BAG_OID = "1.2.840.113549.1.12.10.1.3";
const X509_CERTIFICATE_OID = "1.2.840.113549.1.9.22.1";
const PKCS12_TRIPLE_DES_OID = "1.2.840.113549.1.12.1.3";
const PKCS12_TWO_KEY_TRIPLE_DES_OID = "1.2.840.113549.1.12.1.2";
const MINIMUM_SIGNING_RSA_BITS = 2_048;

export interface SigningMaterial {
  readonly certificates: readonly Certificate[];
  readonly privateKey: KeyObject;
  readonly signerCertificate: Certificate;
  readonly warnings: readonly UdidToolsWarning[];
}

interface ParsedPkcs12 {
  readonly certificates: Certificate[];
  readonly privateKeys: KeyObject[];
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

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function parseCertificateDer(bytes: Uint8Array, limits: ResourceLimits): Certificate {
  try {
    preflightDer(bytes, limits);
    return Certificate.fromBER(toArrayBuffer(bytes));
  } catch {
    throw new UdidToolsError("INVALID_CERTIFICATE", "A certificate could not be decoded.");
  }
}

function certificateDer(certificate: Certificate): Uint8Array {
  return Uint8Array.from(new Uint8Array(certificate.toSchema(true).toBER(false)));
}

function certificateFingerprint(certificate: Certificate): string {
  return createHash("sha256").update(certificateDer(certificate)).digest("hex");
}

function parseCertificateInput(input: CertificateInput, limits: ResourceLimits): Certificate {
  const bytes = decodeBinaryInput(input, limits, {
    errorCode: "INVALID_CERTIFICATE",
    inputKind: "Certificate",
    maxBytes: limits.maxCertificateBytes,
    pemLabels: CERTIFICATE_PEM_LABELS,
  });
  return parseCertificateDer(bytes, limits);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength && timingSafeEqual(Buffer.from(left), Buffer.from(right))
  );
}

function pkcs12PasswordBytes(passphrase: string): Uint8Array {
  const password = Buffer.from(`${passphrase}\u0000`, "utf16le");
  password.swap16();
  return Uint8Array.from(password);
}

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
  const password = pkcs12PasswordBytes(passphrase);
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

function parsePbeParameters(value: unknown): {
  readonly salt: Uint8Array;
  readonly iterations: number;
} {
  if (!(value instanceof asn1js.Sequence)) {
    throw new Error("Invalid PKCS#12 encryption parameters.");
  }
  const entries = value.valueBlock.value;
  const salt = entries[0];
  const iterations = entries[1];
  if (!(salt instanceof asn1js.OctetString) || !(iterations instanceof asn1js.Integer)) {
    throw new Error("Invalid PKCS#12 encryption parameters.");
  }
  const count = iterations.valueBlock.valueDec;
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new Error("Invalid PKCS#12 iteration count.");
  }
  return { iterations: count, salt: Uint8Array.from(new Uint8Array(salt.getValue())) };
}

function decryptLegacyShroudedKey(bag: PKCS8ShroudedKeyBag, passphrase: string): Uint8Array {
  const algorithm = bag.encryptionAlgorithm.algorithmId;
  if (algorithm !== PKCS12_TRIPLE_DES_OID && algorithm !== PKCS12_TWO_KEY_TRIPLE_DES_OID) {
    throw new Error(`Unsupported PKCS#12 key encryption algorithm: ${algorithm}`);
  }
  const parameters = parsePbeParameters(bag.encryptionAlgorithm.algorithmParams);
  const key = pkcs12Kdf(passphrase, parameters.salt, parameters.iterations, 1, 24, "sha1");
  const iv = pkcs12Kdf(passphrase, parameters.salt, parameters.iterations, 2, 8, "sha1");
  const decipher = createDecipheriv("des-ede3-cbc", Buffer.from(key), Buffer.from(iv));
  return Uint8Array.from(
    Buffer.concat([decipher.update(Buffer.from(bag.encryptedData.getValue())), decipher.final()])
  );
}

function verifyPkcs12Mac(pfx: PFX, content: Uint8Array, passphrase: string): void {
  if (pfx.macData === undefined) {
    throw new Error("PKCS#12 integrity data is missing.");
  }
  const digestOid = pfx.macData.mac.digestAlgorithm.algorithmId;
  const hashAlgorithm =
    digestOid === "1.3.14.3.2.26"
      ? "sha1"
      : digestOid === "2.16.840.1.101.3.4.2.1"
        ? "sha256"
        : null;
  if (hashAlgorithm === null) {
    throw new Error(`Unsupported PKCS#12 MAC algorithm: ${digestOid}`);
  }
  const key = pkcs12Kdf(
    passphrase,
    Uint8Array.from(new Uint8Array(pfx.macData.macSalt.valueBlock.valueHexView)),
    pfx.macData.iterations ?? 1,
    3,
    hashAlgorithm === "sha1" ? 20 : 32,
    hashAlgorithm
  );
  const actual = createHmac(hashAlgorithm, key).update(content).digest();
  const expected = Buffer.from(pfx.macData.mac.digest.valueBlock.valueHexView);
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) {
    throw new Error("MAC could not be verified.");
  }
}

function parsePkcs12(signing: SigningOptions, limits: ResourceLimits): ParsedPkcs12 {
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

  const passphrase = identity.passphrase ?? "";
  const bytes = decodeBinaryInput(identity.data as BinaryInput, limits, {
    errorCode: "INVALID_PKCS12",
    inputKind: "PKCS#12 identity",
    maxBytes: limits.maxInputBytes,
    pemLabels: PKCS12_PEM_LABELS,
  });

  try {
    const pfx = PFX.fromBER(toArrayBuffer(bytes));
    if (
      pfx.authSafe.contentType !== "1.2.840.113549.1.7.1" ||
      !(pfx.authSafe.content instanceof asn1js.OctetString)
    ) {
      throw new Error("Unsupported PKCS#12 authenticated safe.");
    }
    const authSafeContent = Uint8Array.from(new Uint8Array(pfx.authSafe.content.getValue()));
    verifyPkcs12Mac(pfx, authSafeContent, passphrase);
    const authenticatedSafe = AuthenticatedSafe.fromBER(toArrayBuffer(authSafeContent));
    const certificates: Certificate[] = [];
    const privateKeys: KeyObject[] = [];

    for (const contentInfo of authenticatedSafe.safeContents) {
      if (
        contentInfo.contentType !== "1.2.840.113549.1.7.1" ||
        !(contentInfo.content instanceof asn1js.OctetString)
      ) {
        throw new Error("Encrypted PKCS#12 safe contents are not supported.");
      }
      const contents = SafeContents.fromBER(contentInfo.content.getValue());
      for (const bag of contents.safeBags) {
        if (bag.bagId === CERTIFICATE_BAG_OID && bag.bagValue instanceof CertBag) {
          if (
            bag.bagValue.certId !== X509_CERTIFICATE_OID ||
            !(bag.bagValue.certValue instanceof asn1js.OctetString)
          ) {
            /* c8 ignore next -- PKI.js rejects malformed CertBag values during schema decoding. */
            continue;
          }
          const certificateBytes = Uint8Array.from(
            new Uint8Array(bag.bagValue.certValue.getValue())
          );
          certificates.push(parseCertificateDer(certificateBytes, limits));
        } else if (bag.bagId === KEY_BAG_OID && bag.bagValue instanceof PrivateKeyInfo) {
          privateKeys.push(
            createPrivateKey({
              key: Buffer.from(bag.bagValue.toSchema().toBER(false)),
              format: "der",
              type: "pkcs8",
            })
          );
        } else if (
          bag.bagId === PKCS8_SHROUDED_KEY_BAG_OID &&
          bag.bagValue instanceof PKCS8ShroudedKeyBag
        ) {
          const decrypted = decryptLegacyShroudedKey(bag.bagValue, passphrase);
          preflightDer(decrypted, limits);
          privateKeys.push(
            createPrivateKey({ key: Buffer.from(decrypted), format: "der", type: "pkcs8" })
          );
        }
      }
    }
    return { certificates, privateKeys };
  } catch (error) {
    const message = asErrorMessage(error);
    if (message.includes("MAC could not be verified") || message.includes("Invalid password")) {
      throw new UdidToolsError("INCORRECT_PASSPHRASE", "The PKCS#12 passphrase is incorrect.");
    }
    throw new UdidToolsError("INVALID_PKCS12", "The PKCS#12 identity could not be decoded.");
  }
}

function keyMatchesCertificate(privateKey: KeyObject, certificate: Certificate): boolean {
  try {
    const privatePublicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" });
    const certificatePublicKey = certificate.subjectPublicKeyInfo.toSchema().toBER(false);
    return equalBytes(
      Uint8Array.from(privatePublicKey),
      Uint8Array.from(new Uint8Array(certificatePublicKey))
    );
  } catch {
    /* c8 ignore next -- parsed PKI.js certificates have a valid SPKI schema. */
    return false;
  }
}

function validateSignerCertificate(
  certificate: Certificate,
  now: Date
): readonly UdidToolsWarning[] {
  const notBefore = certificate.notBefore.value;
  const notAfter = certificate.notAfter.value;
  if (
    !(notBefore instanceof Date) ||
    !(notAfter instanceof Date) ||
    notAfter.getTime() <= now.getTime()
  ) {
    throw new UdidToolsError("INVALID_CERTIFICATE", "The signing certificate has expired.");
  }
  const warnings: UdidToolsWarning[] = [];
  if (notBefore.getTime() > now.getTime()) {
    warnings.push({
      code: "CERTIFICATE_NOT_YET_VALID",
      details: { notBefore: notBefore.toISOString() },
      message: "The signing certificate is not valid yet.",
    });
  }
  if (notAfter.getTime() - now.getTime() <= EXPIRY_WARNING_WINDOW_MS) {
    warnings.push({
      code: "CERTIFICATE_EXPIRES_SOON",
      details: { notAfter: notAfter.toISOString() },
      message: "The signing certificate expires within 30 days.",
    });
  }
  return warnings;
}

function deduplicateCertificates(certificates: readonly Certificate[]): {
  readonly certificates: readonly Certificate[];
  readonly duplicateCount: number;
} {
  const seen = new Set<string>();
  const unique: Certificate[] = [];
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
  const parsed = parsePkcs12(signing, limits);
  if (parsed.privateKeys.length > limits.maxCertificates) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "The PKCS#12 identity contains too many keys.", {
      details: { maxKeys: limits.maxCertificates },
    });
  }
  if (parsed.certificates.length + additionalInputs.length > limits.maxCertificates) {
    throw new UdidToolsError("INPUT_TOO_LARGE", "Too many certificates were provided.", {
      details: { maxCertificates: limits.maxCertificates },
    });
  }
  if (parsed.privateKeys.length === 0) {
    throw new UdidToolsError(
      "MISSING_SIGNING_MATERIAL",
      "The PKCS#12 identity does not contain a private key."
    );
  }
  const privateKeys = parsed.privateKeys.filter((key) => key.asymmetricKeyType === "rsa");
  if (privateKeys.length === 0) {
    throw new UdidToolsError(
      "UNSUPPORTED_ALGORITHM",
      "The PKCS#12 identity does not contain a supported RSA private key."
    );
  }
  if (parsed.certificates.length === 0) {
    throw new UdidToolsError(
      "MISSING_SIGNING_MATERIAL",
      "The PKCS#12 identity does not contain a signer certificate."
    );
  }
  for (const certificate of parsed.certificates) {
    if (certificateDer(certificate).byteLength > limits.maxCertificateBytes) {
      throw new UdidToolsError("INPUT_TOO_LARGE", "A certificate exceeds the configured limit.", {
        details: { maxBytes: limits.maxCertificateBytes },
      });
    }
  }

  const matches = privateKeys.flatMap((privateKey) =>
    parsed.certificates
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
  /* c8 ignore next 3 -- matches is non-empty after the guard above. */
  if (match === undefined) {
    throw new UdidToolsError("INTERNAL_ERROR", "The signing identity could not be selected.");
  }
  if ((match.privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < MINIMUM_SIGNING_RSA_BITS) {
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
    ...parsed.certificates.filter((certificate) => certificate !== match.signerCertificate),
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
