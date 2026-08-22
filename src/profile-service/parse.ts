import { createHash, timingSafeEqual } from "node:crypto";

import { inspectAndVerifyCms } from "../cms/index.js";
import { UdidToolsError, type UdidToolsWarning } from "../errors.js";
import { resolveLimits } from "../limits.js";
import { decodePlist } from "../plist/index.js";
import { failure, success, unwrapResult, type Result } from "../result.js";
import {
  KNOWN_DEVICE_ATTRIBUTES,
  type ParseProfileServiceResponseOptions,
  type PlistValue,
  type ProfileServiceAttributes,
  type ProfileServiceChallenge,
  type ProfileServiceResponse,
  type ProfileServiceResponseInput,
} from "../types.js";

const ATTRIBUTE_MAP = {
  ICCID: "iccid",
  IMEI: "imei",
  MAC_ADDRESS_EN0: "macAddressEn0",
  MEID: "meid",
  PRODUCT: "product",
  SERIAL: "serialNumber",
  UDID: "udid",
  VERSION: "version",
} as const;

function safeAttributeName(value: string): string {
  const printable = value.replace(/[^\x20-\x7e]/gu, "?");
  return printable.length <= 128 ? printable : `${printable.slice(0, 128)}…`;
}

function toBytes(input: ProfileServiceResponseInput): Uint8Array {
  if (typeof input === "string") {
    return new TextEncoder().encode(input);
  }
  if (input instanceof Uint8Array) {
    return Uint8Array.from(input);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input.slice(0));
  }
  throw new UdidToolsError("MALFORMED_CMS", "The Profile Service response input is invalid.");
}

function isRecord(value: PlistValue): value is Readonly<Record<string, PlistValue>> {
  return (
    typeof value === "object" &&
    value !== null &&
    !(value instanceof Date) &&
    !(value instanceof Uint8Array) &&
    !Array.isArray(value)
  );
}

function normalizeResponse(
  raw: Readonly<Record<string, PlistValue>>,
  required: readonly string[],
  expected: readonly string[],
  warnings: UdidToolsWarning[]
): { readonly attributes: ProfileServiceAttributes; readonly challenge?: string | Uint8Array } {
  const attributes: Record<string, string> = Object.create(null) as Record<string, string>;
  let challenge: string | Uint8Array | undefined;

  for (const [key, value] of Object.entries(raw)) {
    if (key === "CHALLENGE") {
      if (typeof value !== "string" && !(value instanceof Uint8Array)) {
        throw new UdidToolsError("MALFORMED_PLIST", "CHALLENGE must be a string or data value.");
      }
      challenge = value;
      continue;
    }

    const normalizedKey = ATTRIBUTE_MAP[key as keyof typeof ATTRIBUTE_MAP];
    if (normalizedKey !== undefined) {
      if (typeof value !== "string") {
        throw new UdidToolsError("MALFORMED_PLIST", `${key} must be a string value.`);
      }
      attributes[normalizedKey] = value;
      continue;
    }

    warnings.push({
      code: "UNKNOWN_RESPONSE_ATTRIBUTE",
      message: "The response contains an unknown attribute that was preserved in raw data.",
      details: { attribute: safeAttributeName(key) },
    });
  }

  for (const expectedAttribute of expected) {
    const normalizedKey = ATTRIBUTE_MAP[expectedAttribute as keyof typeof ATTRIBUTE_MAP];
    if (normalizedKey !== undefined && attributes[normalizedKey] === undefined) {
      warnings.push({
        code: "OPTIONAL_ATTRIBUTE_MISSING",
        message: "A requested response attribute is missing.",
        details: { attribute: expectedAttribute },
      });
    }
  }

  for (const requiredAttribute of required) {
    const normalizedKey = ATTRIBUTE_MAP[requiredAttribute as keyof typeof ATTRIBUTE_MAP];
    if (normalizedKey !== undefined && attributes[normalizedKey] === undefined) {
      throw new UdidToolsError(
        "MISSING_REQUIRED_ATTRIBUTE",
        "A required Profile Service response attribute is missing.",
        { details: { attribute: requiredAttribute } }
      );
    }
  }

  return challenge === undefined ? { attributes } : { attributes, challenge };
}

function challengeMatches(actual: string | Uint8Array, expected: ProfileServiceChallenge): boolean {
  if (expected.type === "string" && typeof actual !== "string") {
    return false;
  }
  if (expected.type === "data" && !(actual instanceof Uint8Array)) {
    return false;
  }

  const actualBytes = typeof actual === "string" ? new TextEncoder().encode(actual) : actual;
  const expectedBytes =
    expected.type === "string" ? new TextEncoder().encode(expected.value) : expected.value;
  const actualDigest = createHash("sha256").update(actualBytes).digest();
  const expectedDigest = createHash("sha256").update(expectedBytes).digest();
  return timingSafeEqual(actualDigest, expectedDigest);
}

function validateVerificationOptions(options: ParseProfileServiceResponseOptions): void {
  const verification: unknown = options.verification;
  if (verification === undefined) {
    return;
  }
  if (typeof verification !== "object" || verification === null || !("mode" in verification)) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "The verification policy is invalid.");
  }
  const mode: unknown = verification.mode;
  if (mode !== "none" && mode !== "signature" && mode !== "trust-chain") {
    throw new UdidToolsError("INVALID_CONFIGURATION", "The verification mode is invalid.");
  }
  if (mode === "trust-chain") {
    const trustPolicy = verification as {
      readonly intermediates?: unknown;
      readonly trustAnchors?: unknown;
    };
    if (!Array.isArray(trustPolicy.trustAnchors)) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Trust-chain verification requires a trust-anchor array."
      );
    }
    if (trustPolicy.intermediates !== undefined && !Array.isArray(trustPolicy.intermediates)) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Verification intermediates must be an array."
      );
    }
  }
}

function validateAttributeList(value: unknown, field: string): void {
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value)) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "Response attributes must be an array.", {
      details: { field },
    });
  }
  const known = new Set<string>(KNOWN_DEVICE_ATTRIBUTES);
  const seen = new Set<string>();
  for (const attribute of value) {
    if (typeof attribute !== "string" || !known.has(attribute) || seen.has(attribute)) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Response attributes must contain unique known attribute names.",
        { details: { field } }
      );
    }
    seen.add(attribute);
  }
}

function validateExpectedChallenge(challenge: unknown, maximumBytes: number): void {
  if (challenge === undefined) {
    return;
  }
  if (typeof challenge !== "object" || challenge === null || !("type" in challenge)) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "The expected challenge is invalid.");
  }
  const candidate = challenge as { readonly type?: unknown; readonly value?: unknown };
  if (candidate.type === "string") {
    if (
      typeof candidate.value !== "string" ||
      candidate.value.length === 0 ||
      new TextEncoder().encode(candidate.value).byteLength > maximumBytes
    ) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "The expected string challenge is invalid or too large."
      );
    }
    return;
  }
  if (candidate.type === "data") {
    if (
      !(candidate.value instanceof Uint8Array) ||
      candidate.value.byteLength === 0 ||
      candidate.value.byteLength > maximumBytes
    ) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "The expected data challenge is invalid or too large."
      );
    }
    return;
  }
  throw new UdidToolsError("INVALID_CONFIGURATION", "The expected challenge type is unsupported.");
}

async function parseResponse(
  input: ProfileServiceResponseInput,
  options: ParseProfileServiceResponseOptions
): Promise<{
  readonly response: ProfileServiceResponse;
  readonly warnings: readonly UdidToolsWarning[];
}> {
  if (typeof options !== "object" || options === null) {
    throw new UdidToolsError(
      "INVALID_CONFIGURATION",
      "Response parsing options must be an object."
    );
  }
  validateVerificationOptions(options);
  const limits = resolveLimits(options.limits);
  if (options.allowUnsigned !== undefined && typeof options.allowUnsigned !== "boolean") {
    throw new UdidToolsError("INVALID_CONFIGURATION", "allowUnsigned must be a boolean.");
  }
  validateAttributeList(options.expectedAttributes, "expectedAttributes");
  validateAttributeList(options.requiredAttributes, "requiredAttributes");
  validateExpectedChallenge(options.expectedChallenge, limits.maxStringBytes);
  const inputBytes = toBytes(input);
  if (inputBytes.byteLength > limits.maxInputBytes) {
    throw new UdidToolsError(
      "INPUT_TOO_LARGE",
      "The Profile Service response exceeds the input limit."
    );
  }

  const warnings: UdidToolsWarning[] = [];
  const textPrefix = new TextDecoder().decode(inputBytes.subarray(0, 64)).trimStart();
  const isUnsignedXml = textPrefix.startsWith("<?xml") || textPrefix.startsWith("<plist");
  let plistBytes: Uint8Array;
  let signature: ProfileServiceResponse["signature"];

  if (isUnsignedXml) {
    if (options.allowUnsigned !== true) {
      throw new UdidToolsError(
        "MALFORMED_CMS",
        "An unsigned Profile Service response is not allowed."
      );
    }
    plistBytes = inputBytes;
    signature = { present: false, signers: [], trusted: null, valid: null };
  } else {
    const inspected = await inspectAndVerifyCms(
      inputBytes,
      options.verification ?? { mode: "signature" },
      limits
    );
    plistBytes = inspected.content;
    signature = inspected.signature;
    warnings.push(...inspected.warnings);
  }

  const decoded = decodePlist(plistBytes, limits);
  if (!isRecord(decoded)) {
    throw new UdidToolsError(
      "MALFORMED_PLIST",
      "The Profile Service response must contain a dictionary."
    );
  }

  const normalized = normalizeResponse(
    decoded,
    options.requiredAttributes ?? [],
    options.expectedAttributes ?? [],
    warnings
  );
  if (options.expectedChallenge !== undefined) {
    if (normalized.challenge === undefined) {
      throw new UdidToolsError(
        "MISSING_CHALLENGE",
        "The Profile Service response does not contain the expected challenge."
      );
    }
    if (!challengeMatches(normalized.challenge, options.expectedChallenge)) {
      throw new UdidToolsError(
        "CHALLENGE_MISMATCH",
        "The Profile Service response challenge does not match."
      );
    }
  }
  const response: ProfileServiceResponse = {
    attributes: normalized.attributes,
    raw: decoded,
    signature,
    ...(normalized.challenge === undefined ? {} : { challenge: normalized.challenge }),
  };

  return { response, warnings };
}

/** Verify, correlate, and parse a Profile Service response without throwing. */
export async function parseProfileServiceResponse(
  input: ProfileServiceResponseInput,
  options: ParseProfileServiceResponseOptions = {}
): Promise<Result<ProfileServiceResponse>> {
  try {
    const parsed = await parseResponse(input, options);
    return success(parsed.response, parsed.warnings);
  } catch (error) {
    return failure(error);
  }
}

/** Parse a Profile Service response and throw {@link UdidToolsError} on failure. */
export async function parseProfileServiceResponseOrThrow(
  input: ProfileServiceResponseInput,
  options: ParseProfileServiceResponseOptions = {}
): Promise<ProfileServiceResponse> {
  return unwrapResult(await parseProfileServiceResponse(input, options));
}
