import { Buffer } from "node:buffer";

import { UdidToolsError, type UdidToolsErrorCode } from "../errors.js";
import type { ResourceLimits } from "../limits.js";
import type { BinaryInput } from "../types.js";

const PEM_PATTERN =
  /^-----BEGIN ([A-Z0-9][A-Z0-9 ._/-]*)-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END \1-----\s*$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export interface DecodedPem {
  readonly bytes: Uint8Array;
  readonly label: string;
}

interface RuntimeEncodedBinaryInput {
  readonly encoding?: unknown;
  readonly value: string;
}

function isRuntimeEncodedBinaryInput(value: unknown): value is RuntimeEncodedBinaryInput {
  return (
    typeof value === "object" &&
    value !== null &&
    "value" in value &&
    typeof value.value === "string"
  );
}

function assertWithinLimit(
  length: number,
  maxBytes: number,
  errorCode: UdidToolsErrorCode,
  inputKind: string
): void {
  if (length > maxBytes) {
    throw new UdidToolsError("INPUT_TOO_LARGE", `${inputKind} exceeds the configured byte limit.`, {
      details: { inputKind, maxBytes },
    });
  }

  if (length === 0) {
    throw new UdidToolsError(errorCode, `${inputKind} must not be empty.`);
  }
}

function decodeBase64(value: string, errorCode: UdidToolsErrorCode, inputKind: string): Uint8Array {
  const compact = value.replace(/[\t\n\r ]/gu, "");

  if (compact.length === 0 || compact.length % 4 !== 0 || !BASE64_PATTERN.test(compact)) {
    throw new UdidToolsError(errorCode, `${inputKind} is not valid base64.`);
  }

  const decoded = Buffer.from(compact, "base64");

  // Buffer is intentionally not permissive here: canonical re-encoding must match.
  if (decoded.toString("base64") !== compact) {
    throw new UdidToolsError(errorCode, `${inputKind} is not canonical base64.`);
  }

  return Uint8Array.from(decoded);
}

export function decodePem(
  value: string,
  limits: ResourceLimits,
  errorCode: UdidToolsErrorCode = "INVALID_CERTIFICATE",
  inputKind = "Certificate",
  maxBytes = limits.maxCertificateBytes
): DecodedPem {
  if (Buffer.byteLength(value, "utf8") > limits.maxStringBytes) {
    throw new UdidToolsError(
      "INPUT_TOO_LARGE",
      `${inputKind} text exceeds the configured byte limit.`,
      {
        details: { inputKind, maxBytes: limits.maxStringBytes },
      }
    );
  }

  const match = PEM_PATTERN.exec(value.trim());
  if (match === null) {
    throw new UdidToolsError(errorCode, `${inputKind} is not valid PEM.`);
  }

  const label = match[1];
  const body = match[2];
  if (label === undefined || body === undefined) {
    throw new UdidToolsError(errorCode, `${inputKind} is not valid PEM.`);
  }

  const bytes = decodeBase64(body, errorCode, inputKind);
  assertWithinLimit(bytes.byteLength, maxBytes, errorCode, inputKind);

  return { bytes, label };
}

export function decodeBinaryInput(
  input: BinaryInput,
  limits: ResourceLimits,
  options: {
    readonly errorCode?: UdidToolsErrorCode;
    readonly inputKind?: string;
    readonly maxBytes?: number;
    readonly pemLabels?: readonly string[];
  } = {}
): Uint8Array {
  const errorCode = options.errorCode ?? "INVALID_CERTIFICATE";
  const inputKind = options.inputKind ?? "Binary input";
  const maxBytes = options.maxBytes ?? limits.maxCertificateBytes;

  if (input instanceof Uint8Array) {
    assertWithinLimit(input.byteLength, maxBytes, errorCode, inputKind);
    return Uint8Array.from(input);
  }

  const encodedInput: unknown = input;
  if (!isRuntimeEncodedBinaryInput(encodedInput)) {
    throw new UdidToolsError(errorCode, `${inputKind} has an invalid binary input shape.`);
  }

  if (Buffer.byteLength(encodedInput.value, "utf8") > limits.maxStringBytes) {
    throw new UdidToolsError(
      "INPUT_TOO_LARGE",
      `${inputKind} text exceeds the configured byte limit.`,
      {
        details: { inputKind, maxBytes: limits.maxStringBytes },
      }
    );
  }

  let bytes: Uint8Array;
  if (encodedInput.encoding === "base64") {
    bytes = decodeBase64(encodedInput.value, errorCode, inputKind);
  } else if (encodedInput.encoding === "pem") {
    const decoded = decodePem(encodedInput.value, limits, errorCode, inputKind, maxBytes);
    if (options.pemLabels !== undefined && !options.pemLabels.includes(decoded.label)) {
      throw new UdidToolsError(errorCode, `${inputKind} has an unsupported PEM label.`, {
        details: { label: decoded.label },
      });
    }
    bytes = decoded.bytes;
  } else {
    throw new UdidToolsError(errorCode, `${inputKind} uses an unsupported binary encoding.`);
  }

  assertWithinLimit(bytes.byteLength, maxBytes, errorCode, inputKind);
  return bytes;
}

export function bytesToBinaryString(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("latin1");
}

export function binaryStringToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "latin1"));
}
