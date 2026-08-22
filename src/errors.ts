/** Stable machine-readable error codes returned by the public API. */
export type UdidToolsErrorCode =
  | "CERTIFICATE_KEY_MISMATCH"
  | "CHALLENGE_MISMATCH"
  | "INCORRECT_PASSPHRASE"
  | "INPUT_TOO_LARGE"
  | "INTERNAL_ERROR"
  | "INVALID_CERTIFICATE"
  | "INVALID_CONFIGURATION"
  | "INVALID_PKCS12"
  | "INVALID_PRIVATE_KEY"
  | "INVALID_PROFILE_IDENTIFIER"
  | "INVALID_RESPONSE_URL"
  | "INVALID_SIGNATURE"
  | "MALFORMED_CMS"
  | "MALFORMED_PLIST"
  | "MISSING_CHALLENGE"
  | "MISSING_REQUIRED_ATTRIBUTE"
  | "MISSING_SIGNING_MATERIAL"
  | "OUTPUT_TOO_LARGE"
  | "PROFILE_SIGNING_FAILED"
  | "UNSUPPORTED_ALGORITHM"
  | "UNTRUSTED_SIGNER";

export interface UdidToolsErrorOptions {
  readonly details?: Readonly<Record<string, unknown>>;
}

/** A sanitized, typed error. Secret input values are never included in its fields. */
export class UdidToolsError extends Error {
  readonly code: UdidToolsErrorCode;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(code: UdidToolsErrorCode, message: string, options: UdidToolsErrorOptions = {}) {
    super(message);
    this.name = "UdidToolsError";
    this.code = code;
    this.details = options.details;
  }
}

export type UdidToolsWarningCode =
  | "CERTIFICATE_EXPIRES_SOON"
  | "CERTIFICATE_NOT_YET_VALID"
  | "DUPLICATE_CERTIFICATE_IGNORED"
  | "INSECURE_RESPONSE_URL"
  | "OPTIONAL_ATTRIBUTE_MISSING"
  | "SIGNER_TRUST_NOT_CHECKED"
  | "UNKNOWN_RESPONSE_ATTRIBUTE";

export interface UdidToolsWarning {
  readonly code: UdidToolsWarningCode;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly message: string;
}

export function toUdidToolsError(error: unknown): UdidToolsError {
  if (error instanceof UdidToolsError) {
    return error;
  }

  return new UdidToolsError("INTERNAL_ERROR", "An unexpected library error occurred.");
}
