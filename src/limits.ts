import { UdidToolsError } from "./errors.js";

/** Bounded-work policy applied before and during parsing, encoding, and crypto. */
export interface ResourceLimits {
  readonly maxArrayItems: number;
  readonly maxAsn1Depth: number;
  readonly maxAsn1Nodes: number;
  readonly maxCertificateBytes: number;
  readonly maxCertificates: number;
  readonly maxDictionaryKeys: number;
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
  readonly maxPlistDepth: number;
  readonly maxStringBytes: number;
}

/** Security-oriented defaults used independently for every operation. */
export const DEFAULT_LIMITS: Readonly<ResourceLimits> = Object.freeze({
  maxArrayItems: 256,
  maxAsn1Depth: 32,
  maxAsn1Nodes: 8_192,
  maxCertificateBytes: 256 * 1024,
  maxCertificates: 16,
  maxDictionaryKeys: 256,
  maxInputBytes: 2 * 1024 * 1024,
  maxOutputBytes: 2 * 1024 * 1024,
  maxPlistDepth: 32,
  maxStringBytes: 512 * 1024,
});

/** Per-call resource-limit overrides. */
export type ResourceLimitsInput = Partial<ResourceLimits>;

export function resolveLimits(input: ResourceLimitsInput | undefined): ResourceLimits {
  const resolved = { ...DEFAULT_LIMITS, ...input };

  for (const [name, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Every resource limit must be a positive safe integer.",
        { details: { limit: name } }
      );
    }
  }

  return resolved;
}
