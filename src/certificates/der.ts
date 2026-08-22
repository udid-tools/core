import forge from "node-forge";

import type { ResourceLimits } from "../limits.js";
import { bytesToBinaryString } from "./binary-input.js";

interface ForgeFromDerOptions {
  readonly decodeBitStrings: boolean;
  readonly maxDepth: number;
  readonly parseAllBytes: boolean;
  readonly strict: boolean;
}

type ForgeFromDer = (
  bytes: string | forge.util.ByteBuffer,
  options: ForgeFromDerOptions
) => forge.asn1.Asn1;

// @types/node-forge predates node-forge 1.4.0's per-call maxDepth option.
const fromDer = forge.asn1.fromDer as unknown as ForgeFromDer;

/**
 * Strict, bounded DER preflight used before any third-party ASN.1/CMS parser.
 *
 * `decodeBitStrings` is deliberately disabled. node-forge may recursively
 * interpret arbitrary BIT STRING contents as ASN.1 and that secondary path has
 * historically not inherited every per-call parser option. This pass rejects
 * trailing bytes and bounds explicit constructed nesting. It cannot make an
 * independent downstream parser memory-safe; callers must still enforce the
 * byte limits before invoking this helper.
 */
export function preflightDer(bytes: Uint8Array, limits: ResourceLimits): forge.asn1.Asn1 {
  return fromDer(bytesToBinaryString(bytes), {
    decodeBitStrings: false,
    maxDepth: limits.maxAsn1Depth,
    parseAllBytes: true,
    strict: true,
  });
}

/** Parses DER for node-forge consumers after the bounded non-decoding preflight. */
export function parseDerForForge(bytes: Uint8Array, limits: ResourceLimits): forge.asn1.Asn1 {
  preflightDer(bytes, limits);
  return fromDer(bytesToBinaryString(bytes), {
    decodeBitStrings: true,
    maxDepth: limits.maxAsn1Depth,
    parseAllBytes: true,
    strict: true,
  });
}
