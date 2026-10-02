import * as asn1js from "asn1js";

import type { ResourceLimits } from "../limits.js";

/** Strict, bounded DER preflight used before any third-party ASN.1 parser. */
export function preflightDer(bytes: Uint8Array, limits: ResourceLimits): asn1js.AsnType {
  const parsed = asn1js.fromBER(Uint8Array.from(bytes).buffer, {
    maxContentLength: limits.maxInputBytes,
    maxDepth: limits.maxAsn1Depth,
    maxNodes: limits.maxAsn1Nodes,
  });

  if (parsed.offset === -1 || parsed.offset !== bytes.byteLength) {
    throw new Error("The input is not a complete DER document.");
  }

  return parsed.result;
}
