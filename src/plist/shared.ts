import { Buffer } from "node:buffer";

import { UdidToolsError } from "../errors.js";
import type { ResourceLimits } from "../limits.js";

export function malformedPlist(message: string): UdidToolsError {
  return new UdidToolsError("MALFORMED_PLIST", message);
}

export function limitExceeded(
  limit: keyof ResourceLimits,
  maximum: number,
  actual?: number
): UdidToolsError {
  const code = limit === "maxOutputBytes" ? "OUTPUT_TOO_LARGE" : "INPUT_TOO_LARGE";
  return new UdidToolsError(code, "A configured plist resource limit was exceeded.", {
    details: actual === undefined ? { limit, maximum } : { actual, limit, maximum },
  });
}

export function utf8ByteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

export function assertStringWithinLimit(value: string, limits: ResourceLimits): void {
  const byteLength = utf8ByteLength(value);
  if (byteLength > limits.maxStringBytes) {
    throw limitExceeded("maxStringBytes", limits.maxStringBytes, byteLength);
  }
}

export function assertValidXmlText(value: string): void {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === undefined ||
      !(
        codePoint === 0x09 ||
        codePoint === 0x0a ||
        codePoint === 0x0d ||
        (codePoint >= 0x20 && codePoint <= 0xd7ff) ||
        (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
        (codePoint >= 0x10000 && codePoint <= 0x10ffff)
      )
    ) {
      throw malformedPlist("A plist string contains a character that XML 1.0 cannot represent.");
    }
  }
}

export function assertDepth(depth: number, limits: ResourceLimits): void {
  if (depth > limits.maxPlistDepth) {
    throw limitExceeded("maxPlistDepth", limits.maxPlistDepth, depth);
  }
}
