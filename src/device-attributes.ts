import { UdidToolsError } from "./errors.js";
import type { CustomDeviceAttribute } from "./types.js";

const ATTRIBUTE_PATTERN = /^[A-Z][A-Z0-9_]*$/u;

/**
 * Opt into a future or vendor-specific Profile Service attribute while keeping
 * accidental arbitrary strings out of the normal typed configuration path.
 */
export function customDeviceAttribute(value: string): CustomDeviceAttribute {
  if (!ATTRIBUTE_PATTERN.test(value)) {
    throw new UdidToolsError(
      "INVALID_CONFIGURATION",
      "A custom device attribute must contain only uppercase ASCII letters, digits, and underscores."
    );
  }

  return value as CustomDeviceAttribute;
}
