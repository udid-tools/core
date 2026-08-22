import { Buffer } from "node:buffer";

import { resolveLimits, type ResourceLimits, type ResourceLimitsInput } from "../limits.js";
import type { PlistValue } from "../types.js";
import { BASE64_PATTERN, PLIST_FOOTER, PLIST_HEADER, UNSAFE_DICTIONARY_KEYS } from "./constants.js";
import {
  assertDepth,
  assertStringWithinLimit,
  assertValidXmlText,
  limitExceeded,
  malformedPlist,
  utf8ByteLength,
} from "./shared.js";

const INDENT = "  ";

class BoundedXmlWriter {
  readonly #limits: ResourceLimits;
  readonly #segments: string[] = [];
  #byteLength = 0;

  constructor(limits: ResourceLimits) {
    this.#limits = limits;
  }

  append(segment: string): void {
    const segmentBytes = utf8ByteLength(segment);
    const nextLength = this.#byteLength + segmentBytes;
    if (nextLength > this.#limits.maxOutputBytes) {
      throw limitExceeded("maxOutputBytes", this.#limits.maxOutputBytes, nextLength);
    }

    this.#segments.push(segment);
    this.#byteLength = nextLength;
  }

  toBytes(): Uint8Array {
    return new TextEncoder().encode(this.#segments.join(""));
  }
}

function escapeXmlText(value: string): string {
  assertValidXmlText(value);

  return value.replace(/[&<>"'\r]/gu, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&apos;";
      case "\r":
        // XML normalizes literal carriage returns. A character reference preserves it.
        return "&#13;";
      default:
        return character;
    }
  });
}

function assertPlainDictionary(
  value: object
): asserts value is Readonly<Record<string, PlistValue>> {
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== null && prototype !== Object.prototype) {
    throw malformedPlist("A plist dictionary must be a plain object.");
  }

  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw malformedPlist("A plist dictionary cannot contain symbol keys.");
  }
}

function dictionaryKeys(
  value: Readonly<Record<string, PlistValue>>,
  limits: ResourceLimits
): string[] {
  const keys = Object.getOwnPropertyNames(value);
  if (keys.length > limits.maxDictionaryKeys) {
    throw limitExceeded("maxDictionaryKeys", limits.maxDictionaryKeys, keys.length);
  }

  for (const key of keys) {
    if (UNSAFE_DICTIONARY_KEYS.has(key)) {
      throw malformedPlist("A plist dictionary contains an unsafe key.");
    }

    assertStringWithinLimit(key, limits);
    assertValidXmlText(key);

    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      throw malformedPlist("A plist dictionary must contain only enumerable data properties.");
    }
  }

  return keys.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
}

function formatDate(value: Date): string {
  const timestamp = value.getTime();
  if (!Number.isFinite(timestamp)) {
    throw malformedPlist("A plist date must be valid.");
  }

  return value.toISOString();
}

function formatNumber(value: number): { readonly tag: "integer" | "real"; readonly text: string } {
  if (!Number.isFinite(value)) {
    throw malformedPlist("A plist number must be finite.");
  }

  if (Object.is(value, -0)) {
    return { tag: "real", text: "-0" };
  }

  if (Number.isInteger(value)) {
    if (!Number.isSafeInteger(value)) {
      throw malformedPlist("A plist integer must be a safe JavaScript integer.");
    }
    return { tag: "integer", text: String(value) };
  }

  return { tag: "real", text: String(value) };
}

function encodeValue(
  value: unknown,
  depth: number,
  writer: BoundedXmlWriter,
  limits: ResourceLimits,
  ancestors: WeakSet<object>
): void {
  assertDepth(depth, limits);
  const indentation = INDENT.repeat(depth);

  if (typeof value === "string") {
    assertStringWithinLimit(value, limits);
    writer.append(`${indentation}<string>${escapeXmlText(value)}</string>\n`);
    return;
  }

  if (typeof value === "number") {
    const number = formatNumber(value);
    writer.append(`${indentation}<${number.tag}>${number.text}</${number.tag}>\n`);
    return;
  }

  if (typeof value === "boolean") {
    writer.append(`${indentation}<${value ? "true" : "false"}/>\n`);
    return;
  }

  if (value instanceof Date) {
    writer.append(`${indentation}<date>${formatDate(value)}</date>\n`);
    return;
  }

  if (value instanceof Uint8Array) {
    const encoded = Buffer.from(value).toString("base64");
    if (!BASE64_PATTERN.test(encoded)) {
      throw malformedPlist("A plist data value could not be encoded.");
    }
    assertStringWithinLimit(encoded, limits);
    writer.append(`${indentation}<data>${encoded}</data>\n`);
    return;
  }

  if (typeof value !== "object" || value === null) {
    throw malformedPlist("A plist contains an unsupported value.");
  }

  if (ancestors.has(value)) {
    throw malformedPlist("A plist cannot contain cyclic data.");
  }
  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      if (value.length > limits.maxArrayItems) {
        throw limitExceeded("maxArrayItems", limits.maxArrayItems, value.length);
      }

      writer.append(`${indentation}<array>\n`);
      for (const item of value) {
        encodeValue(item, depth + 1, writer, limits, ancestors);
      }
      writer.append(`${indentation}</array>\n`);
      return;
    }

    assertPlainDictionary(value);
    const keys = dictionaryKeys(value, limits);
    writer.append(`${indentation}<dict>\n`);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw malformedPlist("A plist dictionary contains an invalid property.");
      }

      writer.append(`${INDENT.repeat(depth + 1)}<key>${escapeXmlText(key)}</key>\n`);
      encodeValue(descriptor.value as PlistValue, depth + 1, writer, limits, ancestors);
    }
    writer.append(`${indentation}</dict>\n`);
  } finally {
    ancestors.delete(value);
  }
}

export function encodePlist(value: PlistValue, limitsInput?: ResourceLimitsInput): Uint8Array {
  const limits = resolveLimits(limitsInput);
  const writer = new BoundedXmlWriter(limits);
  writer.append(PLIST_HEADER);
  encodeValue(value, 1, writer, limits, new WeakSet());
  writer.append(PLIST_FOOTER);
  return writer.toBytes();
}
