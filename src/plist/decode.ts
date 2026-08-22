import { Buffer } from "node:buffer";

import { XMLParser } from "fast-xml-parser";
import { SyntaxValidator } from "fast-xml-validator";

import { UdidToolsError } from "../errors.js";
import { resolveLimits, type ResourceLimits, type ResourceLimitsInput } from "../limits.js";
import type { PlistValue } from "../types.js";
import { BASE64_PATTERN, UNSAFE_DICTIONARY_KEYS } from "./constants.js";
import {
  assertDepth,
  assertStringWithinLimit,
  assertValidXmlText,
  limitExceeded,
  malformedPlist,
  utf8ByteLength,
} from "./shared.js";

type OrderedNode = Readonly<Record<string, unknown>>;

interface ElementNode {
  readonly attributes: Readonly<Record<string, unknown>> | undefined;
  readonly children: readonly unknown[];
  readonly name: string;
}

const XML_DECLARATION_PATTERN =
  /^\uFEFF?[\t\n\r ]*<\?xml[\t\n\r ]+version=(?:"1\.0"|'1\.0')(?:[\t\n\r ]+encoding=(?:"UTF-8"|'UTF-8'|"utf-8"|'utf-8'))?[\t\n\r ]*\?>/u;
const PLIST_DOCTYPE_PATTERN =
  /^[\t\n\r ]*<!DOCTYPE[\t\n\r ]+plist[\t\n\r ]+PUBLIC[\t\n\r ]+"-\/\/Apple\/\/DTD PLIST 1\.0\/\/EN"[\t\n\r ]+"http:\/\/www\.apple\.com\/DTDs\/PropertyList-1\.0\.dtd"[\t\n\r ]*>/u;
const INTEGER_PATTERN = /^[+-]?\d+$/u;
const REAL_PATTERN = /^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$/u;
const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/u;

function toXmlString(input: string | Uint8Array, limits: ResourceLimits): string {
  const inputBytes = typeof input === "string" ? utf8ByteLength(input) : input.byteLength;
  if (inputBytes > limits.maxInputBytes) {
    throw limitExceeded("maxInputBytes", limits.maxInputBytes, inputBytes);
  }

  if (typeof input === "string") {
    return input;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw malformedPlist("A plist must be valid UTF-8.");
  }
}

function removeSafeProlog(xml: string): string {
  let remaining = xml;
  const declaration = XML_DECLARATION_PATTERN.exec(remaining);
  if (declaration !== null) {
    remaining = remaining.slice(declaration[0].length);
  } else {
    remaining = remaining.replace(/^\uFEFF/u, "");
  }

  const doctype = PLIST_DOCTYPE_PATTERN.exec(remaining);
  if (doctype !== null) {
    remaining = remaining.slice(doctype[0].length);
  }

  // DTDs, custom entities, CDATA, comments, and processing instructions have no
  // place in a plist value. Rejecting them also removes XML expansion and XXE risk.
  if (remaining.includes("<!") || remaining.includes("<?")) {
    throw malformedPlist("A plist contains an unsupported XML declaration.");
  }

  return remaining;
}

function isOrderedNode(value: unknown): value is OrderedNode {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function attributesFrom(node: OrderedNode): Readonly<Record<string, unknown>> | undefined {
  const attributes = node[":@"];
  if (attributes === undefined) {
    return undefined;
  }
  if (!isOrderedNode(attributes)) {
    throw malformedPlist("A plist element contains malformed attributes.");
  }
  return attributes;
}

function asElement(value: unknown): ElementNode {
  if (!isOrderedNode(value)) {
    throw malformedPlist("A plist contains a malformed XML node.");
  }

  const keys = Object.keys(value).filter((key) => key !== ":@");
  if (keys.length !== 1) {
    throw malformedPlist("A plist contains a malformed XML node.");
  }

  const name = keys[0];
  if (name === undefined || name === "#text") {
    throw malformedPlist("A plist contains text where an element was required.");
  }

  const children = value[name];
  if (!Array.isArray(children)) {
    throw malformedPlist("A plist contains a malformed XML element.");
  }

  return { attributes: attributesFrom(value), children, name };
}

function textFromNode(value: unknown): string | undefined {
  if (!isOrderedNode(value)) {
    throw malformedPlist("A plist contains a malformed XML node.");
  }

  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== "#text") {
    return undefined;
  }

  const text = value["#text"];
  if (typeof text !== "string") {
    throw malformedPlist("A plist contains malformed text.");
  }
  return text;
}

function structuralChildren(children: readonly unknown[]): ElementNode[] {
  const elements: ElementNode[] = [];
  for (const child of children) {
    const text = textFromNode(child);
    if (text !== undefined) {
      if (text.trim().length !== 0) {
        throw malformedPlist("A plist collection contains unexpected text.");
      }
      continue;
    }
    elements.push(asElement(child));
  }
  return elements;
}

function assertNoAttributes(element: ElementNode): void {
  if (element.attributes !== undefined && Object.keys(element.attributes).length !== 0) {
    throw malformedPlist("Plist value elements cannot have attributes.");
  }
}

function elementText(element: ElementNode, limits: ResourceLimits): string {
  assertNoAttributes(element);
  let text = "";
  for (const child of element.children) {
    const part = textFromNode(child);
    if (part === undefined) {
      throw malformedPlist("A scalar plist value cannot contain child elements.");
    }
    text += part;
    assertStringWithinLimit(text, limits);
  }

  assertValidXmlText(text);
  return text;
}

function assertEmptyElement(element: ElementNode): void {
  assertNoAttributes(element);
  if (element.children.length !== 0) {
    throw malformedPlist("A boolean plist element must be empty.");
  }
}

function parseInteger(text: string): number {
  const normalized = text.trim();
  if (!INTEGER_PATTERN.test(normalized)) {
    throw malformedPlist("A plist integer is invalid.");
  }

  const value = Number(normalized);
  if (!Number.isSafeInteger(value)) {
    throw malformedPlist("A plist integer exceeds JavaScript's safe integer range.");
  }
  return value;
}

function parseReal(text: string): number {
  const normalized = text.trim();
  if (!REAL_PATTERN.test(normalized)) {
    throw malformedPlist("A plist real number is invalid.");
  }

  const value = Number(normalized);
  if (!Number.isFinite(value)) {
    throw malformedPlist("A plist real number must be finite.");
  }
  return value;
}

function parseDate(text: string): Date {
  const normalized = text.trim();
  const match = DATE_PATTERN.exec(normalized);
  if (match === null) {
    throw malformedPlist("A plist date must use an ISO 8601 UTC representation.");
  }

  const milliseconds = (match[7] ?? "").padEnd(3, "0");
  const [, year, month, day, hour, minute, second] = match;
  if (
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined
  ) {
    throw malformedPlist("A plist date is invalid.");
  }
  const canonical = `${year}-${month}-${day}T${hour}:${minute}:${second}.${milliseconds}Z`;
  const value = new Date(canonical);
  if (!Number.isFinite(value.getTime()) || value.toISOString() !== canonical) {
    throw malformedPlist("A plist date is invalid.");
  }
  return value;
}

function parseData(text: string): Uint8Array {
  const compact = text.replace(/[\t\n\r ]/gu, "");
  if (compact.length % 4 !== 0 || !BASE64_PATTERN.test(compact)) {
    throw malformedPlist("A plist data value is not valid base64.");
  }

  const value = Buffer.from(compact, "base64");
  if (value.toString("base64") !== compact) {
    throw malformedPlist("A plist data value is not canonical base64.");
  }
  return Uint8Array.from(value);
}

function parseArray(
  element: ElementNode,
  depth: number,
  limits: ResourceLimits
): readonly PlistValue[] {
  assertNoAttributes(element);
  const children = structuralChildren(element.children);
  if (children.length > limits.maxArrayItems) {
    throw limitExceeded("maxArrayItems", limits.maxArrayItems, children.length);
  }
  return children.map((child) => parseValue(child, depth + 1, limits));
}

function parseDictionary(
  element: ElementNode,
  depth: number,
  limits: ResourceLimits
): Readonly<Record<string, PlistValue>> {
  assertNoAttributes(element);
  const children = structuralChildren(element.children);
  if (children.length % 2 !== 0) {
    throw malformedPlist("A plist dictionary contains a key without a value.");
  }

  const keyCount = children.length / 2;
  if (keyCount > limits.maxDictionaryKeys) {
    throw limitExceeded("maxDictionaryKeys", limits.maxDictionaryKeys, keyCount);
  }

  const dictionary = Object.create(null) as Record<string, PlistValue>;
  for (let index = 0; index < children.length; index += 2) {
    const keyElement = children[index];
    const valueElement = children[index + 1];
    if (keyElement === undefined || valueElement === undefined || keyElement.name !== "key") {
      throw malformedPlist("A plist dictionary must alternate key and value elements.");
    }

    const key = elementText(keyElement, limits);
    if (UNSAFE_DICTIONARY_KEYS.has(key)) {
      throw malformedPlist("A plist dictionary contains an unsafe key.");
    }
    if (Object.hasOwn(dictionary, key)) {
      throw malformedPlist("A plist dictionary contains a duplicate key.");
    }

    dictionary[key] = parseValue(valueElement, depth + 1, limits);
  }
  return dictionary;
}

function parseValue(element: ElementNode, depth: number, limits: ResourceLimits): PlistValue {
  assertDepth(depth, limits);

  switch (element.name) {
    case "array":
      return parseArray(element, depth, limits);
    case "data":
      return parseData(elementText(element, limits));
    case "date":
      return parseDate(elementText(element, limits));
    case "dict":
      return parseDictionary(element, depth, limits);
    case "false":
      assertEmptyElement(element);
      return false;
    case "integer":
      return parseInteger(elementText(element, limits));
    case "real":
      return parseReal(elementText(element, limits));
    case "string":
      return elementText(element, limits);
    case "true":
      assertEmptyElement(element);
      return true;
    case "key":
      throw malformedPlist("A key element is only valid inside a dictionary.");
    default:
      throw malformedPlist("A plist contains an unsupported value element.");
  }
}

function parseDocument(parsed: unknown, limits: ResourceLimits): PlistValue {
  if (!Array.isArray(parsed)) {
    throw malformedPlist("A plist XML document is malformed.");
  }

  const roots = structuralChildren(parsed);
  if (roots.length !== 1 || roots[0]?.name !== "plist") {
    throw malformedPlist("A plist XML document must have exactly one plist root element.");
  }

  const root = roots[0];
  const attributes = root.attributes;
  if (
    attributes === undefined ||
    Object.keys(attributes).length !== 1 ||
    attributes["@_version"] !== "1.0"
  ) {
    throw malformedPlist('The plist root must declare version="1.0".');
  }

  const values = structuralChildren(root.children);
  if (values.length !== 1) {
    throw malformedPlist("A plist root must contain exactly one value.");
  }

  const value = values[0];
  if (value === undefined) {
    throw malformedPlist("A plist root must contain a value.");
  }
  return parseValue(value, 1, limits);
}

export function decodePlist(
  input: string | Uint8Array,
  limitsInput?: ResourceLimitsInput
): PlistValue {
  const limits = resolveLimits(limitsInput);
  const xml = removeSafeProlog(toXmlString(input, limits));
  assertValidXmlText(xml);

  try {
    SyntaxValidator.validate(xml, { allowBooleanAttributes: false });
  } catch {
    throw malformedPlist("A plist is not well-formed XML.");
  }

  try {
    const parser = new XMLParser({
      allowBooleanAttributes: false,
      alwaysCreateTextNode: false,
      // fast-xml-parser gates numeric character references with this option.
      // XMLValidator has already rejected non-XML named entities and all DTDs.
      htmlEntities: true,
      ignoreAttributes: false,
      ignoreDeclaration: true,
      maxNestedTags: limits.maxPlistDepth + 2,
      parseAttributeValue: false,
      parseTagValue: false,
      preserveOrder: true,
      processEntities: true,
      trimValues: false,
    });
    return parseDocument(parser.parse(xml) as unknown, limits);
  } catch (error) {
    if (error instanceof UdidToolsError) {
      throw error;
    }
    throw malformedPlist("A plist could not be parsed safely.");
  }
}
