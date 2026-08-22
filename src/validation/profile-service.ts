import { isIP } from "node:net";

import { UdidToolsError, type UdidToolsWarning } from "../errors.js";
import type { ResourceLimits } from "../limits.js";
import {
  KNOWN_DEVICE_ATTRIBUTES,
  type PlistValue,
  type ProfileServiceDefinition,
} from "../types.js";

const IDENTIFIER_PATTERN =
  /^(?=.{3,255}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RESERVED_SERVICE_KEYS = new Set(["Challenge", "DeviceAttributes", "URL"]);
const RESERVED_PROFILE_KEYS = new Set([
  "PayloadContent",
  "PayloadDescription",
  "PayloadDisplayName",
  "PayloadIdentifier",
  "PayloadOrganization",
  "PayloadType",
  "PayloadUUID",
  "PayloadVersion",
]);
const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const ATTRIBUTE_PATTERN = /^[A-Z][A-Z0-9_]*$/u;

export interface ValidatedProfileServiceDefinition {
  readonly definition: ProfileServiceDefinition;
  readonly responseUrl: URL;
  readonly warnings: readonly UdidToolsWarning[];
}

function assertString(
  value: unknown,
  name: string,
  limits: ResourceLimits
): asserts value is string {
  if (typeof value !== "string") {
    throw new UdidToolsError("INVALID_CONFIGURATION", `${name} must be a string.`, {
      details: { field: name },
    });
  }
  const byteLength = Buffer.byteLength(value, "utf8");
  if (value.trim().length === 0 || byteLength > limits.maxStringBytes) {
    throw new UdidToolsError(
      "INVALID_CONFIGURATION",
      `${name} must be a non-empty string within the configured size limit.`,
      { details: { field: name } }
    );
  }
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    return true;
  }

  const ipVersion = isIP(hostname);
  return ipVersion !== 0 && (hostname === "127.0.0.1" || hostname === "::1");
}

export function validateProfileServiceDefinition(
  definition: ProfileServiceDefinition,
  limits: ResourceLimits
): ValidatedProfileServiceDefinition {
  if (typeof definition !== "object" || definition === null) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "A profile definition is required.");
  }
  if (typeof definition.service !== "object" || definition.service === null) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "A Profile Service definition is required.");
  }

  assertString(definition.identifier, "profile.identifier", limits);
  if (!IDENTIFIER_PATTERN.test(definition.identifier)) {
    throw new UdidToolsError(
      "INVALID_PROFILE_IDENTIFIER",
      "The profile identifier must use reverse-DNS notation."
    );
  }

  assertString(definition.displayName, "profile.displayName", limits);
  if (definition.description !== undefined) {
    assertString(definition.description, "profile.description", limits);
  }
  if (definition.organization !== undefined) {
    assertString(definition.organization, "profile.organization", limits);
  }
  if (definition.uuid !== undefined && !UUID_PATTERN.test(definition.uuid)) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "The profile UUID is invalid.", {
      details: { field: "profile.uuid" },
    });
  }

  let responseUrl: URL;
  assertString(definition.service.responseUrl, "profile.service.responseUrl", limits);
  try {
    responseUrl = new URL(definition.service.responseUrl);
  } catch {
    throw new UdidToolsError(
      "INVALID_RESPONSE_URL",
      "The Profile Service response URL is invalid."
    );
  }

  if (responseUrl.protocol !== "https:" && responseUrl.protocol !== "http:") {
    throw new UdidToolsError(
      "INVALID_RESPONSE_URL",
      "The Profile Service response URL must use HTTP or HTTPS."
    );
  }
  if (responseUrl.username !== "" || responseUrl.password !== "" || responseUrl.hash !== "") {
    throw new UdidToolsError(
      "INVALID_RESPONSE_URL",
      "The Profile Service response URL must not contain credentials or a fragment."
    );
  }

  const warnings: UdidToolsWarning[] = [];
  if (responseUrl.protocol !== "https:" && !isLoopbackHostname(responseUrl.hostname)) {
    warnings.push({
      code: "INSECURE_RESPONSE_URL",
      message: "The Profile Service response URL does not use HTTPS.",
      details: { hostname: responseUrl.hostname },
    });
  }

  const { deviceAttributes } = definition.service;
  if (!Array.isArray(deviceAttributes)) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "Device attributes must be an array.");
  }
  if (deviceAttributes.length === 0 || deviceAttributes.length > limits.maxArrayItems) {
    throw new UdidToolsError(
      "INVALID_CONFIGURATION",
      "At least one device attribute is required and the configured array limit must not be exceeded.",
      { details: { field: "profile.service.deviceAttributes" } }
    );
  }

  const seenAttributes = new Set<string>();
  for (const attribute of deviceAttributes) {
    if (typeof attribute !== "string" || !ATTRIBUTE_PATTERN.test(attribute)) {
      throw new UdidToolsError("INVALID_CONFIGURATION", "A device attribute is invalid.");
    }
    if (seenAttributes.has(attribute)) {
      throw new UdidToolsError("INVALID_CONFIGURATION", "Device attributes must be unique.", {
        details: { attribute },
      });
    }
    seenAttributes.add(attribute);
  }

  const validateExtensions = (
    extensions: Readonly<Record<string, PlistValue>> | undefined,
    reservedKeys: ReadonlySet<string>,
    field: string
  ): void => {
    if (extensions === undefined) {
      return;
    }
    if (typeof extensions !== "object" || extensions === null || Array.isArray(extensions)) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Profile extensions must be a dictionary.",
        {
          details: { field },
        }
      );
    }
    const prototype = Object.getPrototypeOf(extensions) as unknown;
    if (prototype !== null && prototype !== Object.prototype) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Profile extensions must be a plain dictionary.",
        {
          details: { field },
        }
      );
    }
    if (Object.getOwnPropertySymbols(extensions).length !== 0) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "Profile extensions cannot use symbol keys.",
        {
          details: { field },
        }
      );
    }

    const keys = Object.getOwnPropertyNames(extensions);
    if (keys.length > limits.maxDictionaryKeys) {
      throw new UdidToolsError("INVALID_CONFIGURATION", "Too many Profile Service extensions.");
    }
    for (const key of keys) {
      if (reservedKeys.has(key) || UNSAFE_OBJECT_KEYS.has(key)) {
        throw new UdidToolsError(
          "INVALID_CONFIGURATION",
          "A Profile Service extension conflicts with a reserved key.",
          { details: { field, key } }
        );
      }
      const descriptor = Object.getOwnPropertyDescriptor(extensions, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new UdidToolsError(
          "INVALID_CONFIGURATION",
          "Profile extensions must contain only enumerable data properties.",
          { details: { field, key } }
        );
      }
    }
  };

  validateExtensions(definition.extensions, RESERVED_PROFILE_KEYS, "profile.extensions");
  validateExtensions(
    definition.service.extensions,
    RESERVED_SERVICE_KEYS,
    "profile.service.extensions"
  );

  const challenge = definition.service.challenge;
  if (challenge !== undefined) {
    if (typeof challenge !== "object" || challenge === null) {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "The Profile Service challenge is invalid."
      );
    }
    if (challenge.type === "string") {
      assertString(challenge.value, "profile.service.challenge.value", limits);
    } else if (challenge.type === "data") {
      if (!(challenge.value instanceof Uint8Array)) {
        throw new UdidToolsError("INVALID_CONFIGURATION", "A data challenge must be a Uint8Array.");
      }
      if (challenge.value.byteLength === 0 || challenge.value.byteLength > limits.maxStringBytes) {
        throw new UdidToolsError(
          "INVALID_CONFIGURATION",
          "The Profile Service challenge must be non-empty and within the configured size limit."
        );
      }
    } else {
      throw new UdidToolsError(
        "INVALID_CONFIGURATION",
        "The Profile Service challenge type is unsupported."
      );
    }
  }

  return { definition, responseUrl, warnings };
}

export function isKnownDeviceAttribute(value: string): boolean {
  return (KNOWN_DEVICE_ATTRIBUTES as readonly string[]).includes(value);
}
