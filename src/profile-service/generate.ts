import { randomUUID } from "node:crypto";

import { loadSigningMaterial } from "../certificates/index.js";
import { signCms } from "../cms/index.js";
import { UdidToolsError, type UdidToolsWarning } from "../errors.js";
import { resolveLimits } from "../limits.js";
import { encodePlist } from "../plist/index.js";
import { failure, success, unwrapResult, type Result } from "../result.js";
import type { GeneratedProfile, PlistValue, ProfileGenerationOptions } from "../types.js";
import { validateProfileServiceDefinition } from "../validation/profile-service.js";

const CONTENT_TYPE = "application/x-apple-aspen-config" as const;

function assignExtensions(
  target: Record<string, PlistValue>,
  extensions: Readonly<Record<string, PlistValue>>
): void {
  for (const key of Object.getOwnPropertyNames(extensions)) {
    const descriptor = Object.getOwnPropertyDescriptor(extensions, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new UdidToolsError("INVALID_CONFIGURATION", "A profile extension is invalid.");
    }
    target[key] = descriptor.value as PlistValue;
  }
}

function createPayload(
  options: ProfileGenerationOptions,
  uuid: string
): Readonly<Record<string, PlistValue>> {
  const profile = options.profile;
  const serviceContent: Record<string, PlistValue> = Object.create(null) as Record<
    string,
    PlistValue
  >;

  serviceContent["URL"] = profile.service.responseUrl;
  serviceContent["DeviceAttributes"] = [...profile.service.deviceAttributes];

  if (profile.service.challenge !== undefined) {
    serviceContent["Challenge"] = profile.service.challenge.value;
  }
  if (profile.service.extensions !== undefined) {
    assignExtensions(serviceContent, profile.service.extensions);
  }

  const payload: Record<string, PlistValue> = Object.create(null) as Record<string, PlistValue>;
  payload["PayloadContent"] = serviceContent;
  payload["PayloadDisplayName"] = profile.displayName;
  payload["PayloadIdentifier"] = profile.identifier;
  payload["PayloadType"] = "Profile Service";
  payload["PayloadUUID"] = uuid;
  payload["PayloadVersion"] = 1;

  if (profile.extensions !== undefined) {
    assignExtensions(payload, profile.extensions);
  }

  if (profile.description !== undefined) {
    payload["PayloadDescription"] = profile.description;
  }
  if (profile.organization !== undefined) {
    payload["PayloadOrganization"] = profile.organization;
  }

  return payload;
}

function generate(options: ProfileGenerationOptions): {
  readonly profile: GeneratedProfile;
  readonly warnings: readonly UdidToolsWarning[];
} {
  if (typeof options !== "object" || options === null) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "Generation options are required.");
  }
  if (typeof options.profile !== "object" || options.profile === null) {
    throw new UdidToolsError("INVALID_CONFIGURATION", "A profile definition is required.");
  }
  if (options.profile.kind !== "profile-service") {
    throw new UdidToolsError("INVALID_CONFIGURATION", "Unsupported profile kind.");
  }

  const limits = resolveLimits(options.limits);
  const validated = validateProfileServiceDefinition(options.profile, limits);
  const uuid = options.profile.uuid ?? randomUUID();
  const unsignedProfile = encodePlist(createPayload(options, uuid), limits);

  if (unsignedProfile.byteLength > limits.maxOutputBytes) {
    throw new UdidToolsError("OUTPUT_TOO_LARGE", "The generated profile exceeds the output limit.");
  }

  const warnings = [...validated.warnings];
  let data = unsignedProfile;
  let signed = false;

  if (options.signing !== undefined) {
    if (typeof options.signing !== "object" || options.signing === null) {
      throw new UdidToolsError("INVALID_CONFIGURATION", "Signing options must be an object.");
    }
    const material = loadSigningMaterial(options.signing, limits);
    warnings.push(...material.warnings);
    data = signCms(unsignedProfile, material, options.signing.digestAlgorithm ?? "sha256");
    signed = true;
  }

  if (data.byteLength > limits.maxOutputBytes) {
    throw new UdidToolsError("OUTPUT_TOO_LARGE", "The generated profile exceeds the output limit.");
  }

  return {
    profile: {
      contentType: CONTENT_TYPE,
      data,
      profile: { identifier: options.profile.identifier, kind: "profile-service", uuid },
      protection: { encrypted: false, signed },
    },
    warnings,
  };
}

/** Generate unsigned XML or signed CMS profile bytes without throwing. */
export async function generateProfile(
  options: ProfileGenerationOptions
): Promise<Result<GeneratedProfile>> {
  try {
    const generated = generate(options);
    return success(generated.profile, generated.warnings);
  } catch (error) {
    return failure(error);
  }
}

/** Generate a profile and throw {@link UdidToolsError} on failure. */
export async function generateProfileOrThrow(
  options: ProfileGenerationOptions
): Promise<GeneratedProfile> {
  return unwrapResult(await generateProfile(options));
}
