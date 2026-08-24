import { describe, expect, it } from "vitest";
import fc from "fast-check";
import forge from "node-forge";

import { loadSigningMaterial } from "../../src/certificates/index.js";
import { inspectAndVerifyCms, signCms } from "../../src/cms/index.js";
import { resolveLimits } from "../../src/limits.js";
import { decodePlist, encodePlist } from "../../src/plist/index.js";
import {
  generateProfile,
  generateProfileOrThrow,
  parseProfileServiceResponse,
  parseProfileServiceResponseOrThrow,
  type ProfileGenerationOptions,
} from "../../src/index.js";
import {
  certificateDer,
  createPkcs12,
  createSyntheticIdentity,
} from "../helpers/synthetic-identity.js";

const FIXED_UUID = "B9E26D5B-31E9-4B21-A940-2F1743C1DD0E";
const CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
const SHA1_OID = "1.3.14.3.2.26";
const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";

function unsignedOptions(): ProfileGenerationOptions {
  return {
    profile: {
      kind: "profile-service",
      description: "Share selected device identifiers.",
      displayName: "Device Identification",
      extensions: { FutureTopLevelKey: "preserved" },
      identifier: "com.example.profile-service",
      organization: "Example Inc.",
      service: {
        challenge: { type: "string", value: "opaque-challenge" },
        deviceAttributes: ["UDID", "SERIAL", "PRODUCT", "VERSION"],
        extensions: { FutureServiceKey: 1 },
        responseUrl: "https://example.com/profile-response",
      },
      uuid: FIXED_UUID,
    },
  };
}

function createSignedResponse(options: { readonly sha1?: boolean } = {}): {
  readonly bytes: Uint8Array;
  readonly rootCertificate: Uint8Array;
} {
  const identity = createSyntheticIdentity();
  const pkcs12 = createPkcs12(
    identity.leafKeys.privateKey,
    [identity.leafCertificate, identity.rootCertificate],
    "test-passphrase"
  );
  const material = loadSigningMaterial(
    {
      identity: { data: pkcs12, passphrase: "test-passphrase", type: "pkcs12" },
    },
    resolveLimits(undefined)
  );
  const content = encodePlist({
    CHALLENGE: "opaque-challenge",
    FUTURE_ATTRIBUTE: "kept",
    PRODUCT: "iPhone17,1",
    SERIAL: "SERIAL123",
    UDID: "00008110-001234567890801E",
    VERSION: "18.0",
  });

  let bytes = signCms(content, material);
  if (options.sha1 === true) {
    const signedData = forge.pkcs7.createSignedData();
    signedData.content = forge.util.createBuffer(Buffer.from(content).toString("latin1"), "raw");
    signedData.addCertificate(identity.leafCertificate);
    signedData.addSigner({
      authenticatedAttributes: [
        { type: CONTENT_TYPE_OID, value: "1.2.840.113549.1.7.1" },
        { type: MESSAGE_DIGEST_OID },
        { type: SIGNING_TIME_OID },
      ],
      certificate: identity.leafCertificate,
      digestAlgorithm: SHA1_OID,
      key: identity.leafKeys.privateKey,
    });
    signedData.sign({ detached: false });
    bytes = Uint8Array.from(
      Buffer.from(forge.asn1.toDer(signedData.toAsn1()).getBytes(), "latin1")
    );
  }

  return {
    bytes,
    rootCertificate: certificateDer(identity.rootCertificate),
  };
}

describe("Profile Service generation", () => {
  it("generates a complete unsigned Profile Service plist", async () => {
    const result = await generateProfile(unsignedOptions());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.protection).toEqual({ encrypted: false, signed: false });
    expect(result.value.contentType).toBe("application/x-apple-aspen-config");
    const decoded = decodePlist(result.value.data);
    expect(decoded).toMatchObject({
      FutureTopLevelKey: "preserved",
      PayloadContent: {
        Challenge: "opaque-challenge",
        DeviceAttributes: ["UDID", "SERIAL", "PRODUCT", "VERSION"],
        FutureServiceKey: 1,
        URL: "https://example.com/profile-response",
      },
      PayloadIdentifier: "com.example.profile-service",
      PayloadType: "Profile Service",
      PayloadUUID: FIXED_UUID,
      PayloadVersion: 1,
    });
  });

  it("signs only when a complete nested signing configuration is present", async () => {
    const identity = createSyntheticIdentity();
    const pkcs12 = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate],
      "test-passphrase"
    );
    const result = await generateProfile({
      ...unsignedOptions(),
      signing: {
        certificateChain: [certificateDer(identity.rootCertificate)],
        identity: { data: pkcs12, passphrase: "test-passphrase", type: "pkcs12" },
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.protection.signed).toBe(true);
    const inspected = await inspectAndVerifyCms(
      result.value.data,
      { mode: "signature" },
      resolveLimits(undefined)
    );
    expect(inspected.signature.valid).toBe(true);
    expect(decodePlist(inspected.content)).toMatchObject({
      PayloadType: "Profile Service",
    });
  });

  it("fails closed for incomplete signing instead of silently returning XML", async () => {
    const invalid = {
      ...unsignedOptions(),
      signing: {},
    } as unknown as ProfileGenerationOptions;
    const result = await generateProfile(invalid);
    expect(result).toMatchObject({
      error: { code: "MISSING_SIGNING_MATERIAL" },
      ok: false,
    });
  });

  it("returns typed failures by default and throws only from OrThrow", async () => {
    const invalid = {
      ...unsignedOptions(),
      profile: { ...unsignedOptions().profile, identifier: "not-reverse-dns" },
    };
    await expect(generateProfile(invalid)).resolves.toMatchObject({
      error: { code: "INVALID_PROFILE_IDENTIFIER" },
      ok: false,
    });
    await expect(generateProfileOrThrow(invalid)).rejects.toMatchObject({
      code: "INVALID_PROFILE_IDENTIFIER",
    });
  });

  it("defensively validates JavaScript runtime shapes and extension descriptors", async () => {
    const accessorExtensions = {} as Record<string, unknown>;
    Object.defineProperty(accessorExtensions, "FutureKey", {
      enumerable: true,
      get(): never {
        throw new Error("must not be invoked");
      },
    });

    const invalidOptions: readonly ProfileGenerationOptions[] = [
      undefined as unknown as ProfileGenerationOptions,
      { profile: undefined } as unknown as ProfileGenerationOptions,
      {
        ...unsignedOptions(),
        profile: {
          ...unsignedOptions().profile,
          service: undefined,
        },
      } as unknown as ProfileGenerationOptions,
      {
        ...unsignedOptions(),
        profile: { ...unsignedOptions().profile, identifier: 42 },
      } as unknown as ProfileGenerationOptions,
      {
        ...unsignedOptions(),
        profile: {
          ...unsignedOptions().profile,
          service: {
            ...unsignedOptions().profile.service,
            responseUrl: "https://user:pass@example.com/callback#fragment",
          },
        },
      },
      {
        ...unsignedOptions(),
        profile: {
          ...unsignedOptions().profile,
          service: { ...unsignedOptions().profile.service, deviceAttributes: ["lowercase"] },
        },
      } as unknown as ProfileGenerationOptions,
      {
        ...unsignedOptions(),
        profile: {
          ...unsignedOptions().profile,
          extensions: accessorExtensions,
        },
      } as unknown as ProfileGenerationOptions,
      { ...unsignedOptions(), signing: null } as unknown as ProfileGenerationOptions,
      { ...unsignedOptions(), limits: { maxInputBytes: 0 } },
    ];

    for (const options of invalidOptions) {
      const result = await generateProfile(options);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(["INVALID_CONFIGURATION", "INVALID_RESPONSE_URL"]).toContain(result.error.code);
      }
    }
  });

  it("generates safe defaults and reports non-loopback HTTP response URLs", async () => {
    const sourceProfile = unsignedOptions().profile;
    const baseProfile = {
      kind: "profile-service" as const,
      displayName: sourceProfile.displayName,
      identifier: sourceProfile.identifier,
      service: {
        deviceAttributes: sourceProfile.service.deviceAttributes,
        responseUrl: "http://profiles.example.test/callback",
      },
    };
    const result = await generateProfile({ profile: baseProfile });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.profile.uuid).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
    );
    expect(result.warnings).toContainEqual(
      expect.objectContaining({ code: "INSECURE_RESPONSE_URL" })
    );
    expect(decodePlist(result.value.data)).not.toHaveProperty("PayloadDescription");

    const loopback = await generateProfile({
      profile: {
        ...baseProfile,
        service: { ...baseProfile.service, responseUrl: "http://api.localhost/callback" },
      },
    });
    expect(loopback).toMatchObject({ ok: true, warnings: [] });
  });

  it("rejects malformed profile definitions across every public validation boundary", async () => {
    const nonPlainExtensions = Object.create({ inherited: true }) as Record<string, string>;
    nonPlainExtensions["FutureKey"] = "value";
    const symbolExtensions = { FutureKey: "value" } as Record<string | symbol, string>;
    symbolExtensions[Symbol("hidden")] = "value";
    const nonEnumerableExtensions = {} as Record<string, string>;
    Object.defineProperty(nonEnumerableExtensions, "FutureKey", {
      enumerable: false,
      value: "value",
    });

    const profile = unsignedOptions().profile;
    const invalidOptions: readonly ProfileGenerationOptions[] = [
      { profile: { ...profile, kind: "mdm" } } as unknown as ProfileGenerationOptions,
      { profile: { ...profile, service: null } } as unknown as ProfileGenerationOptions,
      { profile: { ...profile, displayName: 1 } } as unknown as ProfileGenerationOptions,
      { profile: { ...profile, description: "" } },
      { profile: { ...profile, organization: 1 } } as unknown as ProfileGenerationOptions,
      { profile: { ...profile, uuid: "not-a-uuid" } },
      {
        profile: {
          ...profile,
          service: { ...profile.service, responseUrl: "not a URL" },
        },
      },
      {
        profile: {
          ...profile,
          service: { ...profile.service, responseUrl: "ftp://example.test/callback" },
        },
      },
      {
        profile: {
          ...profile,
          service: { ...profile.service, deviceAttributes: "UDID" },
        },
      } as unknown as ProfileGenerationOptions,
      {
        profile: { ...profile, service: { ...profile.service, deviceAttributes: [] } },
      },
      {
        limits: { maxArrayItems: 1 },
        profile: {
          ...profile,
          service: { ...profile.service, deviceAttributes: ["UDID", "SERIAL"] },
        },
      },
      {
        profile: {
          ...profile,
          service: { ...profile.service, deviceAttributes: [42] },
        },
      } as unknown as ProfileGenerationOptions,
      {
        profile: {
          ...profile,
          service: { ...profile.service, deviceAttributes: ["UDID", "UDID"] },
        },
      },
      { profile: { ...profile, extensions: [] } } as unknown as ProfileGenerationOptions,
      { profile: { ...profile, extensions: nonPlainExtensions } },
      {
        profile: { ...profile, extensions: symbolExtensions },
      },
      {
        limits: { maxDictionaryKeys: 1 },
        profile: { ...profile, extensions: { FutureA: 1, FutureB: 2 } },
      },
      { profile: { ...profile, extensions: { PayloadType: "override" } } },
      { profile: { ...profile, extensions: { constructor: "override" } } },
      { profile: { ...profile, extensions: nonEnumerableExtensions } },
      {
        profile: {
          ...profile,
          service: { ...profile.service, extensions: { URL: "override" } },
        },
      },
      {
        profile: {
          ...profile,
          service: { ...profile.service, challenge: "challenge" },
        },
      } as unknown as ProfileGenerationOptions,
      {
        profile: {
          ...profile,
          service: { ...profile.service, challenge: { type: "string", value: "" } },
        },
      },
      {
        profile: {
          ...profile,
          service: { ...profile.service, challenge: { type: "data", value: "AQID" } },
        },
      } as unknown as ProfileGenerationOptions,
      {
        profile: {
          ...profile,
          service: {
            ...profile.service,
            challenge: { type: "data", value: new Uint8Array() },
          },
        },
      },
      {
        profile: {
          ...profile,
          service: { ...profile.service, challenge: { type: "number", value: 1 } },
        },
      } as unknown as ProfileGenerationOptions,
    ];

    for (const options of invalidOptions) {
      await expect(generateProfile(options)).resolves.toMatchObject({ ok: false });
    }
  });

  it("enforces output limits before and after CMS signing", async () => {
    await expect(
      generateProfile({ ...unsignedOptions(), limits: { maxOutputBytes: 64 } })
    ).resolves.toMatchObject({ error: { code: "OUTPUT_TOO_LARGE" }, ok: false });

    const baseline = await generateProfile(unsignedOptions());
    expect(baseline.ok).toBe(true);
    if (!baseline.ok) {
      return;
    }
    const identity = createSyntheticIdentity();
    const pkcs12 = createPkcs12(
      identity.leafKeys.privateKey,
      [identity.leafCertificate],
      "test-passphrase"
    );
    await expect(
      generateProfile({
        ...unsignedOptions(),
        limits: { maxOutputBytes: baseline.value.data.byteLength + 64 },
        signing: {
          identity: { data: pkcs12, passphrase: "test-passphrase", type: "pkcs12" },
        },
      })
    ).resolves.toMatchObject({ error: { code: "OUTPUT_TOO_LARGE" }, ok: false });
  });
});

describe("Profile Service response parsing", () => {
  it("rejects unsigned responses by default and can opt in explicitly", async () => {
    const bytes = encodePlist({
      "BAD\nFIELD": "sanitized-warning-name",
      CHALLENGE: new Uint8Array([1, 2, 3]),
      FUTURE_ATTRIBUTE: "kept",
      UDID: "device-id",
    });
    await expect(parseProfileServiceResponse(bytes)).resolves.toMatchObject({
      error: { code: "MALFORMED_CMS" },
      ok: false,
    });

    const result = await parseProfileServiceResponse(bytes, {
      allowUnsigned: true,
      expectedAttributes: ["UDID", "SERIAL"],
      expectedChallenge: { type: "data", value: new Uint8Array([1, 2, 3]) },
      requiredAttributes: ["UDID"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.attributes.udid).toBe("device-id");
    expect(result.value.raw["FUTURE_ATTRIBUTE"]).toBe("kept");
    expect(result.value.signature).toEqual({
      present: false,
      signers: [],
      trusted: null,
      valid: null,
    });
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "OPTIONAL_ATTRIBUTE_MISSING" }),
        expect.objectContaining({ code: "UNKNOWN_RESPONSE_ATTRIBUTE" }),
      ])
    );
    expect(result.warnings).toContainEqual(
      expect.objectContaining({
        code: "UNKNOWN_RESPONSE_ATTRIBUTE",
        details: { attribute: "BAD?FIELD" },
      })
    );
  });

  it("verifies a signed response and preserves unknown Apple fields", async () => {
    const signed = createSignedResponse();
    const result = await parseProfileServiceResponse(signed.bytes, {
      expectedChallenge: { type: "string", value: "opaque-challenge" },
      requiredAttributes: ["UDID", "SERIAL"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.attributes).toMatchObject({
      product: "iPhone17,1",
      serialNumber: "SERIAL123",
      udid: "00008110-001234567890801E",
      version: "18.0",
    });
    expect(result.value.raw["FUTURE_ATTRIBUTE"]).toBe("kept");
    expect(result.value.signature.valid).toBe(true);
    expect(result.value.signature.trusted).toBeNull();
    expect(result.warnings).toContainEqual(
      expect.objectContaining({ code: "SIGNER_TRUST_NOT_CHECKED" })
    );
  });

  it("verifies an RSA/SHA-1 response from an Apple Profile Service client", async () => {
    const signed = createSignedResponse({ sha1: true });
    const result = await parseProfileServiceResponse(signed.bytes, {
      requiredAttributes: ["UDID"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.attributes.udid).toBe("00008110-001234567890801E");
    expect(result.value.signature.valid).toBe(true);
  });

  it("validates trust only against caller-provided anchors", async () => {
    const signed = createSignedResponse();
    const result = await parseProfileServiceResponse(signed.bytes, {
      verification: {
        mode: "trust-chain",
        trustAnchors: [signed.rootCertificate],
      },
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.signature).toMatchObject({ trusted: true, valid: true });
    }
  });

  it("preserves trust-chain verification for RSA/SHA-1", async () => {
    const signed = createSignedResponse({ sha1: true });
    const result = await parseProfileServiceResponse(signed.bytes, {
      verification: {
        mode: "trust-chain",
        trustAnchors: [signed.rootCertificate],
      },
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.signature).toMatchObject({ trusted: true, valid: true });
    }
  });

  it("fails on missing or mismatched correlation data", async () => {
    const withChallenge = encodePlist({ CHALLENGE: "actual", UDID: "device-id" });
    await expect(
      parseProfileServiceResponse(withChallenge, {
        allowUnsigned: true,
        expectedChallenge: { type: "string", value: "expected" },
      })
    ).resolves.toMatchObject({ error: { code: "CHALLENGE_MISMATCH" }, ok: false });

    await expect(
      parseProfileServiceResponse(encodePlist({ UDID: "device-id" }), {
        allowUnsigned: true,
        expectedChallenge: { type: "string", value: "expected" },
      })
    ).resolves.toMatchObject({ error: { code: "MISSING_CHALLENGE" }, ok: false });

    await expect(
      parseProfileServiceResponse(encodePlist({ UDID: "device-id" }), {
        allowUnsigned: true,
        requiredAttributes: ["SERIAL"],
      })
    ).resolves.toMatchObject({
      error: { code: "MISSING_REQUIRED_ATTRIBUTE" },
      ok: false,
    });
  });

  it("never rejects the safe parser promise for arbitrary bounded bytes", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 256 }), async (input) => {
        const result = await parseProfileServiceResponse(input);
        expect(typeof result.ok).toBe("boolean");
      }),
      { numRuns: 100 }
    );
  });

  it("rejects invalid parser policies as typed configuration failures", async () => {
    const body = encodePlist({ UDID: "device-id" });
    const invalidPolicies = [
      null,
      { allowUnsigned: "yes" },
      { allowUnsigned: true, expectedAttributes: ["UDID", "UDID"] },
      { allowUnsigned: true, requiredAttributes: ["UNKNOWN"] },
      { allowUnsigned: true, expectedChallenge: { type: "string", value: "" } },
      { verification: { mode: "unknown" } },
      { verification: { mode: "trust-chain", trustAnchors: "root" } },
      { verification: { mode: "trust-chain", trustAnchors: [], intermediates: "chain" } },
      { expectedAttributes: "UDID" },
      { expectedAttributes: [1] },
      { expectedChallenge: "challenge" },
      { expectedChallenge: { type: "string", value: 1 } },
      { expectedChallenge: { type: "data", value: "AQID" } },
      { expectedChallenge: { type: "data", value: new Uint8Array() } },
      { expectedChallenge: { type: "unsupported", value: "value" } },
      { verification: {} },
    ] as const;

    for (const policy of invalidPolicies) {
      const result = await parseProfileServiceResponse(
        body,
        policy as unknown as Parameters<typeof parseProfileServiceResponse>[1]
      );
      expect(result).toMatchObject({ error: { code: "INVALID_CONFIGURATION" }, ok: false });
    }
  });

  it("keeps throwing behavior explicit", async () => {
    await expect(
      parseProfileServiceResponseOrThrow(new Uint8Array([0, 1, 2]))
    ).rejects.toMatchObject({ code: "MALFORMED_CMS" });
  });

  it("accepts string and ArrayBuffer inputs and normalizes every documented attribute", async () => {
    const bytes = encodePlist({
      ICCID: "iccid",
      IMEI: "imei",
      MAC_ADDRESS_EN0: "00:11:22:33:44:55",
      MEID: "meid",
      PRODUCT: "iPhone17,1",
      SERIAL: "serial",
      UDID: "udid",
      VERSION: "18.0",
    });
    const textResult = await parseProfileServiceResponse(new TextDecoder().decode(bytes), {
      allowUnsigned: true,
    });
    expect(textResult).toMatchObject({
      ok: true,
      value: {
        attributes: {
          iccid: "iccid",
          imei: "imei",
          macAddressEn0: "00:11:22:33:44:55",
          meid: "meid",
          product: "iPhone17,1",
          serialNumber: "serial",
          udid: "udid",
          version: "18.0",
        },
      },
    });

    const copiedBuffer = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(copiedBuffer).set(bytes);
    await expect(
      parseProfileServiceResponse(copiedBuffer, { allowUnsigned: true })
    ).resolves.toMatchObject({ ok: true });
  });

  it("rejects malformed response values and enforces its input boundary", async () => {
    const malformedBodies = [
      encodePlist("not-a-dictionary"),
      encodePlist(["not-a-dictionary"]),
      encodePlist({ CHALLENGE: 1 }),
      encodePlist({ UDID: 1 }),
    ];
    for (const body of malformedBodies) {
      await expect(
        parseProfileServiceResponse(body, { allowUnsigned: true })
      ).resolves.toMatchObject({ error: { code: "MALFORMED_PLIST" }, ok: false });
    }

    await expect(parseProfileServiceResponse(42 as unknown as Uint8Array)).resolves.toMatchObject({
      error: { code: "MALFORMED_CMS" },
      ok: false,
    });
    await expect(
      parseProfileServiceResponse(encodePlist({ UDID: "device" }), {
        allowUnsigned: true,
        limits: { maxInputBytes: 8 },
      })
    ).resolves.toMatchObject({ error: { code: "INPUT_TOO_LARGE" }, ok: false });
  });

  it("treats challenge type differences as correlation failures", async () => {
    await expect(
      parseProfileServiceResponse(encodePlist({ CHALLENGE: new Uint8Array([1]) }), {
        allowUnsigned: true,
        expectedChallenge: { type: "string", value: "1" },
      })
    ).resolves.toMatchObject({ error: { code: "CHALLENGE_MISMATCH" }, ok: false });
    await expect(
      parseProfileServiceResponse(encodePlist({ CHALLENGE: "1" }), {
        allowUnsigned: true,
        expectedChallenge: { type: "data", value: new Uint8Array([1]) },
      })
    ).resolves.toMatchObject({ error: { code: "CHALLENGE_MISMATCH" }, ok: false });
  });

  it("supports explicit CMS inspection without signature verification", async () => {
    const signed = createSignedResponse();
    const result = await parseProfileServiceResponse(signed.bytes, {
      verification: { mode: "none" },
    });
    expect(result).toMatchObject({
      ok: true,
      value: { signature: { present: true, trusted: null, valid: null } },
    });
  });

  it("caps unknown attribute names before returning warning metadata", async () => {
    const longName = "A".repeat(160);
    const result = await parseProfileServiceResponse(encodePlist({ [longName]: "value" }), {
      allowUnsigned: true,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.warnings[0]?.details?.["attribute"]).toBe(`${"A".repeat(128)}…`);
    }
  });
});
