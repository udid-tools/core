---
title: Public API
description: Stable entry points and configuration shapes.
---

## Operations

```ts
generateProfile(options): Promise<Result<GeneratedProfile>>
generateProfileOrThrow(options): Promise<GeneratedProfile>

parseProfileServiceResponse(input, options?): Promise<Result<ProfileServiceResponse>>
parseProfileServiceResponseOrThrow(input, options?): Promise<ProfileServiceResponse>

customDeviceAttribute(value): CustomDeviceAttribute
```

The package exports all configuration, result, error, warning, limit, plist, certificate, and response types from `@udid-tools/core`. Internal plist/CMS helpers are intentionally not public in the beta.

## Binary input

Certificates and PKCS#12 identities accept `Uint8Array` or an explicit encoded object:

```ts
type BinaryInput = Uint8Array | { encoding: "base64" | "pem"; value: string };
```

PEM labels are allow-listed for the target input. Base64 must be canonical. Inputs are defensively copied.

## Generated output

`GeneratedProfile` includes:

- `data`: XML or DER bytes;
- `contentType`: `application/x-apple-aspen-config`;
- `protection.signed`: which format was returned;
- `profile.identifier`, `profile.uuid`, and discriminant `profile.kind`.

## Parsed response

`ProfileServiceResponse` includes normalized `attributes`, optional string/data `challenge`, lossless `raw`, and signature metadata. Signer metadata contains sanitized subject/issuer display strings, serial number, validity dates, and a SHA-256 fingerprint. `signature.valid` and `trusted` are independent `boolean | null` states; this parser fails rather than returning `false` for a bad signature or trust chain. Use verification policy—not display strings—for authorization.

Run `npm run docs:api` to generate the complete declaration reference from source comments.
