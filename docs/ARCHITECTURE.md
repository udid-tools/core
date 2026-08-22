# Architecture

`@udid-tools/core` is a dependency-light, framework-agnostic Node.js library. Its architecture keeps protocol modeling, untrusted data parsing, and cryptographic policy separate so each can evolve without changing the main developer workflow.

## System boundary

```text
Application-owned HTTP / secrets / storage / policy
                         │
                         ▼
          generateProfile / parseProfileServiceResponse
                  │                    │
          validation + types       limits + types
                  │                    │
                  ▼                    ▼
              plist codec ◄──── CMS inspection / verification
                  │                    ▲
                  └──── CMS signing ───┘
                           ▲
                  PKCS#12 / certificates
```

The application owns transport, authentication, authorization, one-time challenge issuance and storage, secret loading, rate limiting, persistence, observability, and business decisions. The package owns deterministic serialization, signing material validation, CMS construction/verification, response normalization, and typed failure reporting.

## Public façade

Only `src/index.ts` is exported. The initial use cases are:

- `generateProfile(options)` and `generateProfileOrThrow(options)`
- `parseProfileServiceResponse(input, options)` and `parseProfileServiceResponseOrThrow(input, options)`
- `customDeviceAttribute(value)` for deliberate forward-compatible attribute names

The profile definition is discriminated by `kind: "profile-service"`. Future profile families can add new variants without repurposing the current fields. `signing` is an optional nested object; its presence selects signed output and incomplete input is an error.

## Layers

### Profile Service

Builds the Apple `Profile Service` property list and normalizes a returned device dictionary. It has no HTTP concerns. Known attributes become camel-cased properties while the original dictionary remains in `raw`.

### Plist codec

Supports XML plist dictionaries, arrays, strings, safe integers/reals, booleans, dates, and data. Encoding is deterministic. Decoding rejects active XML features, malformed or duplicate keys, invalid scalar representations, and resource-limit violations.

### Certificate material

Decodes strict binary inputs, loads PKCS#12, identifies the signer by matching its RSA public key to the private key, rejects ambiguous/missing identities, validates current certificate timing, and combines only caller-provided certificates.

### CMS

Produces DER attached SignedData with authenticated content-type, message-digest, and signing-time attributes. Response inspection requires attached content and embedded signer certificates, allow-lists RSA/SHA-256 in the beta, verifies all signers, and performs offline path validation only when explicit roots are provided.

### Cross-cutting safety

`Result`, typed errors/warnings, and resource limits are shared primitives. Safe entry points convert third-party dependency exceptions to sanitized `INTERNAL_ERROR` failures. Throwing behavior is opt-in and clearly named.

## Compatibility strategy

- Optional fields and discriminated unions make capabilities additive.
- `extensions` at profile and service-content levels carry future Apple plist fields while preventing reserved-key overrides.
- `raw` preserves unknown response keys and plist value types.
- Stable error/warning codes are machine-readable; messages may improve without requiring consumer branching changes.
- Secure defaults remain stable: unsigned response parsing is denied, signatures are verified, trust is reported separately, and no hidden trust material is introduced.

## Runtime and packaging

- Node.js `>=22.14.0`
- ESM-only, strict TypeScript declarations and source maps
- exact production dependencies and lockfile
- no install scripts and `sideEffects: false`
- a single public export path
- npm and GitHub Packages receive the same attested tarball

## Decisions

Accepted architectural decisions live in [`docs/decisions`](./decisions/):

1. [Package boundary and MDM exclusion](./decisions/0001-package-boundary.md)
2. [Result-first public API](./decisions/0002-result-first-api.md)
3. [Explicit signing and trust material](./decisions/0003-explicit-crypto-material.md)
4. [Beta cryptographic profile](./decisions/0004-beta-crypto-profile.md)
5. [Lossless Apple compatibility](./decisions/0005-lossless-compatibility.md)
6. [Reproducible dual-registry release](./decisions/0006-release-supply-chain.md)
