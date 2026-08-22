# AGENTS.md

This file is the durable engineering context for humans and coding agents working on `@udid-tools/core`.

## Product intent

Build a small, framework-agnostic, server-side TypeScript core for Apple Profile Service profile generation, optional signing, CMS response verification, and lossless response parsing. The current release target is `0.1.0-beta.1` under the npm scope `@udid-tools`.

MDM is a separate product boundary. Do not add MDM enrollment, APNs, check-in, commands, declarative management, SCEP orchestration, profile delivery state machines, HTTP servers, persistence, or UI code here. A future MDM package may reuse stable low-level primitives without changing this package’s Profile Service contract.

## Non-negotiable runtime contracts

1. Runtime source is Node.js TypeScript and ESM-only.
2. The package must not read environment variables, files, network resources, system trust stores, or global application configuration.
3. The package must not log, emit telemetry, mutate global crypto configuration, or retain secret material in module-level state.
4. Signing is configured only through a nested `signing` object. It is never a boolean.
5. Missing `signing` means unsigned XML. Present but incomplete or invalid `signing` fails closed; never silently downgrade to unsigned output.
6. Use only certificates, keys, intermediates, and trust anchors supplied by the caller. Never download Apple chains or silently add anchors.
7. Safe public functions return `Promise<Result<T>>` and must not reject because of malformed external input or an internal dependency exception. Throwing variants must end in `OrThrow`.
8. Public errors use stable machine-readable codes and sanitized details. Never include input bytes, private keys, passphrases, challenges, or environment values.
9. Unknown Apple fields must remain available losslessly. Additive Apple changes should not require a major release.
10. Every parser and encoder must enforce bounded resource usage before expensive work.

## Beta cryptographic scope

- Input identity: PKCS#12/PFX.
- Signing key: RSA.
- Digest: SHA-256.
- Output: DER-encoded attached CMS/PKCS#7 SignedData.
- Chain: optional and caller-provided.
- Response verification: `none`, `signature`, or `trust-chain` with caller-provided roots/intermediates.
- No revocation network lookups, certificate downloads, OS trust store, profile encryption, detached content, or alternative signing algorithms in this beta.

New algorithms require an approved issue using the algorithm-request template, threat analysis, test vectors, interoperability tests, documentation, and an ADR. Prefer adding a new discriminated identity/provider variant over changing existing fields.

## Source boundaries

- `src/profile-service/`: public use-case orchestration only.
- `src/validation/`: runtime configuration validation and compatibility checks.
- `src/plist/`: strict bounded XML plist codec; no business logic.
- `src/certificates/`: binary input and PKCS#12/X.509 material loading.
- `src/cms/`: CMS signing, inspection, integrity verification, and explicit trust-chain validation.
- `src/types.ts`: public discriminated contracts and lossless plist value types.
- `src/errors.ts`, `src/result.ts`, `src/limits.ts`: cross-cutting stable safety contract.
- `src/index.ts`: the only public package entry point. Internal helpers stay unexported unless deliberately promoted.
- `tests/`: unit, security, property, and integration coverage.
- `docs/src/content/docs/`: Starlight user documentation.
- `docs/decisions/`: accepted architecture decisions.

Dependencies point inward toward shared types/errors/limits. Profile orchestration may use plist/certificate/CMS modules; those lower layers must not import Profile Service orchestration.

## API evolution

- Follow semantic versioning, including during beta.
- Prefer additive optional fields and discriminated unions.
- Do not repurpose an existing field, error code, or warning code.
- Keep defaults secure and stable. New permissive behavior must be opt-in.
- Preserve `raw` response data even when adding a new normalized property.
- Deprecate before removal and document migration paths. Stable-line removals wait for the next major release.
- Keep generation async at the public boundary so future signing providers do not require a return-type break.

## Apple compatibility policy

Use primary Apple documentation as the normative source. Record the source URL and access date in documentation when adding a field. The archived OTA Profile Service guide documents the special `Profile Service` payload and signed device response; current Device Management profile docs cover shared configuration-profile keys. Do not infer MDM behavior into Profile Service.

Document observed but nonnormative behavior separately. Use branded custom attributes or extension dictionaries for forward compatibility. Never claim Apple endorsement.

## Security review checklist

- Validate runtime values even when TypeScript says they are valid.
- Enforce byte/count/depth limits before XML, ASN.1, PKCS#12, certificate, or signature work.
- Treat response bodies and certificate containers as hostile.
- Reject duplicate or unsafe dictionary keys and nonplain/accessor objects.
- Avoid algorithm negotiation from untrusted data; allow-list supported OIDs.
- Verify every CMS signer and require attached content.
- Distinguish signature integrity from signer trust in types and documentation.
- Require explicit roots for trust-chain mode and remain offline.
- Compare expected challenges without placing values in logs/errors.
- Keep dependency versions exact and review transitive changes before lockfile updates.

## Required verification

Use the active Node.js version required by `package.json` and run:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run verify
npm audit --audit-level=high
npm audit signatures
```

Tests must cover success, expected failures, hostile inputs, boundary limits, and public safe/throwing behavior. Coverage thresholds are repository policy, not a substitute for security cases. Generated profiles and CMS must be inspected structurally, not only snapshot-tested.

Before release, inspect `npm pack --dry-run`, the real tarball contents, package exports, provenance workflow, checksum, SBOM, and consumer installation smoke test. Never commit real certificates, passphrases, environment files, production device identifiers, or generated secret fixtures.

## Documentation and release rules

README gives the shortest safe path; the Starlight site contains complete guides, API reference, capability matrix, security model, and Apple references. Update docs and examples in the same change as public behavior. Run the docs build with warnings treated as defects.

Release automation publishes one verified tarball to npm and GitHub Packages. npm uses trusted publishing/OIDC and provenance; GitHub Packages uses the repository token. Prereleases use the `beta` dist-tag. Never publish from an unreviewed local working tree.

## Repository hygiene

- Do not commit directly generated secrets, `.env` files, `node_modules`, coverage, docs build output, or package tarballs.
- Do not weaken pinned GitHub Action SHAs, lockfile integrity, dependency review, CodeQL, or release attestations to make a check pass.
- Use conventional, focused changes and update `CHANGELOG.md` for user-visible behavior.
- Do not commit, push, tag, or publish unless the repository owner explicitly requests it.
