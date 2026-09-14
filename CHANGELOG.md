# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project follows [Semantic
Versioning]. Prereleases use npm's `beta` distribution tag.

## [Unreleased]

## [0.1.0-beta.4] - 2026-09-14

### Changed

- Refreshed the verified documentation toolchain with Astro 7.3.2,
  `typedoc-plugin-frontmatter` 1.3.2, and `typescript-eslint` 8.70.0. The runtime API and runtime
  dependencies are unchanged from `0.1.0-beta.3`.

### Security

- Updated the pinned CodeQL Action to 4.38.0 and its default CodeQL bundle to 2.27.0.
- Adopted Astro 7.3.2's stricter escaping for dynamic MDX `<script>` and `<style>` content.

## [0.1.0-beta.3] - 2026-09-13

### Changed

- Updated the runtime XML parser to `fast-xml-parser` 5.11.1 and refreshed the verified
  documentation toolchain.
- Improved the documentation layout and standardized live npm, CI, security, coverage,
  deployment, OpenSSF, and license badges.

### Security

- Added a second human CODEOWNER and conventional commit and pull-request title enforcement.
- Added keyless Sigstore signatures and verification bundles for every GitHub Release asset, in
  addition to the existing checksum, CycloneDX SBOM, GitHub artifact attestation, and npm
  provenance.

## [0.1.0-beta.2] - 2026-08-24

### Fixed

- Accept valid RSA/SHA-1 CMS responses produced by Apple Profile Service clients
  while continuing to verify every signature and configured trust chain (#12).

## [0.1.0-beta.1] - 2026-08-22

### Added

- Initial TypeScript API for generating signed and unsigned Apple Profile
  Service profiles.
- PKCS#12 RSA/SHA-256 signing with caller-provided certificate chains.
- CMS response parsing, signature verification, optional trust validation, and
  lossless plist data.
- Result-based errors, warnings, configurable resource limits, and throwing
  convenience APIs.
- UDID Tools-branded documentation site, examples, tests, community health
  files, author metadata, and hardened CI and release automation.

[keep a changelog]: https://keepachangelog.com/en/1.1.0/
[semantic versioning]: https://semver.org/spec/v2.0.0.html
[unreleased]: https://github.com/udid-tools/core/compare/v0.1.0-beta.4...HEAD
[0.1.0-beta.4]: https://github.com/udid-tools/core/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/udid-tools/core/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/udid-tools/core/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/udid-tools/core/releases/tag/v0.1.0-beta.1
