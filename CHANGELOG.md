# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project follows [Semantic
Versioning]. Prereleases use npm's `beta` distribution tag.

## [Unreleased]

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
[unreleased]: https://github.com/udid-tools/core/compare/v0.1.0-beta.2...HEAD
[0.1.0-beta.2]: https://github.com/udid-tools/core/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/udid-tools/core/releases/tag/v0.1.0-beta.1
