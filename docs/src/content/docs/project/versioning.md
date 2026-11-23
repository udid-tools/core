---
title: Versioning and releases
description: SemVer, stable releases, and dual-registry publication.
---

The package follows Semantic Versioning. Version `1.0.0` is the first stable release and uses the npm `latest` dist-tag. Future beta prereleases use a separate `beta` dist-tag.

Incompatible public API or behavior changes require a major version. Prefer additive fields and variants, document changes, and deprecate supported contracts before removal.

Release automation validates that the signed Git tag exactly matches `package.json`, runs all quality/security/docs checks, builds one allow-listed tarball, records SHA-256, produces a CycloneDX SBOM, keylessly signs and verifies every release asset with Sigstore, attests the tarball, publishes the same bytes to npm and GitHub Packages, and creates a GitHub release.

npm publication uses Trusted Publishing/OIDC and provenance. GitHub Packages uses `GITHUB_TOKEN`. Verification instructions and the expected workflow identity are documented in [Release integrity](./release-integrity/). The protected `release` environment, registry trust relationship, branch/ruleset, secret scanning, and other settings require one-time repository-owner configuration documented in `.github/REPOSITORY_SETTINGS.md`.
