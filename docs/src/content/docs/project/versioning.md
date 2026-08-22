---
title: Versioning and releases
description: SemVer, beta tags, and dual-registry publication.
---

The package follows Semantic Versioning. The initial version is `0.1.0-beta.1`; prereleases use the npm `beta` dist-tag. Stable non-prerelease versions use `latest`.

During beta, a release may intentionally break an experimental contract, but every change is documented and versioned. The design still prefers additive fields and variants so real integrations do not churn. After a stable release, incompatible public API or behavior changes require a major version.

Release automation validates that the Git tag exactly matches `package.json`, runs all quality/security/docs checks, builds one allow-listed tarball, records SHA-256, produces a CycloneDX SBOM, attests the artifact, publishes the same bytes to npm and GitHub Packages, and creates a GitHub release.

npm publication uses Trusted Publishing/OIDC and provenance. GitHub Packages uses `GITHUB_TOKEN`. The protected `release` environment, registry trust relationship, branch/ruleset, secret scanning, and other settings require one-time repository-owner configuration documented in `.github/REPOSITORY_SETTINGS.md`.
