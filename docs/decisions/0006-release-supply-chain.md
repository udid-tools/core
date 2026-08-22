# ADR 0006: Reproducible dual-registry release

- Status: Accepted
- Date: 2026-08-22

## Context

The package must be available from npm and GitHub Packages. A recent repository compromise makes release integrity, minimal credentials, dependency provenance, and repeatability primary requirements.

## Decision

Build and verify one allow-listed npm tarball per tag, compute its SHA-256, produce a CycloneDX SBOM, attest the artifact, and publish that exact tarball to both registries. npm uses Trusted Publishing/OIDC with provenance; GitHub Packages uses the scoped repository token. Actions are pinned to immutable commit SHAs, dependency caches and lifecycle scripts are disabled in privileged jobs, and reruns must match existing registry integrity.

Use semantic tags and map prereleases to the `beta` dist-tag. Protect the GitHub `release` environment and configure registry trust manually before first publication.

## Consequences

Registry contents are traceable to the same reviewed artifact. Release setup is more deliberate, and maintainers must follow the repository-settings checklist, but long-lived npm automation tokens are avoided.
