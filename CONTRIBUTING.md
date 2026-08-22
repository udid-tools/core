# Contributing to UDID Tools Core

Thank you for helping improve `@udid-tools/core`. The project welcomes bug
fixes, documentation improvements, tests, and carefully scoped features.

## Before you begin

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.
- Review [THREAT_MODEL.md](THREAT_MODEL.md) for security boundaries.
- Search existing issues and pull requests before opening a new one.
- Use the algorithm request form for a new key, container, or digest algorithm.

Never submit a production private key, PKCS#12/PFX identity, passphrase,
unredacted device response, or confidential certificate material. Test fixtures
must use synthetic identities created solely for testing.

## Development setup

The package requires Node.js 22.14.0 or newer and the npm version declared in
`package.json`.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run verify
```

The repository intentionally disables dependency lifecycle scripts during
installation. A dependency that requires an install script needs an explicit
security review and an architecture decision record before it can be accepted.

Useful commands:

```bash
npm run format:check
npm run lint
npm run typecheck
npm test
npm run test:coverage
npm run build
npm run docs:api
npm run docs:check
npm run docs:build
npm run pack:check
```

## Making a change

1. Create a focused branch from `main`.
2. Add or update tests before changing security-sensitive behavior.
3. Keep public types independent from implementation-library types.
4. Preserve the Result-based default API and the documented no-side-effect
   guarantees.
5. Update documentation and the capability matrix when behavior changes.
6. Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for a
   user-visible change.
7. Run `npm run verify` from a clean working tree.

Do not combine unrelated refactors with a security fix or feature. Avoid adding
runtime dependencies unless the capability cannot reasonably be implemented
with the platform or an existing audited dependency.

## Architecture and public API

The library is framework-agnostic and server-only. It must not read environment
variables, read files, make network requests, log, create background tasks, or
mutate global state. Callers explicitly supply all signing and trust material.

Changes to public exports, public error or warning codes, defaults, serialized
output, or validation policy are API changes. Backward-compatible optional
capabilities may ship in a minor release. Renames, removals, stricter defaults,
or behavioral changes require a major release after `1.0.0` and a migration
guide. During beta, propose material API changes in an issue before coding.

Significant architecture decisions require an ADR in `docs/decisions/`. An ADR should
state the context, decision, alternatives, consequences, and compatibility
impact.

## Tests

Every fix or feature needs tests at the lowest useful level. Depending on the
change, include:

- Unit tests for validation and transformations.
- Integration tests for signing, parsing, and verification.
- Synthetic malformed-input and resource-limit tests.
- Compile-time tests for public TypeScript contracts.
- A consumer test against the packed tarball.
- Documentation example compilation.

Tests must be deterministic and must not require network access, Apple services,
or private production material.

## Commits and pull requests

Write small commits with an imperative summary. A pull request must explain the
problem, the chosen design, security implications, compatibility impact, and
verification performed. Complete the pull request template and respond to
review feedback without rewriting another contributor's work.

All required checks must pass. Security-sensitive files may require a
CODEOWNER review. Maintainers may request changes even when automated checks
pass.

## Dependency changes

Explain why every new dependency is needed and what alternatives were
considered. Include its license, maintenance status, install-script behavior,
transitive dependency impact, and known security posture in the pull request.
Dependency Review, CodeQL, npm audit, Dependabot, and OpenSSF Scorecard augment
human review; they do not replace it.

## Releases

Only maintainers release the package. Release workflows build one tarball,
attest it, and publish that same artifact to npm and GitHub Packages. Do not
publish product versions locally or add registry tokens to the repository. The
only exception is the documented one-time, non-release namespace bootstrap in
`.github/REPOSITORY_SETTINGS.md` before OIDC can be configured.
