# Security policy

Security is a core design constraint of `@udid-tools/core`. The package handles
untrusted CMS/plist input and caller-provided signing material, so reports that
could affect confidentiality, integrity, authenticity, availability, or the
package supply chain are treated seriously.

## Supported versions

The project is currently in beta. Until the first stable release, only the
latest published beta receives security fixes.

| Version                     | Supported   |
| --------------------------- | ----------- |
| Latest `0.x` beta           | Yes         |
| Older prereleases           | No          |
| Unreleased source on `main` | Best effort |

This table will be updated when a stable release exists.

## Report a vulnerability privately

Use [GitHub Private Vulnerability Reporting] to report a suspected
vulnerability. Do not open a public issue, discussion, or pull request before a
coordinated disclosure.

[github private vulnerability reporting]: https://github.com/udid-tools/core/security/advisories/new

Include, when safe and relevant:

- Affected package version and Node.js version.
- Impact and realistic attack scenario.
- Minimal reproduction using synthetic data.
- Whether the issue is known to be actively exploited.
- Suggested remediation or mitigations.

Never send a production private key, passphrase, PKCS#12/PFX identity,
authentication token, or unredacted real-device response. Maintainers will ask
for a synthetic reproduction if additional material is needed.

We aim to acknowledge a complete report within three business days and provide
an initial triage within seven business days. Complex investigations may take
longer. These targets are best-effort, not guarantees.

## Coordinated disclosure

Maintainers will validate the report, determine affected versions, prepare and
review a fix, request a CVE when appropriate, publish a security advisory, and
release patched versions before public technical details are shared. Reporter
credit is offered unless anonymity is requested.

Please allow a reasonable remediation window and avoid testing against systems
or data you do not own or have permission to assess.

## Security expectations

The library is designed to:

- Perform no implicit network, filesystem, environment-variable, or logging
  operations.
- Keep expected failures inside the public `Result` contract.
- Apply bounded parsing and validation to untrusted input.
- Avoid exposing secrets in errors, warnings, or diagnostic metadata.
- Require explicit trust anchors for trust-chain validation.
- Use only caller-provided signing identities and certificate chains.

No JavaScript library can recover from process termination, runtime failure, or
resource exhaustion outside its enforceable limits. See [THREAT_MODEL.md] for
the detailed guarantees, exclusions, and residual risks.

[threat_model.md]: THREAT_MODEL.md

## Repository and release security

Official releases are produced only by the protected GitHub Actions release
environment. npm publishing uses trusted publishing with OIDC; GitHub Packages
uses the job-scoped `GITHUB_TOKEN`. Releases are built once and the same tarball
is published to both registries. Long-lived registry tokens must not be used.

Consumers should verify package provenance and pin dependencies according to
their risk model.
