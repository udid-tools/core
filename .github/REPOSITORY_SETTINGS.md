# Repository security setup

Git cannot encode every GitHub, npm, or organization policy. Complete this
checklist before the repository accepts contributions or publishes a release.
Settings names can change; choose the strict equivalent when the UI differs.

## GitHub organization

- Require two-factor authentication for every member; maintainers should use
  passkeys or hardware security keys.
- Keep the number of organization owners minimal and review it regularly.
- Restrict repository creation, Action installation, and OAuth application
  approval to trusted roles.
- Set the default `GITHUB_TOKEN` permission to read repository contents only.
- Allow only required Actions. Require full commit SHA pinning through
  organization policy when available.
- Store and test an offline account- and organization-recovery procedure.

## Repository features

- Enable the dependency graph, Dependabot alerts, Dependabot security updates,
  code scanning, secret scanning, and push protection.
- Enable GitHub Private Vulnerability Reporting.
- Configure GitHub Pages to use **GitHub Actions** as its source.
- Disable unused deployment keys, webhooks, Apps, and Actions periodically.
- Enable automatic deletion of head branches after merge.

Create the labels used by forms and generated release notes: `bug`,
`enhancement`, `crypto`, `documentation`, `security`, `dependencies`, `javascript`,
`github-actions`, `breaking-change`, and `skip-changelog`. Give security and
breaking-change labels visually distinct colors.

## `main` ruleset

- Require pull requests and at least one approving review.
- Require review from CODEOWNERS for owned files.
- Dismiss stale approvals after new commits and require approval of the most
  recent reviewable push.
- Require all conversations to be resolved.
- Require branches to be up to date before merge.
- Require these checks after their first successful run:
  - `Quality and test suite`
  - `Node.js 22.14.0 compatibility`
  - `Node.js 24 compatibility`
  - `Packed package consumer`
  - `Dependency review`
  - `CodeQL`
  - `npm audit`
- Block force pushes and branch deletion.
- Require linear history and signed commits when that policy is practical for
  every maintainer and automation account.
- Limit bypass permission to emergency maintainers and audit every bypass.

The dependency review job exists only on pull requests. GitHub can treat a
conditionally skipped job differently across ruleset configurations; confirm
the selected required-check behavior with a test pull request.

## Release tags and environment

- Add a tag ruleset for `v*` that restricts creation, update, deletion, and
  bypass. Require signed annotated tags.
- Create a `release` environment with required reviewers, no self-review when
  available, and deployment restricted to protected release tags.
- Do not add npm tokens to the environment. GitHub Packages uses the
  automatically scoped `GITHUB_TOKEN`.
- Test the environment and tag policy with a disposable prerelease version
  before relying on it for a stable release.

## npm trusted publishing

For `@udid-tools/core`, configure a GitHub Actions trusted publisher with these
exact, case-sensitive values:

```text
Organization: udid-tools
Repository: core
Workflow filename: release.yml
Environment: release
Allowed action: npm publish
```

The repository must be public for npm provenance. Trusted publisher settings
live on an existing npm package's settings page, so verify npm's current
first-publish support before creating the first release tag. If the package
cannot yet be connected to OIDC, perform one carefully reviewed bootstrap
before publishing `0.1.0-beta.1`:

1. Prepare a minimal, dependency-free placeholder named `@udid-tools/core` with
   a clearly non-release version such as `0.0.0-bootstrap.0`. Include only
   metadata, the MIT license, and a README stating that it has no functional API.
2. Inspect its tarball file list. From a clean trusted workstation, publish it as
   public under a dedicated `bootstrap` dist-tag using an interactive npm
   session protected by 2FA. Staged publishing cannot bootstrap a package that
   does not yet exist.
3. Log out and revoke any bootstrap token immediately. Configure and test the
   trusted publisher above, then disallow traditional token publishing.
4. Publish `0.1.0-beta.1` only through the protected release workflow so the
   real first beta receives npm OIDC provenance. Afterward, remove the temporary
   `bootstrap` dist-tag; the placeholder version itself remains immutable.

Never add a bootstrap token to this repository, a GitHub secret, an issue, or a
workflow file. Never manually bootstrap with the planned beta version: npm
versions are immutable, and the release workflow cannot add missing provenance
by republishing it. If any integrity comparison fails, stop and investigate.

The release workflow requires Node.js 22.14.0 or newer and npm 11.5.1 or newer
for OIDC. It intentionally installs the exact npm version declared in
`package.json`, disables release caches, and publishes one checksum-verified
tarball to both registries.

## npm organization and package

- Require two-factor authentication and hardware-backed authentication for npm
  maintainers.
- Keep package maintainers minimal and review them regularly.
- Require two-factor authentication for package settings changes.
- After OIDC is verified, disallow traditional token publishing and revoke
  obsolete automation tokens.
- Confirm that `beta` points only to a prerelease and `latest` only to a stable
  release after every publication.

## GitHub Packages

- Keep package access inherited from the repository unless a narrower policy is
  required.
- Confirm that only the release workflow has `packages: write`.
- Verify the GitHub Packages tarball checksum matches the npm tarball and the
  checksum attached to the GitHub Release.

## Periodic review

At least quarterly and after every security incident, audit members, owners,
ruleset bypasses, environments, trusted publishers, package maintainers,
installed Apps, workflow permissions, Actions pins, dependency alerts, secret
scanning findings, and recovery material. Record remediation in a private
security tracking system when disclosure would increase risk.
