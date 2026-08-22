## Summary

<!-- What problem does this change solve, and why is this design appropriate? -->

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Refactor with no intended behavior change
- [ ] Dependency or build tooling
- [ ] Security hardening

## Public API and compatibility

<!-- Describe changes to exports, types, error/warning codes, defaults, validation, or serialized bytes. Write "None" when there is no public impact. -->

- [ ] The change is backward-compatible with the documented beta API.
- [ ] User-visible behavior is documented and listed in `CHANGELOG.md`.
- [ ] A migration note or ADR is included when the compatibility impact is material.

## Security review

<!-- Consider trust boundaries, secret handling, parser limits, algorithm support, dependencies, and release behavior. -->

- [ ] I reviewed `THREAT_MODEL.md` and preserved its security invariants.
- [ ] The change introduces no implicit network, filesystem, environment, logging, or background-task behavior.
- [ ] Errors, warnings, fixtures, and snapshots contain no production secrets or real device data.
- [ ] New or changed untrusted-input paths have negative and resource-limit tests.
- [ ] New dependencies are justified below and do not require an unreviewed install script.

### Dependency justification

<!-- For each new dependency: purpose, alternatives, license, maintenance/security posture, lifecycle scripts, and transitive impact. Write "None" otherwise. -->

## Verification

<!-- List exact commands and device/interoperability checks performed. -->

- [ ] `npm run verify`
- [ ] Relevant examples compile and use the current API.
- [ ] Tests use only disposable synthetic identities and sanitized fixtures.

## Documentation and references

<!-- Link official Apple/standards references, issues, ADRs, and updated guides. -->
