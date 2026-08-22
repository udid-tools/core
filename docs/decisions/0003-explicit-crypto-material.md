# ADR 0003: Explicit signing and trust material

- Status: Accepted
- Date: 2026-08-22

## Context

Certificate chains and trust policy vary between developers and deployments. Automatic Apple-chain downloads or environment/filesystem conventions introduce network dependence, hidden trust, secret-handling ambiguity, and hard-to-test global configuration.

## Decision

The library reads no environment variables or files and performs no network access. Callers pass the signing identity and optional certificate chain through the nested `signing` object. Response trust-chain verification uses only explicit `trustAnchors` and optional `intermediates`.

Absent `signing` requests XML. Present but incomplete signing material is an error; the implementation never falls back silently. Integrity verification and signer trust remain separate states.

## Consequences

Secret managers and rotation stay application-owned. Tests are deterministic and offline. Developers must load and pass their own material, but the trust boundary is visible in code and no certificate authority is privileged implicitly.
