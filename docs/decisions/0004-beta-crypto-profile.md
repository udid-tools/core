# ADR 0004: Beta cryptographic profile

- Status: Accepted
- Date: 2026-08-22

## Context

The first practical deployment uses an Apple Developer certificate with its developer-supplied chain. Supporting many key containers and algorithms immediately would increase the audit and interoperability surface before real demand exists.

## Decision

For `0.1.0-beta.1`, accept PKCS#12/PFX identities containing an RSA private key and matching X.509 signer certificate. Generate attached CMS/PKCS#7 SignedData using SHA-256 and RSA PKCS#1 v1.5. Allow only RSA/SHA-256 response signers. Additional chain certificates are optional and caller-provided.

New algorithms require an algorithm-request issue, threat analysis, fixtures/test vectors, interoperability testing, documentation, and a new discriminated configuration variant.

## Consequences

The beta is intentionally narrow and auditable. ECDSA, EdDSA, PEM key pairs, HSM/KMS providers, detached CMS, encryption, and revocation services are deferred without blocking additive future variants.
