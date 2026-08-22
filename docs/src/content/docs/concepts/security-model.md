---
title: Security model
description: Know what the package verifies and what remains application policy.
---

The package treats response bodies, plist data, PKCS#12 containers, and certificates as untrusted. It applies byte/count/depth limits, strict XML and DER parsing, an algorithm allow-list, full CMS signer verification, and sanitized typed failures.

## Integrity is not identity

The default response mode is `signature`. It verifies that every CMS signature matches the attached content and an embedded signer certificate. It returns `valid: true` and `trusted: null`, with `SIGNER_TRUST_NOT_CHECKED`.

This proves integrity, not that the signer belongs to a trust hierarchy you accept. Use `trust-chain` with your own roots and intermediates for that decision. The library does offline path validation only: it does not use the operating-system trust store, download intermediates, fetch CRLs, or call OCSP.

## Challenge correlation

Signature and trust checks do not prevent replay by themselves. Create a high-entropy single-use challenge, bind it to the authenticated session with an expiry, pass it to profile generation, then pass the expected value to response parsing. Consume it atomically after a successful business transaction.

The parser compares same-typed string/data challenges via fixed-size SHA-256 digests. It reports only `CHALLENGE_MISMATCH` or `MISSING_CHALLENGE`; the values are never copied into errors.

## Application responsibilities

- HTTPS termination and secure headers
- user/session authentication
- high-entropy challenge generation, expiry, single-use storage, and atomic consumption
- request size limits at the proxy/server in addition to library limits
- rate limiting and abuse controls
- trust-anchor lifecycle and certificate policy
- authorization of returned device identifiers
- secure secret loading and rotation
- redacted observability and incident response

Never expose a PKCS#12 identity to browser code. Do not log raw response data by default; device identifiers may be sensitive or regulated data.

See the repository [threat model](https://github.com/udid-tools/core/blob/main/THREAT_MODEL.md) and [security policy](https://github.com/udid-tools/core/blob/main/SECURITY.md).
