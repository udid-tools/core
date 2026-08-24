---
title: Contributing
description: How to propose, implement, and verify changes safely.
---

Read the repository’s [contributor guide](https://github.com/udid-tools/core/blob/main/CONTRIBUTING.md), [security policy](https://github.com/udid-tools/core/blob/main/SECURITY.md), [threat model](https://github.com/udid-tools/core/blob/main/THREAT_MODEL.md), and `AGENTS.md` before changing protocol or cryptographic behavior.

Use the matching issue form. Security vulnerabilities must be reported privately, not through public issues. New caller-configurable algorithms require the dedicated request form and must include motivation, standards/OIDs, key/container formats, test vectors, platform interoperability evidence, threat analysis, and migration impact. Reproducible compatibility defects within the existing Apple Profile Service scope use the bug report form and still require synthetic regression coverage and security review.

Local verification:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run verify
npm audit --audit-level=high
npm audit signatures
```

Update tests, docs, capability matrix, changelog, and an ADR when the change affects a public/security contract. Never use real production certificates, passphrases, challenges, or device identifiers as fixtures.
