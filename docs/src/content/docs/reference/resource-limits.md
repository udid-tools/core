---
title: Resource limits
description: Default bounds applied before expensive parsing and crypto work.
---

| Limit                 | Default |
| --------------------- | ------: |
| `maxInputBytes`       |   2 MiB |
| `maxOutputBytes`      |   2 MiB |
| `maxAsn1Depth`        |      32 |
| `maxAsn1Nodes`        |   8,192 |
| `maxCertificateBytes` | 256 KiB |
| `maxCertificates`     |      16 |
| `maxPlistDepth`       |      32 |
| `maxArrayItems`       |     256 |
| `maxDictionaryKeys`   |     256 |
| `maxStringBytes`      | 512 KiB |

Override only what your use case needs:

```ts
await parseProfileServiceResponse(body, {
  limits: {
    maxInputBytes: 256 * 1024,
    maxCertificates: 8,
    maxAsn1Depth: 24,
    maxAsn1Nodes: 4_096,
    maxPlistDepth: 16,
  },
});
```

Every override must be a positive safe integer. Limits are per call, have no global state, and are resolved before work begins. Configure an equal or smaller request-body limit at your reverse proxy/framework so large requests are rejected before buffering.

ASN.1/CMS receives byte, depth, content-length, node, signer, and certificate checks. No parser can promise constant memory for every dependency bug; keep dependencies updated, retain outer process/request isolation, and follow the security policy.
