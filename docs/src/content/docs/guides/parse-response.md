---
title: Parse a device response
description: Verify CMS, correlate a challenge, and normalize device attributes safely.
---

Pass the exact request body bytes. Do not decode CMS DER as UTF-8:

```ts
const result = await parseProfileServiceResponse(body, {
  expectedChallenge: { type: "string", value: storedChallenge },
  expectedAttributes: ["PRODUCT", "VERSION"],
  requiredAttributes: ["UDID"],
  verification: {
    mode: "trust-chain",
    trustAnchors: roots,
    intermediates,
  },
});

if (!result.ok) {
  return new Response("Invalid profile response", { status: 400 });
}

const { attributes, raw, signature } = result.value;
```

`requiredAttributes` turn absence into `MISSING_REQUIRED_ATTRIBUTE`. `expectedAttributes` produce `OPTIONAL_ATTRIBUTE_MISSING` warnings instead, which is useful for hardware-dependent values such as IMEI or ICCID.

Known values are normalized in `attributes`; the complete null-prototype plist dictionary remains in `raw`. Unknown keys emit warnings but are not discarded.

## Verification modes

| Mode                  | Signature integrity | Trust chain                | Result state                   |
| --------------------- | ------------------- | -------------------------- | ------------------------------ |
| omitted / `signature` | required            | not checked                | `valid: true`, `trusted: null` |
| `trust-chain`         | required            | caller roots/intermediates | both `true` on success         |
| `none`                | skipped             | skipped                    | both `null`, explicit warning  |

Invalid signatures or untrusted chains are failures, not successful responses with `false`. The boolean union leaves room for future inspection APIs while this high-level parser remains fail closed.

Signature and trust-chain modes verify both RSA/SHA-1 and RSA/SHA-256 responses used by Apple Profile Service clients.

Unsigned XML is rejected unless `allowUnsigned: true`. That option exists for fixtures and tightly controlled legacy integrations, not as a production default.
