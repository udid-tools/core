---
title: Quick start
description: Generate your first Apple Profile Service mobile configuration profile.
---

```ts
import { writeFile } from "node:fs/promises";

import { generateProfile } from "@udid-tools/core";

const result = await generateProfile({
  profile: {
    kind: "profile-service",
    identifier: "com.example.profile-service",
    displayName: "Device Identification",
    organization: "Example Inc.",
    service: {
      responseUrl: "https://example.com/profile-response",
      deviceAttributes: ["UDID", "SERIAL", "PRODUCT", "VERSION"],
    },
  },
});

if (!result.ok) {
  throw new Error(`Profile generation failed: ${result.error.code}`);
}

await writeFile("device.mobileconfig", result.value.data);
```

Omit `signing` to generate XML. Pass a complete PKCS#12 signing identity to receive attached CMS/PKCS#7 Signed Data.

`result.value.contentType` is always `application/x-apple-aspen-config`. Send the bytes without converting signed DER to text.

The package does not decide how to authenticate the user, issue/store the challenge, authorize the device, or persist returned attributes. Those are application responsibilities.
