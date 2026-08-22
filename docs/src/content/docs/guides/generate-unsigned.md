---
title: Generate an unsigned profile
description: Create Profile Service XML from one typed configuration object.
---

Omit `signing` to request deterministic XML plist output:

```ts
import { generateProfile } from "@udid-tools/core";

const result = await generateProfile({
  profile: {
    kind: "profile-service",
    displayName: "Identify this device",
    description: "Shares selected identifiers with Example Inc.",
    identifier: "com.example.profile-service",
    organization: "Example Inc.",
    service: {
      responseUrl: "https://profiles.example.com/callback",
      deviceAttributes: ["UDID", "SERIAL", "PRODUCT", "VERSION"],
      challenge: { type: "string", value: oneTimeChallenge },
    },
  },
});

if (!result.ok) {
  return { status: 400, code: result.error.code };
}

return new Response(result.value.data, {
  headers: {
    "content-type": result.value.contentType,
    "content-disposition": 'attachment; filename="device.mobileconfig"',
  },
});
```

If `uuid` is absent, a cryptographically random UUID is created and returned in `result.value.profile.uuid`. Supply a stable valid UUID when replacement semantics require one.

Use HTTPS. Non-loopback HTTP is permitted for compatibility but emits `INSECURE_RESPONSE_URL`.

## Future Apple fields

Use `profile.extensions` or `profile.service.extensions` only for understood plist fields that the current types do not yet model. Reserved generated keys cannot be overridden. For a new uppercase device attribute, call `customDeviceAttribute("NEW_ATTRIBUTE")`; raw response data will preserve its value.
