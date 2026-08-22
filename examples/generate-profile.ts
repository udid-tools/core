import { writeFile } from "node:fs/promises";

import { generateProfile } from "@udid-tools/core";

const result = await generateProfile({
  profile: {
    kind: "profile-service",
    displayName: "Device Identification",
    identifier: "com.example.profile-service",
    organization: "Example Inc.",
    service: {
      challenge: { type: "string", value: "single-use-correlation-token" },
      deviceAttributes: ["UDID", "SERIAL", "PRODUCT", "VERSION"],
      responseUrl: "https://example.com/profile-response",
    },
  },
});

if (!result.ok) {
  throw result.error;
}

await writeFile("device.mobileconfig", result.value.data, { mode: 0o600 });
