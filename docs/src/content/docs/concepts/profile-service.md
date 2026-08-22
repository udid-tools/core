---
title: Apple Profile Service
description: Understand the narrow Apple Profile Service flow implemented by the package.
---

Apple Profile Service is a special configuration profile whose literal `PayloadType` is `Profile Service`. It asks a device to POST selected identifiers to a URL. The request profile may include an opaque `Challenge`; the device returns that value with the requested attributes and signs the plist response as CMS/PKCS#7 SignedData.

The beta implements that focused exchange:

1. Your application authenticates a user and creates a one-time challenge.
2. `generateProfile` creates the Profile Service plist and optionally signs it.
3. Your HTTP endpoint serves the returned bytes as `application/x-apple-aspen-config`.
4. The device POSTs signed data to the configured URL.
5. `parseProfileServiceResponse` checks integrity or an explicit trust chain, compares the expected challenge, parses the plist, and returns typed and raw fields.
6. Your application authorizes and stores the result.

This is not MDM. It does not establish an APNs-backed management channel, execute commands, perform check-in, orchestrate SCEP, or maintain enrollment state. Those responsibilities would belong to a separate package.

## Documented request fields

The Profile Service payload uses the common profile fields `PayloadIdentifier`, `PayloadUUID`, `PayloadVersion`, `PayloadDisplayName`, and optional description/organization, plus a `PayloadContent` dictionary:

| Field              | Type             | Library field              |
| ------------------ | ---------------- | -------------------------- |
| `URL`              | string URL       | `service.responseUrl`      |
| `DeviceAttributes` | array of strings | `service.deviceAttributes` |
| `Challenge`        | string or data   | `service.challenge`        |

Apple’s examples cover `UDID`, `VERSION`, `PRODUCT`, `SERIAL`, `MEID`, `IMEI`, `ICCID`, and `MAC_ADDRESS_EN0` across request and response examples. Hardware/platform availability varies, so request only what you need and decide which values are truly required.

## Primary references

- Apple, [Creating a Profile Server for Over-the-Air Enrollment and Configuration](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html) (archived, updated 2018-04-09; accessed 2026-08-22)
- Apple, [Configuration Profile Examples](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/ConfigurationProfileExamples/ConfigurationProfileExamples.html) (archived, updated 2018-04-09; accessed 2026-08-22)
- Apple, [Configuring multiple devices using profiles](https://developer.apple.com/documentation/devicemanagement/configuring-multiple-devices-using-profiles) (accessed 2026-08-22)

Apple documentation and device behavior are authoritative. The project is independent and not endorsed by Apple.
