---
title: Apple compatibility
description: Normative sources, documented attributes, and forward-compatibility policy.
---

The special Profile Service protocol is primarily documented in Apple’s archived OTA guide. Current Apple Device Management documentation now focuses mostly on configuration profiles and MDM, so this project distinguishes three evidence levels:

1. **Documented:** explicit in Apple Profile Service narrative or examples.
2. **Observed:** verified on specified platform versions with reproducible fixtures.
3. **Extension:** accepted losslessly but not yet normalized or claimed as Apple-defined.

`0.1.0-beta.1` types the documented attribute names `UDID`, `VERSION`, `PRODUCT`, `SERIAL`, `MEID`, `IMEI`, `ICCID`, and `MAC_ADDRESS_EN0`. Availability depends on device hardware, OS, privacy behavior, and enrollment context. A requested value is not automatically guaranteed.

When Apple adds a field, developers can use `customDeviceAttribute` and read `raw` without waiting for a release. A library update can then normalize it additively. Reserved structural fields cannot be overridden through extensions.

## References

- [Profile Service payload and signed response](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html)
- [Profile Service request/response plist examples](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/ConfigurationProfileExamples/ConfigurationProfileExamples.html)
- [Common payload keys](https://developer.apple.com/documentation/devicemanagement/commonpayloadkeys)
- [Configuring multiple devices using profiles](https://developer.apple.com/documentation/devicemanagement/configuring-multiple-devices-using-profiles)

References accessed 2026-08-22. Apple documentation and actual platform behavior take precedence over this independent implementation.
