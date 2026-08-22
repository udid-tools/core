# `@udid-tools/core`

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14211/badge)](https://www.bestpractices.dev/projects/14211)

Security-first TypeScript primitives for Apple Profile Service profiles: generate XML, optionally produce attached CMS/PKCS#7 SignedData, verify device responses, and parse every returned plist field without losing unknown data.

> **Beta:** `0.1.0-beta.1` is ready for evaluation. Its public API follows semantic versioning, but beta releases may still contain breaking changes. MDM is intentionally out of scope.

## Install

```bash
npm install @udid-tools/core@beta
```

The package is ESM-only, requires Node.js 22.14 or newer, and is intended for trusted server-side runtimes. It can also be installed from GitHub Packages under the same `@udid-tools/core` name after configuring the `@udid-tools` registry.

## Generate a profile

```ts
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
      challenge: { type: "string", value: "single-use-correlation-token" },
    },
  },
});

if (!result.ok) {
  console.error(result.error.code);
} else {
  // result.value.data is an unsigned XML mobileconfig because signing was omitted.
  // Send it with result.value.contentType.
}
```

`signing` is never a boolean. If it is absent, the result is XML. If it is present, it must contain a complete identity; invalid or incomplete material fails closed and never silently falls back to unsigned output.

```ts
const signed = await generateProfile({
  profile,
  signing: {
    identity: {
      type: "pkcs12",
      data: { encoding: "base64", value: applicationSecret.p12Base64 },
      passphrase: applicationSecret.p12Passphrase,
    },
    certificateChain: applicationSecret.chainPem.map((value) => ({
      encoding: "pem" as const,
      value,
    })),
  },
});
```

The library uses only the PKCS#12/PFX identity and certificate chain supplied by the caller. It never downloads Apple certificates, reads environment variables, opens files, uses the network, or selects a hidden trust store.

## Parse a device response

```ts
import { parseProfileServiceResponse } from "@udid-tools/core";

const result = await parseProfileServiceResponse(requestBody, {
  expectedChallenge: {
    type: "string",
    value: "single-use-correlation-token",
  },
  requiredAttributes: ["UDID"],
  verification: {
    mode: "trust-chain",
    trustAnchors: trustedRoots,
    intermediates,
  },
});

if (!result.ok) {
  // Invalid CMS, signatures, trust chains, challenges, and required fields
  // are typed failures.
  console.error(result.error.code);
} else {
  console.log(result.value.attributes.udid);
  console.log(result.value.raw); // unknown future fields remain available
}
```

The default verification mode checks signature integrity using the embedded signer certificate and reports `trusted: null`. Use `trust-chain` with caller-provided anchors when signer identity matters. `mode: "none"` and unsigned parsing are explicit opt-ins.

## Capability matrix

| Capability                                  | `0.1.0-beta.1`                                                                     |
| ------------------------------------------- | ---------------------------------------------------------------------------------- |
| Apple Profile Service payload               | Supported                                                                          |
| Documented attributes                       | `UDID`, `VERSION`, `PRODUCT`, `SERIAL`, `MEID`, `IMEI`, `ICCID`, `MAC_ADDRESS_EN0` |
| Challenge                                   | String and data                                                                    |
| Unknown request/response fields             | Preserved through typed extensions and `raw`                                       |
| Unsigned XML generation                     | Supported                                                                          |
| Signed profile generation                   | Attached CMS/PKCS#7 SignedData                                                     |
| Signing identity                            | PKCS#12/PFX with RSA private key                                                   |
| Minimum signing key                         | RSA 2048 bits                                                                      |
| Digest                                      | SHA-256                                                                            |
| Certificate chain                           | Caller-provided only                                                               |
| Response verification                       | None, signature integrity, or caller-provided trust chain                          |
| XML plist                                   | Dictionary, array, string, integer, real, boolean, date, data                      |
| MDM, SCEP orchestration, profile encryption | Not included                                                                       |
| Browser runtime                             | Not supported                                                                      |

## Failure model

Normal entry points return `Promise<Result<T>>`. They catch and sanitize expected and unexpected implementation failures so a malformed device payload does not reject the Promise or crash the host request handler.

```ts
const result = await generateProfile(config);

if (!result.ok) {
  switch (result.error.code) {
    case "INCORRECT_PASSPHRASE":
    case "CERTIFICATE_KEY_MISMATCH":
      // Handle configuration securely.
      break;
  }
}
```

Developers who prefer exceptions can opt into `generateProfileOrThrow` and `parseProfileServiceResponseOrThrow`. Every throwing entry point is visibly suffixed with `OrThrow`.

Success values can contain typed warnings such as an insecure response URL, an unchecked signer trust relationship, a certificate nearing expiry, or an unknown response attribute. The library never logs them itself.

## Security posture

- Strict input/output, certificate, collection, string, and nesting limits are enabled by default and can be tightened per call.
- XML DTD expansion, custom entities, processing instructions, CDATA, duplicate dictionary keys, unsafe object keys, invalid UTF-8, and noncanonical base64 are rejected.
- DER/CMS is size-checked and depth-preflighted before cryptographic parsing.
- Private keys and passphrases are not returned, logged, or included in error details.
- Challenge matching uses fixed-size digest comparison and never includes challenge values in errors.
- No global mutable state, telemetry, logging, environment access, filesystem access, or network access exists in runtime source.

See [SECURITY.md](./SECURITY.md) and [THREAT_MODEL.md](./THREAT_MODEL.md) before deploying an internet-facing endpoint.

## Application-owned environment variables

The package deliberately defines no environment-variable contract. A consuming application may use these recommended names while migrating from older site-specific variables:

- `UDID_TOOLS_SIGNING_PKCS12_BASE64`
- `UDID_TOOLS_SIGNING_PKCS12_PASSPHRASE`
- `UDID_TOOLS_SIGNING_CERTIFICATE_CHAIN_PEM`

Read and validate them in the application, then pass their values to `signing`. This keeps secret managers, rotation, and deployment policy outside the reusable core.

## Documentation and project policy

- Documentation site: <https://udid-tools.github.io/core/>
- Architecture: [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)
- Contributor guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Security policy: [`SECURITY.md`](./SECURITY.md)
- Changelog: [`CHANGELOG.md`](./CHANGELOG.md)

The repository includes CI, CodeQL, dependency review, Scorecard, secret scanning guidance, release attestations, SBOM generation, npm provenance, GitHub Packages publishing, issue forms, and an algorithm-request template. Releases use semantic versioning; prereleases are published under the `beta` dist-tag.

## Apple references

The Profile Service format is documented in Apple’s archived [Over-the-Air Profile Delivery and Configuration](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html) guide and its [configuration profile examples](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/ConfigurationProfileExamples/ConfigurationProfileExamples.html). General profile keys are cross-checked against Apple’s current [configuration profile documentation](https://developer.apple.com/documentation/devicemanagement/configuring-multiple-devices-using-profiles).

Apple’s documentation and platform behavior remain authoritative. This project is independent and is not affiliated with or endorsed by Apple Inc.

## License

[MIT](./LICENSE) © UDID Tools contributors.
