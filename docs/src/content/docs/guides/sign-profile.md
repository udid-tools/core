---
title: Sign a profile
description: Produce attached CMS SignedData from caller-provided PKCS#12 material.
---

Provide a complete nested `signing` object to receive signed DER:

```ts
const result = await generateProfile({
  profile,
  signing: {
    identity: {
      type: "pkcs12",
      data: { encoding: "base64", value: secrets.pkcs12Base64 },
      passphrase: secrets.pkcs12Passphrase,
    },
    certificateChain: secrets.chainPem.map((value) => ({
      encoding: "pem" as const,
      value,
    })),
    digestAlgorithm: "sha256",
  },
});
```

`Uint8Array`, strict base64, and PEM certificate inputs are supported. The PKCS#12 container must have exactly one unambiguous RSA private-key/certificate match, and the signing key must be at least 2048 bits. Certificates already present in the container and supplied chain are deduplicated by SHA-256 fingerprint.

The beta output is attached CMS/PKCS#7 SignedData with content-type, message-digest, and signing-time authenticated attributes. The chain is embedded in the output; the package never downloads or invents it.

## Fail-closed behavior

If `signing` exists but the identity, key, certificate, passphrase, algorithm, or key/certificate match is invalid, the call returns an error. It never emits unsigned XML as a fallback.

An expired signer certificate is an error. A not-yet-valid certificate and a certificate expiring within 30 days produce warnings. Whether Apple devices trust/install a particular developer certificate remains deployment policy and must be tested on target platform versions.

## Application-owned secret names

The package never reads environment variables. Applications migrating to the package may standardize on:

```text
UDID_TOOLS_SIGNING_PKCS12_BASE64
UDID_TOOLS_SIGNING_PKCS12_PASSPHRASE
UDID_TOOLS_SIGNING_CERTIFICATE_CHAIN_PEM
```

Read them through your validated configuration/secret manager and pass the values explicitly. Avoid multiline-chain ambiguity by parsing each PEM block into a separate array item.
