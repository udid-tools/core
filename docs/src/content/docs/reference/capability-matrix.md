---
title: Capability matrix
description: Exact implemented and deferred surface.
---

| Area                  | Supported                                                                                     | Deferred / excluded                                        |
| --------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Runtime               | Node.js ≥22.14, ESM, TypeScript declarations                                                  | Browser/client-side signing, CommonJS                      |
| Profile               | Apple `Profile Service` generation                                                            | General configuration payload builder, MDM                 |
| Attributes            | UDID, VERSION, PRODUCT, SERIAL, MEID, IMEI, ICCID, MAC_ADDRESS_EN0; branded custom attributes | Guarantee that a device supplies every requested value     |
| Challenge             | String/data generation, parsing, expected-value comparison                                    | Challenge creation/storage/expiry/consumption              |
| Forward compatibility | Top-level/service extensions; lossless response `raw`                                         | Unvalidated reserved-key overrides                         |
| Plist                 | XML dictionary, array, string, safe integer, real, boolean, date, data                        | Binary plist                                               |
| Output protection     | Unsigned XML or attached CMS SignedData                                                       | Profile encryption, detached CMS                           |
| Identity              | PKCS#12/PFX, RSA key/certificate matching, minimum 2048-bit signing key                       | PEM private keys, HSM/KMS providers, ECDSA/EdDSA           |
| Profile signing       | SHA-256 with RSA PKCS#1 v1.5                                                                  | SHA-1 generation, SHA-384/512, RSA-PSS                     |
| Response signatures   | SHA-1 or SHA-256 with RSA PKCS#1 v1.5                                                         | SHA-384/512, RSA-PSS                                       |
| Chains                | Caller-supplied embedded chain                                                                | Automatic Apple/OS chain discovery/download                |
| Verification          | none, integrity, explicit offline trust chain                                                 | OS trust store, AIA fetching, CRL/OCSP network checks      |
| Side effects          | none                                                                                          | Filesystem, env, network, logging, telemetry, global state |
| Distribution          | npm and GitHub Packages design; beta dist-tag                                                 | Publication before owner review                            |

New caller-configurable crypto capabilities enter as additive discriminated variants after an algorithm request, security review, test vectors, interoperability coverage, documentation, and an ADR.
