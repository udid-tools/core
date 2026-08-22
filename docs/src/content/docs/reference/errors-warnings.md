---
title: Errors and warnings
description: Machine-readable failure and advisory contracts.
---

Branch on `error.code`, not the human-readable message.

## Errors

| Code                                                           | Meaning                                                          |
| -------------------------------------------------------------- | ---------------------------------------------------------------- |
| `INVALID_CONFIGURATION`                                        | A runtime option shape or limit is invalid                       |
| `INVALID_PROFILE_IDENTIFIER`                                   | Identifier is not valid reverse-DNS notation                     |
| `INVALID_RESPONSE_URL`                                         | Callback URL is invalid or unsupported                           |
| `MISSING_SIGNING_MATERIAL`                                     | Present signing config lacks a required identity/key/certificate |
| `INCORRECT_PASSPHRASE`                                         | PKCS#12 passphrase did not verify                                |
| `INVALID_PKCS12`, `INVALID_PRIVATE_KEY`, `INVALID_CERTIFICATE` | Crypto material is malformed/invalid                             |
| `CERTIFICATE_KEY_MISMATCH`                                     | No unambiguous RSA key/certificate match exists                  |
| `UNSUPPORTED_ALGORITHM`                                        | Input is outside the beta allow-list                             |
| `PROFILE_SIGNING_FAILED`                                       | CMS output could not be produced                                 |
| `MALFORMED_CMS`, `MALFORMED_PLIST`                             | External response syntax/structure is invalid                    |
| `INVALID_SIGNATURE`                                            | CMS integrity verification failed                                |
| `UNTRUSTED_SIGNER`                                             | Explicit path validation failed                                  |
| `MISSING_CHALLENGE`, `CHALLENGE_MISMATCH`                      | Correlation data is absent or different                          |
| `MISSING_REQUIRED_ATTRIBUTE`                                   | A caller-required normalized value is absent                     |
| `INPUT_TOO_LARGE`, `OUTPUT_TOO_LARGE`                          | A resource boundary was exceeded                                 |
| `INTERNAL_ERROR`                                               | An unexpected dependency/implementation failure was sanitized    |

`INVALID_PRIVATE_KEY` is reserved for additive identity formats; current PKCS#12 key failures normally map to missing material, unsupported algorithm, mismatch, or invalid PKCS#12.

## Warnings

| Code                            | Meaning                                          |
| ------------------------------- | ------------------------------------------------ |
| `INSECURE_RESPONSE_URL`         | Non-loopback HTTP callback                       |
| `SIGNER_TRUST_NOT_CHECKED`      | Integrity and trust were partly or fully skipped |
| `CERTIFICATE_NOT_YET_VALID`     | Signer validity window has not begun             |
| `CERTIFICATE_EXPIRES_SOON`      | Signer expires within 30 days                    |
| `DUPLICATE_CERTIFICATE_IGNORED` | Duplicate chain entries were removed             |
| `UNKNOWN_RESPONSE_ATTRIBUTE`    | Field is preserved only in `raw`                 |
| `OPTIONAL_ATTRIBUTE_MISSING`    | An expected, nonrequired field is absent         |

The package never logs warnings. Decide how to record them without exposing secrets or device identifiers.
