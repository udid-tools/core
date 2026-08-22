---
title: Roadmap
description: Additive directions after the first beta.
---

The roadmap is demand- and evidence-driven:

- validate interoperability against real Apple-device fixtures without committing sensitive identifiers;
- add more identity/provider variants only after algorithm-request review;
- consider PEM key pairs and KMS/HSM signing providers behind new discriminated variants;
- expand certificate policy and inspection metadata without changing secure defaults;
- normalize newly documented Apple response fields while preserving `raw`;
- strengthen consumer compatibility and platform matrices;
- graduate from beta after API/security feedback and audited real-world use.

Profile encryption, SCEP orchestration, and complete OTA enrollment state machines are not promised for core. MDM remains a possible separate package and will not be folded into this API merely because it also uses configuration profiles.

Use the GitHub feature form for product requests and the dedicated cryptographic algorithm form for any signing/verification expansion.
