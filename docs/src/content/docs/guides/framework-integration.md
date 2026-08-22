---
title: Framework integration
description: Keep web frameworks and application policy outside the core.
---

The package accepts and returns bytes, so adapters stay small in Express, Fastify, Next.js route handlers, Node HTTP, serverless functions, or workers that provide a compatible Node runtime.

Your download route should:

1. authenticate and authorize the user;
2. generate and persist a short-lived one-time challenge;
3. load signing secrets through application configuration;
4. call `generateProfile`;
5. send `result.value.data` with `result.value.contentType`.

Your callback route should:

1. enforce a transport-level body limit no larger than the library limit;
2. keep the raw body as `Uint8Array`;
3. retrieve the expected challenge and trust policy;
4. call `parseProfileServiceResponse`;
5. authorize the device and consume the challenge atomically;
6. store only required identifiers under an appropriate retention policy.

Map typed codes to sanitized HTTP responses. Do not return crypto/parser details to the device and do not log secret material or complete device payloads.

The core deliberately does not prescribe environment schemas, middleware, request objects, response objects, databases, or logger interfaces. That is what keeps the same protocol implementation usable across applications.
