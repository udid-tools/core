# ADR 0002: Result-first public API

- Status: Accepted
- Date: 2026-08-22

## Context

Device responses, certificate containers, and application configuration can fail in expected ways. An uncaught parser or crypto exception should not unexpectedly terminate a request path, while some developers still prefer exception-based control flow.

## Decision

Normal public operations return `Promise<Result<T>>` with stable typed errors and success warnings. Any unknown internal exception is converted to a sanitized `INTERNAL_ERROR`. Exception-based variants are provided only with an `OrThrow` suffix.

Keep generation asynchronous at the public boundary even when the beta implementation is CPU-synchronous, allowing future provider-based signing without a return-type break.

## Consequences

The safe path is obvious and resilient. Consumers must branch on `ok`, and throwing behavior remains available without ambiguity. Error codes, rather than message strings, form the compatibility contract.
