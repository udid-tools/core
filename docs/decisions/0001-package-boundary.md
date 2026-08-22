# ADR 0001: Package boundary and MDM exclusion

- Status: Accepted
- Date: 2026-08-22

## Context

The original site couples Apple Profile Service profile creation, signing, and response parsing to web routes and application configuration. The same protocol core should be reusable by other Node.js applications. MDM is related but has substantially different enrollment, push, command, state, security, and operational responsibilities.

## Decision

Create `@udid-tools/core` as a framework-agnostic Node.js TypeScript package covering only Apple Profile Service profile generation, optional signing, CMS response verification, and plist response parsing. It exposes no HTTP server, persistence, UI, application configuration, SCEP orchestration, or MDM behavior.

If MDM work begins, place it in a separate package such as `@udid-tools/mdm` and reuse promoted low-level primitives through an explicit reviewed API.

## Consequences

The current website can become a thin adapter. Consumers choose their framework and infrastructure. Core remains easier to audit. MDM can evolve without forcing unrelated major changes or dependencies into Profile Service consumers.
