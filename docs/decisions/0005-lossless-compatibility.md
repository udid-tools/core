# ADR 0005: Lossless Apple compatibility

- Status: Accepted
- Date: 2026-08-22

## Context

Apple may add fields, and deployed platform behavior can outpace archived Profile Service documentation. Modeling only current normalized properties would discard data and turn additive platform changes into library major releases.

## Decision

Type all Apple-documented Profile Service fields and plist value kinds. Provide deliberate extension dictionaries for request fields, a branded helper for custom requested attributes, and preserve the complete decoded response dictionary in `raw`. Normalize known response attributes additively.

Reserve generated keys against extension overrides and validate all extension data through the bounded plist codec.

## Consequences

Consumers receive ergonomic known fields and retain future data. Adding a newly documented field is generally backward-compatible. Extensions remain explicit and cannot undermine required payload structure.
