# ADR-004: Adapter Protocol v1 Is gRPC-Only

## Status

Accepted.

## Decision

Adapters are out-of-process gRPC plugins for v1.

## Consequences

Core must not implement in-process language-specific adapter plugins.

