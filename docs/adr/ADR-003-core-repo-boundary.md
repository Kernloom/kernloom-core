# ADR-003: Core Repo Boundary

## Status

Accepted.

## Decision

`kernloom-core` contains Forge and KLIQ as separate commands/modules. v1 does not create `kernloom-forge` or `kernloom-kliq` repositories.

## Consequences

Canonical objects such as `ResolvedPolicy`, `RuntimeBundle`, `RiskSignal`, `CapabilityGrant`, `Evidence` and `ConformanceStatus` stay semantically consistent.

