# ADR-010: Reality Graph from Day One

## Status

Accepted.

## Decision

Reality is modeled as a graph from day one and stored in Postgres-backed graph tables for v1.

## Consequences

The domain model must preserve nodes and edges rather than drifting into unrelated flat tables.

