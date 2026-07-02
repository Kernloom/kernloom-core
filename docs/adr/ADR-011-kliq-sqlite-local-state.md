# ADR-011: KLIQ SQLite Local State

## Status

Accepted.

## Decision

KLIQ uses SQLite local state for recovery and standalone mode.

## Consequences

KLIQ stores last valid bundles, action leases, journals, audit spool, baseline metadata, relationships and adapter health cache locally.

