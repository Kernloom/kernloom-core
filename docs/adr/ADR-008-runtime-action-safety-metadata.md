# ADR-008: Runtime Actions Require Safety Metadata

## Status

Accepted.

## Decision

Runtime Actions require TTL, scope, reason, audit ID, source commit, approved grant and signed bundle.

## Consequences

KLIQ must reject runtime actions that lack required safety metadata or evidence path.

