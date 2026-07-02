# ADR-015: Artifact Signing

## Status

Accepted.

## Decision

Kernloom JSON artifacts use DSSE-style signed envelopes with Ed25519 by default.

## Consequences

Runtime bundles, resolved policies, grant projections and related artifacts carry payload hash, key ID, source commit, policy ID and expiry where applicable.

