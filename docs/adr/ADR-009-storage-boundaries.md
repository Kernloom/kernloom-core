# ADR-009: Storage Boundaries

## Status

Accepted.

## Decision

Postgres stores metadata and state, Redis handles jobs/events/cache, and ArtifactStore supports fs plus MinIO/S3-compatible storage.

## Consequences

Redis is never source of truth, and artifacts are immutable and content-addressed.

