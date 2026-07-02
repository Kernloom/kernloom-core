# Architecture Decision Records

These ADRs are fixed implementation-start decisions from the Kernloom v1 build contract. Changes require an explicit follow-up ADR.

| ADR | Decision |
| --- | --- |
| ADR-001 | Core implementation language is Go. |
| ADR-002 | GitHub namespace is `github.com/kernloom`. |
| ADR-003 | Core repo is `kernloom-core`; Forge and KLIQ are commands/modules inside it. |
| ADR-004 | Adapter protocol v1 is gRPC-only. |
| ADR-005 | CEL is the v1 expression engine. |
| ADR-006 | Git/PR is the authority for approved policy meaning. |
| ADR-007 | No direct production config apply by Kernloom. |
| ADR-008 | Runtime Actions require TTL, scope, reason, audit ID, source commit and signed bundle. |
| ADR-009 | Postgres is metadata/state store; Redis is jobs/events/cache; ArtifactStore is fs + MinIO/S3-compatible. |
| ADR-010 | Reality Graph is modeled as a graph from day one, v1 Postgres-backed. |
| ADR-011 | KLIQ uses SQLite local state for recovery and standalone mode. |
| ADR-012 | KLShield is a separate PEP/Data Plane; KLShield adapter writes BPF maps. |
| ADR-013 | OpenZiti and KLShield are the first official adapters. |
| ADR-014 | Notification plugins v1 are stdout/dev, webhook and email/SMTP. |
| ADR-015 | Artifact signing uses DSSE-style envelopes with Ed25519 for Kernloom artifacts. |
| ADR-016 | Issuance PDP is a gate; Issuer/Signer creates proof artifacts. |
| ADR-017 | Kernloom is attestation-ready but does not hard-code Keylime. |
| ADR-018 | Detailed admin docs are gitignored; admin templates are versioned. |

