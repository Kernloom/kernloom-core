# ADR-012: KLShield PEP Boundary

## Status

Accepted.

## Decision

KLShield remains a separate PEP/Data Plane. The KLShield adapter writes BPF maps; KLIQ owns policy decisions and leases.

## Consequences

KLIQ must not hard-code KLShield internals.

