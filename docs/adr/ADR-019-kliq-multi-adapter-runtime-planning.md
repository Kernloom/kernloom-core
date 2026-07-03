# ADR-019: KLIQ Multi-Adapter Runtime Planning

## Status

Accepted.

## Decision

KLIQ models runtime execution as `RuntimeDecision -> RuntimeActionPlan -> PlannedRuntimeAction[]`.

Each adapter-specific planned action receives its own lease, idempotency key,
TTL, evidence and reconciliation status. Runtime action leases and idempotency
keys include `adapter_id` and `capability_id`.

## Consequences

KLIQ no longer assumes that one runtime decision maps to one adapter call.
Slice 5.5 may still execute only one required adapter-backed action, but all
execution goes through a `RuntimeActionPlan` and an `AdapterRuntimeRegistry`.

Reconciliation groups leases by `adapter_id`; a missing or unreachable adapter
does not block reconciliation for other adapters.
