# PG-14 to PG-16 PR Slices

Use these slices for review. They are intentionally ordered so later PRs build on earlier supply-chain primitives.

## PR 1: `klctl` and Adapter Runtime Verify

Scope:

- `cmd/klctl`, `internal/ctl`, `cmd/kernloomctl` compatibility shim.
- Protocol `AdapterDescriptor.manifest_digest`.
- Runtime action request provenance fields in adapter protocol.
- `internal/forge/adapterverify`.
- Adapter Describe changes in KLShield and Ziti.
- `klctl adapter verify` mTLS, client cert and server certificate pin flags.
- CI/release workflow references to `bin/klctl`.

Review focus:

- Fail-closed adapter verification behavior.
- mTLS defaults and dev-insecure escape hatch.
- Protocol compatibility and generated SDK updates.

## PR 2: PG-15 Runtime Provenance

Scope:

- RuntimeBundle capability grant provenance: `binding_id`, `binding_digest`, `adapter_manifest_digest`, `action_digest`.
- KLIQ runtime planning, leases, adapter executor gRPC requests, SQLite schema, audit spool and status views.
- Runtime/audit tests that prove provenance flows into leases, adapter calls and local audit records.

Review focus:

- No provenance loss between approved build, RuntimeBundle, KLIQ lease, adapter request and audit spool.
- SQLite migrations remain additive.

## PR 3: PG-16 ApprovedBuild Source Hardening

Scope:

- `federated_source_digests` in PolicyBuildManifest.
- Signed adapter manifest artifacts.
- Adapter refs containing signed manifest artifact refs.
- ApprovedBuild validation requiring source digest consistency and signed adapter manifest refs.
- Assignment planning requiring a RuntimeBundle and its adapter manifest artifact pair from the same ApprovedBuild.
- Operator runbook for adapter runtime verify.

Review focus:

- ApprovedBuild cannot authorize a RuntimeBundle without the matching signed adapter manifest artifact.
- Assignment artifacts are signed envelopes, source-commit matched and approved-build bounded.
- CI and production checks match operator expectations.
