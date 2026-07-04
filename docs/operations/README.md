# Operations Guide

Operations runbooks must cover Forge API, workers, KLIQ local state, Correlate, Proof Issuer, conformance workers, Postgres, Redis and ArtifactStore. Unknown conformance is never success.

For managed runtime, operate KLIQ as a long-running `kliq run --mode managed` daemon. The manual KLIQ commands are debug/admin/smoke tools and are not the production assignment path.

Managed KLIQ service identity is SPIFFE/SPIRE-ready. The current local signed service token is an explicit dev/local credential transport; registrations and local state still bind provider, SPIFFE ID, public key material, environment, stage and scope so production can move to SPIFFE SVID or mTLS without changing assignment semantics.

KLIQ activates assigned artifacts atomically. `RuntimeBundle`, `AdapterAssignment`, `ContextRoutePack`, `TrustBundle`, `FallbackProfile`, `ManagementProfile` and `ConformanceExpectation` are validated before the active assignment pointer moves. `ManagementProfile` controls daemon polling, heartbeat, status, decision, reconcile and audit flush intervals. Active `ContextRoutePack`, `FallbackProfile` and `ConformanceExpectation` artifacts are consumed by the runtime path as local enforcement/evidence hooks.

Forge production startup must not silently seed management trust. Provision the management TrustBundle before API startup, or use `--dev-seed-management-trust` only for local smoke tests. Apply management database migrations explicitly with `forge migrate --management-postgres-dsn ...` during deployment.

Production assignment planning requires a signed `PolicyBuildManifest` envelope from the ArtifactStore. The manifest approval must include authority metadata and environment/stage/scope bindings that match the KLIQ registration.

Release pipelines must run formatting, vetting, tests, builds, checksums, SBOM generation, vulnerability scans, provenance generation and signing. Local hooks are `make release-check`, `make sbom`, `make vuln-scan`, `make checksums`, `make release-provenance`, `make release-sign` and `make container-sign IMAGE=...`.
