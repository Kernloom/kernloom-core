# kernloom-core

`kernloom-core` is the Go implementation repository for Forge, KLIQ, Correlate, Proof Issuer, Forge Console API, Conformance, workers, storage, CLI and shared core domain objects.

Forge and KLIQ are separate binaries and modules inside this repository. They are not separate repositories in v1.

## Build

```sh
make build
```

## Test

```sh
make test
```

## Compile KNI

```sh
make build
./bin/forge compile \
  --policy-repo ../enterprise-kernloom-policies \
  --core-registry ../kernloom-core-registry \
  --enterprise-registry ../enterprise-kernloom-registry
```

## Forge API and Jobs

Slice 2 adds an authenticated Forge API and an async simulation job shell. Start the dev services first, then run the API and worker against Redis:

```sh
podman compose -f docker-compose.dev.yml up -d postgres redis
make build

./bin/forge api \
  --addr :8080 \
  --queue redis \
  --redis-addr 127.0.0.1:6379 \
  --management-store postgres \
  --management-postgres-dsn 'postgres://kernloom:kernloom-dev-password@127.0.0.1:5432/kernloom?sslmode=disable' \
  --kliq-service-token-secret 'dev-kliq-service-token-secret' \
  --dev-tokens
```

Dev bearer tokens use this local format:

```text
dev:<subject>:<comma-separated-roles>:<org>:<environment>:<stage>
```

Example submit/read flow:

```sh
TOKEN='dev:alice:policy-author:acme:dev:prod'

curl -sS -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"policy_file":"../enterprise-kernloom-policies/policies/delegation/ziti-readonly-observation.intent.kni","scope":{"org":"acme","stage":"prod"}}' \
  http://127.0.0.1:8080/v1/simulation-jobs

./bin/forge-worker run-once --queue redis --redis-addr 127.0.0.1:6379
```

The API also accepts signed JWTs with OIDC/OAuth2-style claims when started with `--oidc-hmac-secret`; the local dev token provider is opt-in with `--dev-tokens`.

## Managed KLIQ Assignments

Slice 5.9 hardens the Forge-managed KLIQ control plane. The production path uses
a persistent Postgres management store, hashed single-use enrollment tokens,
bound KLIQ identity material, signed assignments, KLIQ service authentication,
revocation state and management audit events. The in-memory store and manual
assignment endpoint are dev/smoke-test only and require `--dev-management`.

For a throwaway smoke test without Postgres, start Forge explicitly in dev mode:

```sh
./bin/forge api \
  --addr :8080 \
  --queue memory \
  --management-store memory \
  --dev-management \
  --kliq-service-token-secret 'dev-kliq-service-token-secret' \
  --dev-tokens
```

```sh
OPERATOR_TOKEN='dev:ops:operator:acme:prod:prod'

curl -sS -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"environment":"prod","stage":"prod","scope":"edge-prod"}' \
  http://127.0.0.1:8080/v1/kliq/enrollment-tokens

curl -sS -H 'Content-Type: application/json' \
  -d '{"enrollment_token":"<secret_token>","node_id":"node-1","environment":"prod","stage":"prod","scope":"edge-prod","version":"dev","trust_key_id":"forge-management-dev-local","public_key_pem":"-----BEGIN PUBLIC KEY-----dev-----END PUBLIC KEY-----","adapter_inventory":["kernloom.adapter.klshield"],"capabilities":["klshield.runtime.source_mitigation"]}' \
  http://127.0.0.1:8080/v1/kliq/enroll
```

Use the returned `registration.kliq_id` and `service_token`. Assignments are
planned by Forge from the KLIQ registration and approved artifacts; arbitrary
manual assignment JSON is no longer a production endpoint.

```sh
curl -sS -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"kliq_id":"<kliq_id>","source_commit":"<source_commit>","approved_build_ref":{"uri":"fs:///var/lib/kernloom/artifacts/.../policy_build_manifest.approved.json","sha256":"sha256:<approved-build-manifest-digest>"},"expires_at":"2026-07-03T23:59:59Z","artifacts":[{"artifact_type":"runtime_bundle","artifact_id":"runtime_bundle.manual","artifact_ref":"fs:///var/lib/kernloom/artifacts/.../runtime_bundle.signed.json","sha256":"sha256:<signed-artifact-digest>"}]}' \
  http://127.0.0.1:8080/v1/kliq/assignments
```

KLIQ pulls its assignment with its own service identity, not the operator token.
It verifies the signed assignment and embedded RuntimeBundle artifact locally
before activation:

```sh
./bin/kliq load-managed-bundle \
  --assignment-url http://127.0.0.1:8080 \
  --bearer-token "<service_token>" \
  --kliq-id "<kliq_id>" \
  --environment prod \
  --stage prod \
  --scope edge-prod \
  --trust-key-id forge-management-dev-local \
  --trust-bundle /etc/kernloom/trust/forge-management.public.json \
  --state /tmp/kernloom-kliq-runtime/state.db
```

Standalone local bundle loading remains available through `kliq load-bundle`.

## KLIQ Local Runtime Lifecycle

Slice 5.5 makes KLIQ runtime execution multi-adapter-safe. Slice 5.6 adds the real KLShield BPF backend on the adapter side. KLIQ loads a signed RuntimeBundle, builds a RuntimeActionPlan, creates adapter-specific leases and executes each supported PlannedRuntimeAction through an AdapterRuntimeRegistry. The lease and idempotency model no longer assumes one RuntimeDecision equals one adapter action.

```sh
make build

./bin/kliq load-bundle \
  --bundle ../enterprise-kernloom-policies/generated/signed/runtime.mitigate-abnormal-source-behavior.runtime_bundle.signed.json \
  --trust-bundle ../enterprise-kernloom-policies/generated/keys/dev-local.ed25519.json \
  --dev-allow-private-trust-key \
  --state /tmp/kernloom-kliq-runtime/state.db
```

Run the KLShield adapter with the default memory runtime store:

```sh
cd ../kernloom-adapter-klshield
make build
./bin/kernloom-adapter-klshield serve --addr 127.0.0.1:18082
```

On a Linux lab host where `kernloom-shield` has loaded and pinned its maps, use
the real KLShield BPF backend instead:

```sh
sudo ./bin/kernloom-adapter-klshield serve \
  --addr 127.0.0.1:18082 \
  --runtime-store bpf \
  --bpffs-root /sys/fs/bpf \
  --default-rate-pps 1000 \
  --default-burst 2000
```

Then execute an IPv4 source action through KLIQ:

```sh
cd ../kernloom-core
./bin/kliq execute-action \
  --trust-bundle ../enterprise-kernloom-policies/generated/keys/dev-local.ed25519.json \
  --dev-allow-private-trust-key \
  --state /tmp/kernloom-kliq-runtime/state.db \
  --adapter-id kernloom.adapter.klshield \
  --adapter-addr 127.0.0.1:18082 \
  --capability-id klshield.runtime.source_mitigation \
  --capability-grant-id grant.local.klshield.runtime.source_mitigation \
  --decision-id decision.slice5_6.local \
  --action-type runtime_action.rate_limit_source \
  --target-scope source \
  --target-key 192.0.2.10 \
  --ttl 30s \
  --reason "slice 5.6 adapter-backed smoke decision" \
  --audit-id audit.slice5_6.local

./bin/kliq reconcile \
  --trust-bundle ../enterprise-kernloom-policies/generated/keys/dev-local.ed25519.json \
  --dev-allow-private-trust-key \
  --state /tmp/kernloom-kliq-runtime/state.db \
  --adapter-id kernloom.adapter.klshield \
  --adapter-addr 127.0.0.1:18082
```

Inspect local KLIQ runtime state without exposing raw targets, audit payloads or
signed bundle payloads:

```sh
./bin/kliq status --state /tmp/kernloom-kliq-runtime/state.db
./bin/kliq bundle status --state /tmp/kernloom-kliq-runtime/state.db
./bin/kliq adapters status --state /tmp/kernloom-kliq-runtime/state.db
./bin/kliq runtime actions --state /tmp/kernloom-kliq-runtime/state.db
./bin/kliq runtime journal \
  --state /tmp/kernloom-kliq-runtime/state.db \
  --action-id runtime_action.example
./bin/kliq audit pending --state /tmp/kernloom-kliq-runtime/state.db
./bin/kliq reconcile --state /tmp/kernloom-kliq-runtime/state.db --dry-run
```

The local read-only status API is loopback-only by default:

```sh
./bin/kliq status-api \
  --state /tmp/kernloom-kliq-runtime/state.db \
  --listen 127.0.0.1:18090

curl -sS http://127.0.0.1:18090/status
curl -sS http://127.0.0.1:18090/runtime/actions
curl -sS http://127.0.0.1:18090/audit/pending
```

## Dev Services

```sh
podman compose -f docker-compose.dev.yml up -d
```

## Release

Release pipelines must run formatting, vetting, linting, unit tests, integration tests, binary builds, container builds and release signing before publishing artifacts.

## Dependencies

Slice 0 uses Go 1.26.4 and only the Go standard library. Later slices add Postgres, Redis, ArtifactStore, CEL, signing and API dependencies within the architecture slots defined in the implementation guide.

## Related Repos

`kernloom-protocol` owns gRPC adapter protocol definitions. Registry and policy repos provide controlled authoring inputs that Forge compiles into signed artifacts consumed by KLIQ and other PDPs.

## ADRs

Implementation-start ADRs are recorded in `docs/adr/`.
