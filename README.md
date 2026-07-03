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
podman compose -f docker-compose.dev.yml up -d redis
make build

./bin/forge api --addr :8080 --queue redis --redis-addr 127.0.0.1:6379
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

The API also accepts signed JWTs with OIDC/OAuth2-style claims when started with `--oidc-hmac-secret`; the dev token provider can be disabled with `--dev-tokens=false`.

## KLIQ Local Runtime Lifecycle

Slice 5.5 makes KLIQ runtime execution multi-adapter-safe. Slice 5.6 adds the real KLShield BPF backend on the adapter side. KLIQ loads a signed RuntimeBundle, builds a RuntimeActionPlan, creates adapter-specific leases and executes each supported PlannedRuntimeAction through an AdapterRuntimeRegistry. The lease and idempotency model no longer assumes one RuntimeDecision equals one adapter action.

```sh
make build

./bin/kliq load-bundle \
  --bundle ../enterprise-kernloom-policies/generated/signed/runtime.mitigate-abnormal-source-behavior.runtime_bundle.signed.json \
  --key ../enterprise-kernloom-policies/generated/keys/dev-local.ed25519.json \
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
  --key ../enterprise-kernloom-policies/generated/keys/dev-local.ed25519.json \
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
  --key ../enterprise-kernloom-policies/generated/keys/dev-local.ed25519.json \
  --state /tmp/kernloom-kliq-runtime/state.db \
  --adapter-id kernloom.adapter.klshield \
  --adapter-addr 127.0.0.1:18082
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
