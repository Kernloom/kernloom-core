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
