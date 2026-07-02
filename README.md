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
