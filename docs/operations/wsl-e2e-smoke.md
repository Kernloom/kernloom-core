# WSL E2E Smoke And Evidence Bundle

This is a local smoke run you can replay on WSL before building the full lab. It proves the current Kernloom repositories can build `klctl`, validate the registries and policy graph, and produce an evidence bundle.

It does not replace the three-node production lab with live KLShield enforcement and traffic evidence.

## Prerequisites

From the shared workspace:

```bash
cd ~/prj/kernloom
git -C kernloom-core status --short
git -C kernloom-core-registry status --short
git -C enterprise-kernloom-registry status --short
git -C enterprise-kernloom-policies status --short
```

Expected: no unrelated local changes you do not want in the evidence run.

Build the CLI:

```bash
cd ~/prj/kernloom/kernloom-core
make build
bin/klctl
```

## Create a local lab inventory

```bash
mkdir -p ~/prj/kernloom/lab-local
cat > ~/prj/kernloom/lab-local/inventory.yaml <<'YAML'
lab:
  name: kernloom-wsl-smoke
  owner: local-operator
control_plane:
  host: wsl
  mgmt_ip: 127.0.0.1
  ubuntu_version: local
  kernel: local
protected_node:
  host: wsl
  mgmt_ip: 127.0.0.1
  data_iface: lo
traffic_generator:
  host: wsl
  mgmt_ip: 127.0.0.1
networks:
  mgmt_cidr: 127.0.0.0/8
  data_cidr: 127.0.0.0/8
  mtu: 1500
  direct_25g_link: false
certificates:
  ca_mode: local-smoke
  forge_server_name: forge.local
  adapter_server_name: klshield-adapter.local
YAML
```

## Run registry and CI validation

```bash
cd ~/prj/kernloom/kernloom-core

bin/klctl registry validate \
  --core-registry ../kernloom-core-registry \
  --enterprise-registry ../enterprise-kernloom-registry

bin/klctl validate ci \
  --tenant kernloom-demo \
  --environment prod \
  --provider github \
  --repo kernloom-demo/klshield-config \
  --base-path envs/prod \
  --target-id klshield-prod \
  --policy-repo ../enterprise-kernloom-policies \
  --core-registry ../kernloom-core-registry \
  --enterprise-registry ../enterprise-kernloom-registry \
  --output text
```

Expected: both commands pass. If `validate ci` fails, fix that before running the lab bundle.

## Produce the evidence bundle

```bash
cd ~/prj/kernloom/kernloom-core

bin/klctl lab e2e \
  --inventory ../lab-local/inventory.yaml \
  --evidence-dir ../lab-local/evidence \
  --tenant kernloom-demo \
  --environment prod \
  --provider github \
  --repo kernloom-demo/klshield-config \
  --base-path envs/prod \
  --target-id klshield-prod \
  --policy-repo ../enterprise-kernloom-policies \
  --core-registry ../kernloom-core-registry \
  --enterprise-registry ../enterprise-kernloom-registry \
  --output text
```

Expected files:

```text
~/prj/kernloom/lab-local/evidence/
  inventory.yaml
  registry-validation.json
  ci-validation.json
  checksums.txt
  evidence-bundle.json
```

Check the bundle:

```bash
jq .status ~/prj/kernloom/lab-local/evidence/evidence-bundle.json
cd ~/prj/kernloom/lab-local/evidence
sha256sum -c checksums.txt
```

## Optional live adapter gate

When a KLShield adapter is running, add adapter verification to the CI and lab commands:

```bash
bin/klctl adapter verify \
  --adapter kernloom.adapter.klshield \
  --endpoint "$ADAPTER_ENDPOINT" \
  --manifest ../kernloom-adapter-klshield/adapter.manifest.yaml \
  --adapter-ca "$ADAPTER_CA" \
  --adapter-client-cert "$ADAPTER_CLIENT_CERT" \
  --adapter-client-key "$ADAPTER_CLIENT_KEY" \
  --adapter-server-cert-sha256 "$ADAPTER_SERVER_CERT_SHA256"
```

Then pass the same values into `validate ci` or `lab e2e` with the `--adapter-verify-*` flags. Without `--adapter-verify-dev-insecure-transport`, adapter verification is fail-closed on TLS/mTLS and certificate pin errors.

## What This Proves

- `klctl` builds and runs.
- Core and enterprise registries load and validate.
- CI validation resolves repository binding, target inventory, action bindings, adapter manifests and policy meaning.
- The evidence bundle records the inventory, validation result and checksums.

## What Still Needs The Full Integration Lab

- Forge API with production TLS/mTLS, OIDC/JWKS and context bindings.
- Enrollment, signed ApprovedBuild, signed assignment and KLIQ activation.
- Live KLShield action, BPF readback, TTL cleanup and audit upload.
- Negative transport, wrong-adapter and stale-risk tests.
