# Adapter Runtime Verify Runbook

`klctl adapter verify` proves that a running adapter binary matches the approved adapter manifest before CI or production rollout trusts it.

## Adapter manifest digest

Adapters must report the digest of the exact manifest that was approved for deployment.

For the official adapters, pass the digest at process start:

```sh
KERNLOOM_ADAPTER_MANIFEST_DIGEST=sha256:<manifest-sha256> \
  kernloom-adapter-klshield serve ...
```

The same value is accepted as `--manifest-digest`. Operators should compute the digest from the released `adapter.manifest.yaml` artifact and store it with the deployment metadata.

## Manual verification

Development or smoke checks may use plaintext transport only on local endpoints:

```sh
bin/klctl adapter verify \
  --adapter kernloom.adapter.klshield \
  --endpoint 127.0.0.1:18082 \
  --manifest /opt/kernloom/adapters/klshield/adapter.manifest.yaml \
  --dev-insecure-transport
```

Production checks must use mTLS and a leaf certificate pin:

```sh
bin/klctl adapter verify \
  --adapter kernloom.adapter.klshield \
  --endpoint klshield-adapter.prod.example:443 \
  --manifest /opt/kernloom/adapters/klshield/adapter.manifest.yaml \
  --adapter-ca /etc/kernloom/adapter-ca.pem \
  --adapter-client-cert /etc/kernloom/klctl-client.pem \
  --adapter-client-key /etc/kernloom/klctl-client-key.pem \
  --adapter-server-name klshield-adapter.prod.example \
  --adapter-server-cert-sha256 sha256:<leaf-cert-sha256>
```

The command fails closed when the endpoint is unavailable, TLS material is incomplete, the certificate pin mismatches, the adapter omits `manifest_digest`, or Describe reports a different protocol version, capability, runtime action, privilege or manifest digest than the manifest declares.

## CI and production gates

CI may optionally verify a staging adapter by setting repository variables:

- `KERNLOOM_CI_ADAPTER_VERIFY_ID`
- `KERNLOOM_CI_ADAPTER_VERIFY_ENDPOINT`
- `KERNLOOM_CI_ADAPTER_VERIFY_MANIFEST`

Production readiness should call:

```sh
bin/klctl production check \
  --core-repo /srv/kernloom-core \
  --adapter-verify-adapter kernloom.adapter.klshield \
  --adapter-verify-endpoint klshield-adapter.prod.example:443 \
  --adapter-verify-manifest /opt/kernloom/adapters/klshield/adapter.manifest.yaml \
  --adapter-verify-ca /etc/kernloom/adapter-ca.pem \
  --adapter-verify-client-cert /etc/kernloom/klctl-client.pem \
  --adapter-verify-client-key /etc/kernloom/klctl-client-key.pem \
  --adapter-verify-server-name klshield-adapter.prod.example \
  --adapter-verify-server-cert-sha256 sha256:<leaf-cert-sha256>
```

Production check rejects `--adapter-verify-dev-insecure-transport` and rejects adapter runtime verification without `--adapter-verify-server-cert-sha256`.

## Operator response

- `adapter_transport_invalid`: fix CA/client cert/client key flags or use dev-insecure only for local smoke.
- `adapter_describe_failed`: check network, mTLS trust, certificate pin and adapter health.
- `adapter_runtime_verify_failed`: do not deploy; compare the running adapter binary, `adapter.manifest.yaml`, `manifest_digest`, capabilities, actions, privileges and protocol version.
- `adapter_manifest_mismatch`: the requested adapter ID and manifest do not describe the same adapter.
- `adapter_runtime_cert_pin_missing`: production gate is intentionally fail-closed; add the approved leaf certificate SHA-256 pin.
