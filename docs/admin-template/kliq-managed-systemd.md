# KLIQ Managed Systemd Template

`kliq run` is the production managed path. Manual commands such as `kliq load-managed-bundle`, `kliq execute-action` and `kliq reconcile` are admin/debug/smoke tools.

Example managed service command:

```sh
kliq run \
  --mode managed \
  --forge-url https://forge.example.internal \
  --state /var/lib/kernloom/kliq/state.db \
  --trust-bundle /etc/kernloom/trust/forge-management.public.json \
  --adapter-ca /etc/kernloom/adapter/ca.pem \
  --adapter-client-cert /etc/kernloom/kliq/adapter-client.crt \
  --adapter-client-key /etc/kernloom/kliq/adapter-client.key \
  --status-listen 127.0.0.1:18090
```

Operational defaults for this slice:

- Assignment polling uses the local KLIQ service identity created by enrollment.
- KLIQ verifies Forge-managed assignments with public trust material only.
- Forge startup does not silently replace, rotate or extend existing trust bundles.
- Production assignment planning requires an approved PolicyBuildManifest binding.
- The local KLIQ SQLite state database must not be group/world accessible; KLIQ creates it with `0600`.
- A newer assignment is verified and staged before the active assignment pointer changes.
- All assigned artifacts are verified and staged with explicit activation status; RuntimeBundle and AdapterAssignment are the first active consumers in this slice.
- `adapter_assignment` artifacts can provide managed adapter endpoints. `--adapter` remains a dev/bootstrap override.
- Adapter gRPC uses authenticated transport by default. Local plaintext adapter
  smoke tests require explicit `--dev-insecure-adapter-transport`.
- `--decision-source file://...` is a local skeleton for future runtime decision delivery; manual `execute-action` remains debug/smoke only.
- Plaintext Forge HTTP is rejected by default. Local smoke tests must pass
  `--dev-insecure-forge-transport`.
- If Forge is unavailable, KLIQ keeps the last valid active assignment until it expires.
- Expired runtime actions are reconciled even when assignment polling is degraded.
- New runtime actions require a valid cached bundle and, in managed mode, a non-expired active assignment.
- The local status API must bind to localhost or another loopback address.
- Status responses redact target keys, idempotency keys, bundle source paths and long identifiers.
- Audit upload posts pending local audit records to Forge and keeps failed uploads spooled with retry metadata.

Environment file example for `/etc/kernloom/kliq.env`:

```sh
KERNLOOM_FORGE_URL=https://forge.example.internal
KERNLOOM_KLIQ_STATE=/var/lib/kernloom/kliq/state.db
KERNLOOM_KLIQ_STATUS_LISTEN=127.0.0.1:18090
KERNLOOM_TRUST_BUNDLE=/etc/kernloom/trust/forge-management.public.json
KERNLOOM_ADAPTER_CA=/etc/kernloom/adapter/ca.pem
KERNLOOM_ADAPTER_CLIENT_CERT=/etc/kernloom/kliq/adapter-client.crt
KERNLOOM_ADAPTER_CLIENT_KEY=/etc/kernloom/kliq/adapter-client.key
```

The environment file must not contain enrollment tokens, operator tokens, private keys or proof payloads. KLIQ stores its local service credential in the SQLite state database during `kliq enroll`; protect that database with host-level file permissions.
