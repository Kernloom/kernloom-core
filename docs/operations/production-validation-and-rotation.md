# Production Validation, Bootstrap And Rotation

## Forge Production Startup

Production Forge must start with explicit trust roots and RS256 OIDC verification:

```bash
forge api \
  --production \
  --addr :8443 \
  --tls-cert /etc/kernloom/tls/forge.crt \
  --tls-key /etc/kernloom/tls/forge.key \
  --client-ca /etc/kernloom/tls/client-ca.crt \
  --queue redis \
  --redis-addr redis:6379 \
  --management-store postgres \
  --management-postgres-dsn "$KERNLOOM_MANAGEMENT_DSN" \
  --management-signer-url https://forge-signer.internal/sign \
  --management-signer-key-id forge-management-2026 \
  --management-signer-ca /etc/kernloom/tls/signer-ca.crt \
  --management-signer-client-cert /etc/kernloom/tls/forge-signer-client.crt \
  --management-signer-client-key /etc/kernloom/tls/forge-signer-client.key \
  --management-signer-cert-sha256 "$SIGNER_CERT_SHA256" \
  --artifact-store-env prod \
  --bootstrap-config /etc/kernloom/bootstrap-root.yaml \
  --context-bindings /etc/kernloom/context-bindings.yaml \
  --oidc-issuer https://idp.example.org \
  --oidc-audience kernloom-forge \
  --oidc-jwks-url https://idp.example.org/.well-known/jwks.json \
  --oidc-jwks-refresh-interval 10m \
  --oidc-jwks-min-refresh-interval 30s \
  --policy-repo /srv/kernloom/enterprise-kernloom-policies \
  --core-registry /srv/kernloom/kernloom-core-registry \
  --enterprise-registry /srv/kernloom/enterprise-kernloom-registry
```

Fail-closed startup gates include missing TLS, dev tokens, HS256/HMAC OIDC, missing bootstrap root, missing context bindings, memory management store and local signer seeding.

JWKS is loaded fail-closed during startup, then refreshed periodically. A token signed with an unknown `kid` triggers a bounded immediate refresh, so normal OIDC signing-key rotation does not require a Forge restart. If refresh fails, Forge keeps the last valid JWKS for existing trusted keys and rejects unknown keys.

## Central Validation PDP

Target config CI should call Forge through `klctl validate ci --forge-url`:

```bash
klctl validate ci \
  --forge-url https://forge.example.org \
  --tenant kernloom-demo \
  --environment prod \
  --provider github \
  --repo "$GITHUB_REPOSITORY" \
  --commit "$GITHUB_SHA" \
  --pull-request "$PR_NUMBER" \
  --base-path envs/prod
```

The reusable GitHub workflow is `.github/workflows/validate-target-config.yml` and expects a `kernloom_validation_token` secret.

## Baseline Promotion

Live learning must not directly influence enforcement. Promote only a frozen baseline version after approval:

```bash
klctl baseline promote \
  --state-db /var/lib/kernloom/kliq/state.db \
  --version-id baseline_version.example \
  --approved-by alice@example.org \
  --reason "Clean seven-day prod window reviewed in change CHG-1234"
```

Reject a candidate:

```bash
klctl baseline promote \
  --state-db /var/lib/kernloom/kliq/state.db \
  --version-id baseline_version.example \
  --action reject \
  --approved-by alice@example.org \
  --reason "Window contains known incident traffic"
```

## Trust Bundle Rotation

Prepare the next public trust bundle as JSON:

```json
{
  "key_id": "forge-management-2026-q4",
  "public_key": "BASE64_ED25519_PUBLIC_KEY",
  "purpose": "assignment_verification",
  "status": "active",
  "expires_at": "2027-01-01T00:00:00Z",
  "issuer": "forge-signer"
}
```

Rotate:

```bash
klctl trust-bundle rotate \
  --forge-url https://forge.example.org \
  --token-file /run/secrets/kernloom-operator-token \
  --key-id forge-management-2026-q3 \
  --next-file next-trust-bundle.json \
  --reason "Scheduled quarterly signer rotation"
```

Revoke:

```bash
klctl trust-bundle revoke \
  --forge-url https://forge.example.org \
  --token-file /run/secrets/kernloom-operator-token \
  --key-id forge-management-2026-q2 \
  --reason "Retired after successful rotation"
```
