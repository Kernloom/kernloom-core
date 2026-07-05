# Managed KLIQ KLShield Getting Started

This guide runs the smallest useful end-to-end path:

1. authoring policy intent already exists in `enterprise-kernloom-policies`
2. Forge compiles and signs artifacts
3. Forge API approves the build manifest and plans a managed KLIQ assignment
4. KLIQ enrolls, pulls the assignment and executes one runtime decision
5. the KLShield adapter applies the action

The default flow below uses dev-local HTTP, dev tokens and the adapter memory
runtime store. That proves the control path without requiring root or BPF maps.
For real KLShield kernel enforcement, use the BPF adapter command in the final
section.

## Prerequisites

Run from the workspace root:

```sh
export KERNLOOM_HOME="$PWD"
podman compose -f docker-compose.dev.yml up -d postgres

(cd kernloom-core && make build)
(cd kernloom-adapter-klshield && make build)
```

Set shared variables:

```sh
cd "$KERNLOOM_HOME"

export WORK=/tmp/kernloom-getting-started
export STATE="$WORK/kliq-state.db"
export MANAGEMENT_KEY="$WORK/forge-management.ed25519.json"
export POLICY_ID="runtime.mitigate-abnormal-source-behavior"
export OPERATOR_TOKEN="dev:ops:operator:acme:prod:prod"
export REVIEWER_TOKEN="dev:reviewer:policy-reviewer:acme:prod:prod"
export FORGE_URL="http://127.0.0.1:8080"
export PG_DSN="postgres://kernloom:kernloom-dev-password@127.0.0.1:5432/kernloom?sslmode=disable"

mkdir -p "$WORK"
```

For each new shell used below, set `KERNLOOM_HOME` to the same workspace root
before running the commands in that shell.

## Compile The Policy Intent

Compile the existing runtime mitigation intent. Use `--build-created-by alice`
so the later review/approval token is a different identity.

```sh
cd "$KERNLOOM_HOME/kernloom-core"

./bin/forge compile \
  --policy-repo ../enterprise-kernloom-policies \
  --policy-file ../enterprise-kernloom-policies/policies/runtime/mitigate-abnormal-source-behavior.intent.kni \
  --core-registry ../kernloom-core-registry \
  --enterprise-registry ../enterprise-kernloom-registry \
  --artifact-store-root ../enterprise-kernloom-policies/generated/artifact-store \
  --signing dev-local \
  --signing-key "$MANAGEMENT_KEY" \
  --signing-key-id forge-management-dev-local \
  --build-created-by alice \
  --correlation-id "getting-started.$(date +%s)" \
  | tee "$WORK/compile.log"
```

Extract refs from the compile output and manifest:

```sh
export MANIFEST_PATH="../enterprise-kernloom-policies/generated/reports/${POLICY_ID}.manifest.json"
export SIGNED_MANIFEST_URI="$(awk '/signed_manifest_ref:/ {print $2}' "$WORK/compile.log")"
export SIGNED_MANIFEST_SHA="$(awk '/signed_manifest_ref:/ {print $3}' "$WORK/compile.log")"
export SOURCE_COMMIT="$(jq -r '.spec.policy_repo.commit' "$MANIFEST_PATH")"
export RUNTIME_BUNDLE_URI="$(jq -r '.spec.signed_outputs.runtime_bundle.artifact_ref.uri' "$MANIFEST_PATH")"
export RUNTIME_BUNDLE_SHA="$(jq -r '.spec.signed_outputs.runtime_bundle.artifact_ref.sha256' "$MANIFEST_PATH")"
export RUNTIME_BUNDLE_SIGNED_PATH="../enterprise-kernloom-policies/generated/signed/${POLICY_ID}.runtime_bundle.signed.json"
export GRANT_ID="$(jq -r '.payload | @base64d | fromjson | .spec.capability_grants[] | select(.action_type=="runtime_action.rate_limit_source") | .capability_grant_id' "$RUNTIME_BUNDLE_SIGNED_PATH")"
```

If `GRANT_ID` is empty, rerun the compile command. Old generated artifacts may
pre-date capability grants.

## Start Forge API

This starts Forge with a persistent Postgres management store and explicit
dev-local plaintext HTTP:

```sh
cd "$KERNLOOM_HOME/kernloom-core"

./bin/forge migrate --management-postgres-dsn "$PG_DSN"

./bin/forge api \
  --addr 127.0.0.1:8080 \
  --dev-insecure-http \
  --queue memory \
  --management-store postgres \
  --management-postgres-dsn "$PG_DSN" \
  --management-signing-key "$MANAGEMENT_KEY" \
  --dev-seed-management-trust \
  --dev-tokens \
  --artifact-store-root ../enterprise-kernloom-policies/generated/artifact-store
```

Keep this process running.

## Approve The Build

In a second shell:

```sh
cd "$KERNLOOM_HOME/kernloom-core"

APPROVAL_JSON="$(
  curl -sS -H "Authorization: Bearer ${REVIEWER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$(jq -n \
      --arg uri "$SIGNED_MANIFEST_URI" \
      --arg sha "$SIGNED_MANIFEST_SHA" \
      '{build_ref:{uri:$uri,sha256:$sha},environment:"prod",stage:"prod",scope:"edge-prod",authority_id:"reviewer",authority_kind:"local-dev-review"}')" \
    "$FORGE_URL/v1/policy-build-manifests/approve"
)"

printf '%s\n' "$APPROVAL_JSON" | jq .

export APPROVED_BUILD_URI="$(printf '%s\n' "$APPROVAL_JSON" | jq -r '.approved_build_ref.uri')"
export APPROVED_BUILD_SHA="$(printf '%s\n' "$APPROVAL_JSON" | jq -r '.approved_build_ref.sha256')"
```

## Enroll KLIQ

Create a single-use enrollment token:

```sh
TOKEN_JSON="$(
  curl -sS -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"environment":"prod","stage":"prod","scope":"edge-prod"}' \
    "$FORGE_URL/v1/kliq/enrollment-tokens"
)"

export ENROLLMENT_TOKEN="$(printf '%s\n' "$TOKEN_JSON" | jq -r '.secret_token')"
```

Enroll the local KLIQ. This writes KLIQ identity and service credentials into
the local SQLite state file.

```sh
ENROLL_OUT="$(
  ./bin/kliq enroll \
    --forge "$FORGE_URL" \
    --dev-insecure-forge-transport \
    --enrollment-token "$ENROLLMENT_TOKEN" \
    --node-id node-dev-1 \
    --environment prod \
    --stage prod \
    --scope edge-prod \
    --trust-key-id forge-management-dev-local \
    --adapter-inventory kernloom.adapter.klshield \
    --capabilities klshield.runtime.source_mitigation \
    --state "$STATE"
)"

printf '%s\n' "$ENROLL_OUT"
export KLIQ_ID="$(printf '%s\n' "$ENROLL_OUT" | awk '/kliq_id:/ {print $2}')"
```

## Plan The Assignment

Plan the assignment from the approved build and signed runtime bundle ref:

```sh
EXPIRES_AT="$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)"

ASSIGNMENT_JSON="$(
  curl -sS -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$(jq -n \
      --arg kliq "$KLIQ_ID" \
      --arg commit "$SOURCE_COMMIT" \
      --arg approved_uri "$APPROVED_BUILD_URI" \
      --arg approved_sha "$APPROVED_BUILD_SHA" \
      --arg runtime_uri "$RUNTIME_BUNDLE_URI" \
      --arg runtime_sha "$RUNTIME_BUNDLE_SHA" \
      --arg expires "$EXPIRES_AT" \
      '{
        kliq_id:$kliq,
        source_commit:$commit,
        approved_build_ref:{uri:$approved_uri,sha256:$approved_sha},
        expires_at:$expires,
        artifacts:[{
          artifact_type:"runtime_bundle",
          artifact_id:"runtime_bundle.runtime.mitigate-abnormal-source-behavior",
          artifact_ref:$runtime_uri,
          sha256:$runtime_sha
        }]
      }')" \
    "$FORGE_URL/v1/kliq/assignments"
)"

printf '%s\n' "$ASSIGNMENT_JSON" | jq .
```

## Start The KLShield Adapter

For the fastest local smoke test, use the memory runtime store:

```sh
cd "$KERNLOOM_HOME/kernloom-adapter-klshield"

./bin/kernloom-adapter-klshield serve \
  --addr 127.0.0.1:18082 \
  --dev-insecure-transport \
  --dev-insecure-skip-authority-verification \
  --dev-allow-default-rate-limit-parameters
```

Keep this process running.

## Run KLIQ And Execute One Runtime Decision

In another shell:

```sh
cd "$KERNLOOM_HOME/kernloom-core"

cat > "$WORK/runtime-decision.json" <<EOF
{
  "decision_id": "decision.getting-started.$(date +%s)",
  "adapter_id": "kernloom.adapter.klshield",
  "capability_id": "klshield.runtime.source_mitigation",
  "capability_grant_id": "$GRANT_ID",
  "action_type": "runtime_action.rate_limit_source",
  "target_scope": "application",
  "target_key": "192.0.2.10",
  "ttl": "30s",
  "reason": "getting started KLShield managed smoke",
  "audit_id": "audit.getting-started.$(date +%s)",
  "correlation_id": "getting-started.manual"
}
EOF

./bin/kliq run \
  --mode managed \
  --once \
  --state "$STATE" \
  --trust-bundle "$MANAGEMENT_KEY" \
  --dev-allow-private-trust-key \
  --forge-url "$FORGE_URL" \
  --dev-insecure-forge-transport \
  --adapter kernloom.adapter.klshield=127.0.0.1:18082 \
  --dev-insecure-adapter-transport \
  --decision-source "$WORK/runtime-decision.json"
```

Inspect local state:

```sh
./bin/kliq status --state "$STATE"
./bin/kliq bundle status --state "$STATE"
./bin/kliq runtime actions --state "$STATE"
./bin/kliq audit pending --state "$STATE"
```

The example policy currently has `runtime.max_scope = "application"`, so the
manual runtime decision uses `target_scope = "application"`. The KLShield
adapter still uses the IPv4 `target_key` as the source map key. A dedicated
source-scoped smoke intent can simplify this later.

## Real KLShield BPF Enforcement

The memory-store adapter proves the Kernloom control path. To enforce in
KLShield maps, first load and pin the KLShield PEP maps from `kernloom-shield`
on a Linux host, then run the adapter with the BPF store:

```sh
cd "$KERNLOOM_HOME/kernloom-adapter-klshield"

sudo ./bin/kernloom-adapter-klshield serve \
  --addr 127.0.0.1:18082 \
  --runtime-store bpf \
  --bpffs-root /sys/fs/bpf \
  --tls-cert /etc/kernloom/adapter/server.crt \
  --tls-key /etc/kernloom/adapter/server.key \
  --client-ca /etc/kernloom/adapter/client-ca.pem \
  --authority-public-key /etc/kernloom/trust/runtime-authority.public.json
```

Then rerun the same `kliq run --once ... --decision-source ...` command with
adapter mTLS flags instead of `--dev-insecure-adapter-transport`.
