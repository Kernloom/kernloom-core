// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
)

const (
	testAdapterID         = "kernloom.adapter.klshield"
	testAdapterIDAlt      = "kernloom.adapter.nginx"
	testCapabilityID      = "klshield.runtime.source_mitigation"
	testCapabilityIDAlt   = "nginx.runtime.route_mitigation"
	testCapabilityGrantID = "grant.klshield.runtime.source_mitigation"
)

func TestManagerLoadBundleRejectsUnsignedRuntimeBundle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	path := filepath.Join(t.TempDir(), "runtime_bundle.json")
	writeJSON(t, path, testRuntimeBundle())

	_, err := (Manager{Store: store, Verifier: signer, Now: func() time.Time { return now }}).LoadBundle(ctx, kliqbundle.LocalFileSource{Path: path})
	if err == nil {
		t.Fatal("expected unsigned runtime bundle to be rejected")
	}
}

func TestManagerLoadManagedBundlePersistsAssignmentVersionAndRejectsOlderAfterRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t, now)
	runtimeEnvelope := signedBundleData(t, signer, now, now.Add(time.Hour))
	currentAssignment := signedManagedAssignment(t, signer, managedTestAssignment(now, signer.KeyID, 2, runtimeEnvelope), now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(currentAssignment)
	}))
	defer server.Close()

	manager := testManager(store, signer, now)
	_, err = manager.LoadManagedBundle(ctx, &kliqbundle.ManagedAssignmentSource{
		BaseURL:     server.URL,
		KLIQID:      "kliq.test",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
		TrustKeyID:  signer.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.KLIQManagementState(ctx, "kliq.test")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveAssignmentVersion != 2 || state.ActiveAssignmentDigest != currentAssignment.PayloadSHA256 {
		t.Fatalf("expected active assignment v2 to persist, got %#v", state)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restartedStore, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedStore.Close()
	olderAssignment := signedManagedAssignment(t, signer, managedTestAssignment(now, signer.KeyID, 1, runtimeEnvelope), now.Add(time.Hour))
	currentAssignment = olderAssignment
	restarted := testManager(restartedStore, signer, now)
	_, err = restarted.LoadManagedBundle(ctx, &kliqbundle.ManagedAssignmentSource{
		BaseURL:     server.URL,
		KLIQID:      "kliq.test",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
		TrustKeyID:  signer.KeyID,
	})
	if err == nil {
		t.Fatal("expected older managed assignment to be rejected after restart")
	}
}

func TestManagerExecutesRequiredActionThroughPlanAndDeduplicates(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	bundlePath := signedBundleFile(t, signer, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))

	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	cached, err := store.LastBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cached.BundleSource != bundlePath || cached.BundleID == "" || cached.PayloadSHA256 == "" || cached.CorrelationID != "correlation.bundle.test" {
		t.Fatalf("expected last valid signed bundle to be cached, got %#v", cached)
	}
	result := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.test",
		TargetKey:  "source-1",
		TTL:        "1m",
		Reason:     "test action",
		AuditID:    "audit.test",
	})
	if !result.Applied || result.Lease.Status != domain.RuntimeActionActive {
		t.Fatalf("expected active applied lease, got %#v", result)
	}
	if result.Lease.PlanID == "" || result.Lease.AdapterID != testAdapterID || result.Lease.CapabilityID != testCapabilityID {
		t.Fatalf("expected plan-aware adapter lease, got %#v", result.Lease)
	}
	if result.Lease.Mode != ActionModeRequired || !result.Lease.Required {
		t.Fatalf("expected required lease mode, got %#v", result.Lease)
	}
	if result.Lease.CorrelationID != "correlation.bundle.test" {
		t.Fatalf("expected bundle correlation id to propagate through lease, got %#v", result.Lease)
	}
	if !result.Lease.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("expected one minute ttl, got %s", result.Lease.ExpiresAt)
	}
	assertJournalEvent(t, store, ctx, result.Lease.RuntimeActionID, "activated")
	audits, err := store.PendingAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].RuntimeActionID != result.Lease.RuntimeActionID {
		t.Fatalf("expected one pending audit record for activated action, got %#v", audits)
	}
	duplicate := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.test-2",
		TargetKey:  "source-1",
		TTL:        "2m",
		Reason:     "duplicate test action",
		AuditID:    "audit.test-2",
	})
	if duplicate.Applied {
		t.Fatal("expected duplicate active lease to be reused, not applied")
	}
	if !duplicate.Lease.ExpiresAt.Equal(result.Lease.ExpiresAt) {
		t.Fatalf("expected duplicate not to extend ttl, got %s want %s", duplicate.Lease.ExpiresAt, result.Lease.ExpiresAt)
	}
	assertJournalEvent(t, store, ctx, result.Lease.RuntimeActionID, "deduplicated")
}

func TestManagerAllowsDecisionCorrelationIDToOverrideBundleCorrelationID(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	result := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID:    "decision.correlation-override",
		CorrelationID: "correlation.decision.test",
		TargetKey:     "source-correlation-override",
		Reason:        "test correlation propagation",
		AuditID:       "audit.correlation-override",
	})
	if result.Lease.CorrelationID != "correlation.decision.test" {
		t.Fatalf("expected decision correlation id to propagate, got %#v", result.Lease)
	}
}

func TestManagerDoesNotDeduplicateSameActionAcrossAdapters(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now,
		testAdapter(testAdapterID, LocalTestExecutor{}),
		testAdapter(testAdapterIDAlt, LocalTestExecutor{}),
	)
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	first := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.adapter-a",
		AdapterID:  testAdapterID,
		TargetKey:  "source-shared",
		Reason:     "first adapter action",
		AuditID:    "audit.adapter-a",
	})
	second := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID:   "decision.adapter-b",
		AdapterID:    testAdapterIDAlt,
		CapabilityID: testCapabilityID,
		TargetKey:    "source-shared",
		Reason:       "second adapter action",
		AuditID:      "audit.adapter-b",
	})
	if !first.Applied || !second.Applied {
		t.Fatalf("expected both adapter-specific actions to apply, got %#v %#v", first, second)
	}
	if first.Lease.IdempotencyKey == second.Lease.IdempotencyKey {
		t.Fatalf("expected adapter-aware idempotency keys to differ")
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("expected two leases for different adapters, got %#v", leases)
	}
}

func TestManagerDoesNotDeduplicateSameActionAcrossCapabilities(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	first := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.capability-a",
		TargetKey:  "source-shared-capability",
		Reason:     "first capability action",
		AuditID:    "audit.capability-a",
	})
	second := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID:   "decision.capability-b",
		CapabilityID: testCapabilityIDAlt,
		TargetKey:    "source-shared-capability",
		Reason:       "second capability action",
		AuditID:      "audit.capability-b",
	})
	if !first.Applied || !second.Applied {
		t.Fatalf("expected both capability-specific actions to apply, got %#v %#v", first, second)
	}
	if first.Lease.IdempotencyKey == second.Lease.IdempotencyKey {
		t.Fatalf("expected capability-aware idempotency keys to differ")
	}
}

func TestIdempotencyKeyIncludesAdapterAndCapability(t *testing.T) {
	base := idempotencyKey("bundle", "decision", testAdapterID, testCapabilityID, "runtime_action.deny_temporarily_source", "source", "source-1")
	changedAdapter := idempotencyKey("bundle", "decision", testAdapterIDAlt, testCapabilityID, "runtime_action.deny_temporarily_source", "source", "source-1")
	changedCapability := idempotencyKey("bundle", "decision", testAdapterID, testCapabilityIDAlt, "runtime_action.deny_temporarily_source", "source", "source-1")
	if base == changedAdapter {
		t.Fatal("expected adapter id to affect idempotency key")
	}
	if base == changedCapability {
		t.Fatal("expected capability id to affect idempotency key")
	}
}

func TestManagerUsesBundleDefaultsWhenRequestOmitsTTLAndScope(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	result := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.defaults",
		TargetKey:  "source-default",
		Reason:     "test default ttl and scope",
		AuditID:    "audit.defaults",
	})
	if result.Lease.TargetScope != "source" {
		t.Fatalf("expected target scope to fall back to bundle max_scope, got %q", result.Lease.TargetScope)
	}
	if result.Lease.TTL != "2m" || !result.Lease.ExpiresAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("expected ttl to fall back to bundle max_ttl, got %q expiring %s", result.Lease.TTL, result.Lease.ExpiresAt)
	}
}

func TestManagerRejectsRuntimeActionWithoutReason(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.missing-reason",
		TargetKey:  "source-missing-reason",
		AuditID:    "audit.missing-reason",
		Reason:     "",
	}))
	if err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected missing reason to be rejected, got %v", err)
	}
}

func TestManagerRequiresAuditIDOrExplicitDecisionDerivedAuditID(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.missing-audit",
		TargetKey:  "source-missing-audit",
		Reason:     "test audit requirement",
		AuditID:    "",
	}))
	if err == nil || !strings.Contains(err.Error(), "audit id") {
		t.Fatalf("expected missing audit id to be rejected, got %v", err)
	}
	result := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID:                  "decision.derive-audit",
		TargetKey:                   "source-derived-audit",
		Reason:                      "test explicit audit derivation",
		AuditID:                     "",
		DeriveAuditIDFromDecisionID: true,
	})
	if result.Lease.AuditID != "audit."+shortHash("decision.derive-audit") {
		t.Fatalf("expected audit id derived from decision id, got %q", result.Lease.AuditID)
	}
}

func TestManagerReconcilesExpiredActionAfterRestart(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.db")
	signer := testSigner(t, start)
	bundlePath := signedBundleFile(t, signer, start, start.Add(time.Hour))

	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	manager := testManager(store, signer, start, testAdapter(testAdapterID, LocalTestExecutor{}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	created := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.restart",
		TargetKey:  "source-2",
		TTL:        "1s",
		Reason:     "test restart reconciliation",
		AuditID:    "audit.restart",
	})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restartedStore, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedStore.Close()
	restarted := testManager(restartedStore, signer, start.Add(2*time.Second), testAdapter(testAdapterID, LocalTestExecutor{}))
	result, err := restarted.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Expired != 1 || result.Active != 0 {
		t.Fatalf("expected one expired and no active leases, got %#v", result)
	}
	lease, err := restartedStore.LeaseByID(ctx, created.Lease.RuntimeActionID)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Status != domain.RuntimeActionExpired {
		t.Fatalf("expected expired lease, got %#v", lease)
	}
	active, err := restartedStore.ActiveLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("expected expired action to be cleaned from active leases, got %#v", active)
	}
	assertJournalEvent(t, restartedStore, ctx, created.Lease.RuntimeActionID, "expired")
	audits, err := restartedStore.PendingAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 2 {
		t.Fatalf("expected activated and expired audit records to remain pending upload, got %#v", audits)
	}
}

func TestManagerReconcileDryRunDoesNotMutateExpiredLease(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	lease := testLeaseFor(testAdapterID, testCapabilityID, "source-dry-run", now.Add(-time.Second), now)
	if err := store.UpsertLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	manager := Manager{Store: store, Now: func() time.Time { return now }}

	result, err := manager.ReconcileDryRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Expired != 1 || result.Active != 0 || result.Unknown != 0 {
		t.Fatalf("expected one expired lease in dry run, got %#v", result)
	}
	after, err := store.LeaseByID(ctx, lease.RuntimeActionID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != domain.RuntimeActionActive {
		t.Fatalf("dry run mutated lease status, got %#v", after)
	}
	entries, err := store.JournalEntries(ctx, lease.RuntimeActionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry run wrote journal entries: %#v", entries)
	}
}

func TestReconcileContinuesWhenOneAdapterIsMissing(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	if err := store.UpsertLease(ctx, testLeaseFor(testAdapterID, testCapabilityID, "source-a", now.Add(-time.Second), now)); err != nil {
		t.Fatal(err)
	}
	leaseB := testLeaseFor(testAdapterIDAlt, testCapabilityID, "source-b", now.Add(-time.Second), now)
	if err := store.UpsertLease(ctx, leaseB); err != nil {
		t.Fatal(err)
	}
	manager := testManager(store, signer, now, testAdapter(testAdapterIDAlt, LocalTestExecutor{}))

	result, err := manager.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Expired != 1 || result.Unknown != 1 {
		t.Fatalf("expected one missing-adapter unknown and one expired cleanup, got %#v", result)
	}
	assertFindingContains(t, result.Findings, testAdapterID)
	updatedB, err := store.LeaseByID(ctx, leaseB.RuntimeActionID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedB.Status != domain.RuntimeActionExpired {
		t.Fatalf("expected adapter B lease to be expired despite adapter A missing, got %#v", updatedB)
	}
}

func TestManagerReconcilesExpiredActionWhenCachedBundleExpired(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	afterExpiry := start.Add(2 * time.Second)
	statePath := filepath.Join(t.TempDir(), "state.db")
	signer := testSigner(t, start)
	bundlePath := signedBundleFile(t, signer, start, start.Add(time.Second))

	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	manager := testManager(store, signer, start, testAdapter(testAdapterID, LocalTestExecutor{}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	created := executeTestAction(t, manager, ctx, ExecuteRequest{
		DecisionID: "decision.expired-bundle-cleanup",
		TargetKey:  "source-expired-bundle-cleanup",
		TTL:        "1s",
		Reason:     "test cleanup after cached bundle expiry",
		AuditID:    "audit.expired-bundle-cleanup",
	})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	signer.Now = func() time.Time { return afterExpiry }
	restartedStore, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedStore.Close()
	restarted := testManager(restartedStore, signer, afterExpiry, testAdapter(testAdapterID, LocalTestExecutor{}))
	result, err := restarted.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Expired != 1 || result.Active != 0 {
		t.Fatalf("expected expired lease cleanup despite expired bundle, got %#v", result)
	}
	assertFindingContains(t, result.Findings, "cached runtime bundle unavailable or invalid")
	assertFindingContains(t, result.Findings, "cleanup executed with degraded bundle authority")
	lease, err := restartedStore.LeaseByID(ctx, created.Lease.RuntimeActionID)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Status != domain.RuntimeActionExpired {
		t.Fatalf("expected expired lease, got %#v", lease)
	}
}

func TestManagerDeniesNewActionWhenCachedBundleExpired(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	afterExpiry := start.Add(2 * time.Second)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, start)
	manager := testManager(store, signer, start, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, start, start.Add(time.Second))

	signer.Now = func() time.Time { return afterExpiry }
	manager.Now = func() time.Time { return afterExpiry }
	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.expired-bundle-new-action",
		TargetKey:  "source-expired-bundle-new-action",
		Reason:     "test expired bundle blocks new action",
		AuditID:    "audit.expired-bundle-new-action",
	}))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired cached bundle to deny new action, got %v", err)
	}
}

func openTestStore(t *testing.T) *actionstate.SQLiteStore {
	t.Helper()
	store, err := actionstate.OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testSigner(t *testing.T, now time.Time) *signing.DevLocalSigner {
	t.Helper()
	signer, err := signing.NewDevLocalSigner("dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	return signer
}

func signedBundleFile(t *testing.T, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime_bundle.signed.json")
	data := signedBundleData(t, signer, signedAt, expiresAt)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func signedBundleData(t *testing.T, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) []byte {
	t.Helper()
	envelope := signedBundleEnvelope(t, signer, signedAt, expiresAt)
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signedBundleEnvelope(t *testing.T, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) signing.SignedEnvelope {
	t.Helper()
	signer.Now = func() time.Time { return signedAt }
	payload, err := json.Marshal(testRuntimeBundle())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		PolicyID:     "policy.runtime",
		SourceCommit: "abc123",
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func managedTestAssignment(now time.Time, trustKeyID string, version int64, runtimeEnvelope []byte) domain.KLIQAssignment {
	return domain.KLIQAssignment{
		AssignmentID:      "kliq_assignment.test.v" + fmt.Sprint(version),
		AssignmentVersion: version,
		KLIQID:            "kliq.test",
		Environment:       "prod",
		Stage:             "prod",
		Scope:             "edge-prod",
		SourceCommit:      "abc123",
		TrustKeyID:        trustKeyID,
		TrustBundleRef:    trustKeyID,
		CreatedAt:         now,
		ExpiresAt:         now.Add(time.Hour),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.test",
			SHA256:       domain.SHA256JSON(runtimeEnvelope),
			Envelope:     append([]byte(nil), runtimeEnvelope...),
		}},
	}
}

func signedManagedAssignment(t *testing.T, signer *signing.DevLocalSigner, assignment domain.KLIQAssignment, expiresAt time.Time) signing.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		SourceCommit: assignment.SourceCommit,
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func testRuntimeBundle() corebundle.RuntimeBundle {
	return corebundle.RuntimeBundle{
		Kind: "RuntimeBundle",
		Metadata: coreartifact.Metadata{
			ID:            "runtime_bundle.policy.runtime",
			PolicyID:      "policy.runtime",
			ArtifactType:  "runtime_bundle",
			SourceCommit:  "abc123",
			CorrelationID: "correlation.bundle.test",
			CreatedAt:     time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC),
		},
		Spec: corebundle.RuntimeBundleSpec{
			PolicyID:       "policy.runtime",
			RuntimeAllowed: true,
			RuntimeActions: []corebundle.RuntimeAction{{
				Label:       "deny temporarily source",
				CanonicalID: "runtime_action.deny_temporarily_source",
			}},
			MaxTTL:   "2m",
			MaxScope: "source",
		},
		Status: coreartifact.PlannedStatus("slice 4 test bundle"),
	}
}

func testManager(store actionstate.Store, signer signing.Verifier, now time.Time, entries ...StaticAdapterRuntimeEntry) Manager {
	registry := NewStaticAdapterRuntimeRegistry(entries...)
	return Manager{
		Store:    store,
		Verifier: signer,
		Registry: registry,
		Now:      func() time.Time { return now },
	}
}

func testAdapter(adapterID string, executor RuntimeExecutor) StaticAdapterRuntimeEntry {
	return StaticAdapterRuntimeEntry{AdapterID: adapterID, Executor: executor}
}

func loadTestBundle(t *testing.T, manager Manager, ctx context.Context, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) {
	t.Helper()
	bundlePath := signedBundleFile(t, signer, signedAt, expiresAt)
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
}

func defaultExecuteRequest(req ExecuteRequest) ExecuteRequest {
	if req.AdapterID == "" {
		req.AdapterID = testAdapterID
	}
	if req.CapabilityID == "" {
		req.CapabilityID = testCapabilityID
	}
	if req.CapabilityGrantID == "" {
		req.CapabilityGrantID = testCapabilityGrantID
	}
	if req.Mode == "" {
		req.Mode = ActionModeRequired
	}
	if req.ActionType == "" {
		req.ActionType = "runtime_action.deny_temporarily_source"
	}
	if req.DecisionID == "" {
		req.DecisionID = "decision.test"
	}
	if req.TargetKey == "" {
		req.TargetKey = "source-test"
	}
	return req
}

func executeTestAction(t *testing.T, manager Manager, ctx context.Context, req ExecuteRequest) RuntimeActionExecutionResult {
	t.Helper()
	result, err := manager.ExecuteAction(ctx, defaultExecuteRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected one execution result, got %#v", result)
	}
	if len(result.Plan.Actions) != 1 {
		t.Fatalf("expected one planned action, got %#v", result.Plan)
	}
	if result.Results[0].Applied && result.Results[0].Lease.PlanID != result.Plan.PlanID {
		t.Fatalf("expected lease to reference action plan, got %#v / %#v", result.Results[0].Lease, result.Plan)
	}
	return result.Results[0]
}

func testLeaseFor(adapterID, capabilityID, targetKey string, expiresAt, now time.Time) actionstate.RuntimeActionLease {
	planID := "runtime_action_plan." + shortHash(adapterID+capabilityID+targetKey)
	idem := idempotencyKey("runtime_bundle.policy.runtime", "decision."+targetKey, adapterID, capabilityID, "runtime_action.deny_temporarily_source", "source", targetKey)
	return actionstate.RuntimeActionLease{
		RuntimeActionID:   "runtime_action." + shortHash(idem),
		PlanID:            planID,
		DecisionID:        "decision." + targetKey,
		PolicyID:          "policy.runtime",
		BundleID:          "runtime_bundle.policy.runtime",
		SourceCommit:      "abc123",
		CorrelationID:     "correlation.test",
		ActionType:        "runtime_action.deny_temporarily_source",
		TargetScope:       "source",
		TargetKey:         targetKey,
		TTL:               "1s",
		ExpiresAt:         expiresAt,
		Reason:            "test lease",
		AuditID:           "audit." + targetKey,
		CapabilityGrantID: "grant." + capabilityID,
		AdapterID:         adapterID,
		CapabilityID:      capabilityID,
		Mode:              ActionModeRequired,
		Required:          true,
		IdempotencyKey:    idem,
		CreatedAt:         now,
		LastReconciledAt:  now,
		Status:            domain.RuntimeActionActive,
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertJournalEvent(t *testing.T, store actionstate.Store, ctx context.Context, runtimeActionID, event string) {
	t.Helper()
	entries, err := store.JournalEntries(ctx, runtimeActionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Event == event {
			return
		}
	}
	t.Fatalf("expected journal event %q for %s, got %#v", event, runtimeActionID, entries)
}

func assertFindingContains(t *testing.T, findings []string, text string) {
	t.Helper()
	for _, finding := range findings {
		if strings.Contains(finding, text) {
			return
		}
	}
	t.Fatalf("expected finding containing %q, got %#v", text, findings)
}
