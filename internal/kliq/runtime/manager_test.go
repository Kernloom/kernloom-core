// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/kernloom/kernloom-core/internal/core/conformance"
	corecontext "github.com/kernloom/kernloom-core/internal/core/context"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
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
	artifacts, err := store.AssignmentArtifacts(ctx, "kliq.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].ArtifactType != "runtime_bundle" || artifacts[0].AssignmentVersion != 2 || artifacts[0].ActivationStatus != "activated" {
		t.Fatalf("expected staged runtime bundle artifact for active assignment, got %#v", artifacts)
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

func TestManagerLoadManagedBundleKeepsPreviousActiveOnInvalidArtifactDigest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	validRuntimeEnvelope := signedBundleData(t, signer, now, now.Add(time.Hour))
	currentAssignment := signedManagedAssignment(t, signer, managedTestAssignment(now, signer.KeyID, 1, validRuntimeEnvelope), now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(currentAssignment)
	}))
	defer server.Close()
	manager := testManager(store, signer, now)

	validRecord, err := manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	invalidAssignment := managedTestAssignment(now, signer.KeyID, 2, signedBundleData(t, signer, now, now.Add(time.Hour)))
	invalidAssignment.Artifacts[0].SHA256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	currentAssignment = signedManagedAssignment(t, signer, invalidAssignment, now.Add(time.Hour))

	_, err = manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID))
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected artifact digest mismatch rejection, got %v", err)
	}
	assertActiveManagedAssignment(t, store, ctx, 1, currentAssignment.PayloadSHA256, validRecord.PayloadSHA256)
}

func TestManagerLoadManagedBundleKeepsPreviousActiveOnRuntimeArtifactVerificationFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	validRuntimeEnvelope := signedBundleData(t, signer, now, now.Add(time.Hour))
	currentAssignment := signedManagedAssignment(t, signer, managedTestAssignment(now, signer.KeyID, 1, validRuntimeEnvelope), now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(currentAssignment)
	}))
	defer server.Close()
	manager := testManager(store, signer, now)

	validRecord, err := manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	otherSigner := testSigner(t, now)
	otherSigner.KeyID = "other-dev-local"
	invalidRuntimeEnvelope := signedBundleData(t, otherSigner, now, now.Add(time.Hour))
	currentAssignment = signedManagedAssignment(t, signer, managedTestAssignment(now, signer.KeyID, 2, invalidRuntimeEnvelope), now.Add(time.Hour))

	_, err = manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID))
	if err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("expected runtime artifact signature rejection, got %v", err)
	}
	assertActiveManagedAssignment(t, store, ctx, 1, currentAssignment.PayloadSHA256, validRecord.PayloadSHA256)
}

func TestManagerLoadManagedBundleActivatesFullAssignmentArtifacts(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	assignment := managedTestAssignment(now, signer.KeyID, 1, signedBundleData(t, signer, now, now.Add(time.Hour)))
	assignment.Artifacts = append(assignment.Artifacts,
		signedAssignmentArtifact(t, signer, now, "adapter_assignment", "adapter_assignment.klshield", domain.AdapterAssignment{
			Kind:      "AdapterAssignment",
			AdapterID: testAdapterID,
			Endpoint:  "127.0.0.1:19090",
		}),
		signedAssignmentArtifact(t, signer, now, "context_route_pack", "context_route_pack.test", corecontext.ContextRoutePack{
			Kind: "ContextRoutePack",
			Spec: corecontext.ContextRoutePackSpec{
				PolicyID: "policy.runtime",
				Target:   "edge-prod",
				Stage:    "prod",
				Routes: []corecontext.ContextRoute{{
					Name:      "source-minimal",
					Consumers: []string{testAdapterID},
					Facts:     []string{"source.ip"},
				}},
			},
		}),
		signedAssignmentArtifact(t, signer, now, "conformance_expectation", "conformance_expectation.test", conformance.ConformanceExpectation{
			Kind: "ConformanceExpectation",
			Spec: conformance.ConformanceExpectationSpec{
				PolicyID: "policy.runtime",
				Target:   "edge-prod",
				Stage:    "prod",
				Expectations: []conformance.Expectation{{
					Name:        "runtime action audit exists",
					Description: "required runtime action emits local audit",
				}},
			},
		}),
		signedAssignmentArtifact(t, signer, now, "trust_bundle", "trust_bundle.test", domain.TrustBundle{
			KeyID:     signer.KeyID,
			PublicKey: "public-key",
			Purpose:   "assignment_verification",
			Status:    "active",
			ExpiresAt: now.Add(time.Hour),
			Issuer:    "test",
		}),
		signedAssignmentArtifact(t, signer, now, "management_profile", "management_profile.test", domain.KLIQManagementProfile{
			Kind:               "KLIQManagementProfile",
			ProfileID:          "management_profile.test",
			Mode:               "managed_pull",
			PollInterval:       "2s",
			HeartbeatInterval:  "3s",
			StatusInterval:     "4s",
			DecisionInterval:   "5s",
			ReconcileInterval:  "6s",
			AuditFlushInterval: "7s",
			AssignmentSource:   "forge_assignment_api",
		}),
		signedAssignmentArtifact(t, signer, now, "fallback_profile", "fallback_profile.test", domain.KLIQFallbackProfile{
			Kind:                          "KLIQFallbackProfile",
			ProfileID:                     "fallback_profile.test",
			Mode:                          "last_valid_assignment",
			AllowCachedAssignmentFallback: true,
			DenyNewActionsWhenDegraded:    true,
			AuditRequired:                 true,
		}),
	)
	currentAssignment := signedManagedAssignment(t, signer, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(currentAssignment)
	}))
	defer server.Close()
	manager := testManager(store, signer, now)

	if _, err := manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID)); err != nil {
		t.Fatal(err)
	}
	for _, artifactType := range []string{"runtime_bundle", "adapter_assignment", "context_route_pack", "conformance_expectation", "trust_bundle", "management_profile", "fallback_profile"} {
		record, err := store.ActiveArtifact(ctx, "kliq.test", artifactType)
		if err != nil {
			t.Fatalf("expected active %s artifact: %v", artifactType, err)
		}
		if len(record.PayloadJSON) == 0 || record.SHA256 == "" {
			t.Fatalf("expected active %s payload and digest, got %#v", artifactType, record)
		}
	}
	records, err := store.AssignmentArtifacts(ctx, "kliq.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 7 {
		t.Fatalf("expected seven activated artifacts, got %#v", records)
	}
	for _, record := range records {
		if record.ActivationStatus != "activated" {
			t.Fatalf("expected activated artifact status, got %#v", record)
		}
	}
}

func TestManagerLoadManagedBundleRejectsInvalidContextRoutePackAndKeepsPreviousActive(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	validRuntimeEnvelope := signedBundleData(t, signer, now, now.Add(time.Hour))
	currentAssignment := signedManagedAssignment(t, signer, managedTestAssignment(now, signer.KeyID, 1, validRuntimeEnvelope), now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(currentAssignment)
	}))
	defer server.Close()
	manager := testManager(store, signer, now)

	validRecord, err := manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	invalid := managedTestAssignment(now, signer.KeyID, 2, validRuntimeEnvelope)
	invalid.Artifacts = append(invalid.Artifacts, signedAssignmentArtifact(t, signer, now, "context_route_pack", "context_route_pack.invalid", corecontext.ContextRoutePack{
		Kind: "ContextRoutePack",
		Spec: corecontext.ContextRoutePackSpec{
			PolicyID: "policy.runtime",
			Target:   "edge-prod",
			Stage:    "prod",
		},
	}))
	currentAssignment = signedManagedAssignment(t, signer, invalid, now.Add(time.Hour))

	_, err = manager.LoadManagedBundle(ctx, managedAssignmentSource(server.URL, signer.KeyID))
	if err == nil || !strings.Contains(err.Error(), "spec.routes") {
		t.Fatalf("expected invalid context route pack rejection, got %v", err)
	}
	assertActiveManagedAssignment(t, store, ctx, 1, currentAssignment.PayloadSHA256, validRecord.PayloadSHA256)
	if _, err := store.ActiveArtifact(ctx, "kliq.test", "context_route_pack"); !errors.Is(err, actionstate.ErrNotFound) {
		t.Fatalf("expected rejected context route pack not to activate, got %v", err)
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
	if result.Lease.BindingID != "binding.test.klshield" ||
		result.Lease.BindingDigest != "sha256:binding-test" ||
		result.Lease.AdapterManifestDigest != "sha256:adapter-manifest-test" ||
		result.Lease.ActionDigest != "sha256:action-test" {
		t.Fatalf("expected runtime provenance to propagate through lease, got %#v", result.Lease)
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
	if audits[0].BindingID != result.Lease.BindingID ||
		audits[0].BindingDigest != result.Lease.BindingDigest ||
		audits[0].AdapterManifestDigest != result.Lease.AdapterManifestDigest ||
		audits[0].ActionDigest != result.Lease.ActionDigest {
		t.Fatalf("expected runtime provenance to propagate through audit spool, got %#v", audits[0])
	}
	var auditPayload map[string]string
	if err := json.Unmarshal([]byte(audits[0].Payload), &auditPayload); err != nil {
		t.Fatal(err)
	}
	if auditPayload["binding_id"] != result.Lease.BindingID ||
		auditPayload["binding_digest"] != result.Lease.BindingDigest ||
		auditPayload["adapter_manifest_digest"] != result.Lease.AdapterManifestDigest ||
		auditPayload["action_digest"] != result.Lease.ActionDigest {
		t.Fatalf("expected runtime provenance in audit payload, got %#v", auditPayload)
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

func TestManagerRejectsRequestedProvenanceMismatch(t *testing.T) {
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

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID:            "decision.mismatch",
		TargetKey:             "source-mismatch",
		Reason:                "test mismatch",
		AuditID:               "audit.mismatch",
		AdapterManifestDigest: "sha256:not-the-approved-manifest",
	}))
	if err == nil || !strings.Contains(err.Error(), "requested adapter_manifest_digest") {
		t.Fatalf("expected requested provenance mismatch rejection, got %v", err)
	}
}

func TestManagerRejectsRuntimeGrantWithoutProvenance(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	runtimeBundle := testRuntimeBundle()
	runtimeBundle.Spec.CapabilityGrants[0].AdapterManifestDigest = ""
	bundlePath := signedBundleFileForBundle(t, signer, runtimeBundle, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.missing-provenance",
		TargetKey:  "source-missing-provenance",
		Reason:     "test missing provenance",
		AuditID:    "audit.missing-provenance",
	}))
	if err == nil || !strings.Contains(err.Error(), "missing required provenance field adapter_manifest_digest") {
		t.Fatalf("expected missing runtime grant provenance rejection, got %v", err)
	}
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
		DecisionID:        "decision.adapter-b",
		AdapterID:         testAdapterIDAlt,
		CapabilityID:      testCapabilityID,
		CapabilityGrantID: "grant.nginx.klshield.runtime.source_mitigation",
		TargetKey:         "source-shared",
		Reason:            "second adapter action",
		AuditID:           "audit.adapter-b",
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
		DecisionID:        "decision.capability-b",
		CapabilityID:      testCapabilityIDAlt,
		CapabilityGrantID: "grant.klshield.nginx.runtime.route_mitigation",
		TargetKey:         "source-shared-capability",
		Reason:            "second capability action",
		AuditID:           "audit.capability-b",
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

func TestManagerRejectsRuntimeActionOutsideCapabilityGrant(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	bundle := testRuntimeBundle()
	bundle.Spec.CapabilityGrants[0].AllowedTargetScopes = []string{"application"}
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: signedBundleFileForBundle(t, signer, bundle, now, now.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID:        "decision.grant-scope",
		CapabilityGrantID: testCapabilityGrantID,
		TargetKey:         "source-grant-scope",
		Reason:            "test grant target scope",
		AuditID:           "audit.grant-scope",
	}))
	if err == nil || !strings.Contains(err.Error(), "target scope") {
		t.Fatalf("expected target scope outside capability grant to be rejected, got %v", err)
	}
}

func TestManagerRejectsRuntimeActionWithMissingCapabilityGrant(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	manager := testManager(store, signer, now, testAdapter(testAdapterID, LocalTestExecutor{}))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID:        "decision.grant-missing",
		CapabilityGrantID: "grant.missing",
		TargetKey:         "source-grant-missing",
		Reason:            "test missing capability grant",
		AuditID:           "audit.grant-missing",
	}))
	if err == nil || !strings.Contains(err.Error(), "is not present") {
		t.Fatalf("expected missing capability grant to be rejected, got %v", err)
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

func TestManagerDerivesRuntimeActionFromRiskCacheAndPolicyBehavior(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	executor := recordingExecutor{}
	manager := testManager(store, signer, now, testAdapter(testAdapterID, &executor))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))
	score := 95.0
	if err := store.SaveRiskContext(ctx, actionstate.RiskCacheKey{RiskType: "runtime_anomaly", Scope: corerisk.ScopeLocal}, corerisk.RiskContext{
		RiskType:    "runtime_anomaly",
		Tier:        corerisk.TierCritical,
		Score:       &score,
		Confidence:  0.95,
		Source:      "baseline.local",
		Scope:       corerisk.ScopeLocal,
		EvaluatedAt: now,
		ValidUntil:  time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	result, err := manager.ExecuteAction(ctx, ExecuteRequest{
		DecisionID:        "decision.risk-critical",
		RiskType:          "runtime_anomaly",
		AdapterID:         testAdapterID,
		CapabilityID:      testCapabilityID,
		CapabilityGrantID: testCapabilityGrantID,
		Mode:              ActionModeRequired,
		TargetScope:       "source",
		TargetKey:         "source-risk",
		Reason:            "risk behavior authorized mitigation",
		AuditID:           "audit.risk-critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || result.Results[0].Lease.ActionType != "runtime_action.deny_temporarily_source" || executor.calls != 1 {
		t.Fatalf("expected risk-derived runtime action, result=%#v calls=%d", result, executor.calls)
	}
}

func TestManagerRiskUnknownObserveProducesNoRuntimeAction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	executor := recordingExecutor{}
	manager := testManager(store, signer, now, testAdapter(testAdapterID, &executor))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))
	result, err := manager.ExecuteAction(ctx, ExecuteRequest{
		DecisionID:        "decision.risk-unknown",
		RiskType:          "runtime_anomaly",
		AdapterID:         testAdapterID,
		CapabilityID:      testCapabilityID,
		CapabilityGrantID: testCapabilityGrantID,
		Mode:              ActionModeRequired,
		TargetScope:       "source",
		TargetKey:         "source-risk",
		Reason:            "unknown risk should observe only",
		AuditID:           "audit.risk-unknown",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 0 || len(result.Plan.Actions) != 0 || executor.calls != 0 {
		t.Fatalf("expected no runtime action for unknown observe, result=%#v calls=%d", result, executor.calls)
	}
	decisions, err := store.RuntimeDecisions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Status != "no_action" {
		t.Fatalf("expected no_action decision journal, got %#v", decisions)
	}
}

func TestManagerDeniesNewActionWhenLocalAuditWriteFails(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	executor := &countingExecutor{}
	manager := testManager(store, signer, now, testAdapter(testAdapterID, executor))
	loadTestBundle(t, manager, ctx, signer, now, now.Add(time.Hour))
	manager.Store = auditFailStore{Store: store}

	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.audit-write-fails",
		TargetKey:  "source-audit-write-fails",
		Reason:     "test local audit write failure",
		AuditID:    "audit.audit-write-fails",
	}))
	if err == nil || !strings.Contains(err.Error(), "local audit write failed") {
		t.Fatalf("expected local audit failure to deny runtime action, got %v", err)
	}
	if executor.executeCalls != 0 {
		t.Fatalf("expected adapter not to be executed when audit write fails, got %d calls", executor.executeCalls)
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Fatalf("expected no lease after audit write failure, got %#v", leases)
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
	return signedBundleFileForBundle(t, signer, testRuntimeBundle(), signedAt, expiresAt)
}

func signedBundleFileForBundle(t *testing.T, signer *signing.DevLocalSigner, runtimeBundle corebundle.RuntimeBundle, signedAt, expiresAt time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime_bundle.signed.json")
	data := signedBundleDataForBundle(t, signer, runtimeBundle, signedAt, expiresAt)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func signedBundleData(t *testing.T, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) []byte {
	t.Helper()
	return signedBundleDataForBundle(t, signer, testRuntimeBundle(), signedAt, expiresAt)
}

func signedBundleDataForBundle(t *testing.T, signer *signing.DevLocalSigner, runtimeBundle corebundle.RuntimeBundle, signedAt, expiresAt time.Time) []byte {
	t.Helper()
	envelope := signedBundleEnvelopeForBundle(t, signer, runtimeBundle, signedAt, expiresAt)
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signedBundleEnvelope(t *testing.T, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) signing.SignedEnvelope {
	t.Helper()
	return signedBundleEnvelopeForBundle(t, signer, testRuntimeBundle(), signedAt, expiresAt)
}

func signedBundleEnvelopeForBundle(t *testing.T, signer *signing.DevLocalSigner, runtimeBundle corebundle.RuntimeBundle, signedAt, expiresAt time.Time) signing.SignedEnvelope {
	t.Helper()
	signer.Now = func() time.Time { return signedAt }
	payload, err := json.Marshal(runtimeBundle)
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

func signedAssignmentArtifact(t *testing.T, signer *signing.DevLocalSigner, now time.Time, artifactType, artifactID string, payload any) domain.KLIQAssignedArtifact {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	envelope, err := signer.Sign(context.Background(), data, signing.Metadata{
		SourceCommit: "abc123",
		ExpiresAt:    ptrTime(now.Add(time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelopeData, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return domain.KLIQAssignedArtifact{
		ArtifactType: artifactType,
		ArtifactID:   artifactID,
		SHA256:       domain.SHA256JSON(envelopeData),
		Envelope:     envelopeData,
	}
}

func ptrTime(value time.Time) *time.Time {
	return &value
}

func managedAssignmentSource(serverURL, trustKeyID string) *kliqbundle.ManagedAssignmentSource {
	return &kliqbundle.ManagedAssignmentSource{
		BaseURL:     serverURL,
		KLIQID:      "kliq.test",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
		TrustKeyID:  trustKeyID,
	}
}

func assertActiveManagedAssignment(t *testing.T, store actionstate.Store, ctx context.Context, version int64, rejectedDigest, activeBundleDigest string) {
	t.Helper()
	state, err := store.KLIQManagementState(ctx, "kliq.test")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveAssignmentVersion != version {
		t.Fatalf("expected active assignment version %d to remain, got %#v", version, state)
	}
	if state.ActiveAssignmentDigest == rejectedDigest {
		t.Fatalf("expected rejected assignment digest not to activate, got %#v", state)
	}
	bundle, err := store.LastBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.PayloadSHA256 != activeBundleDigest {
		t.Fatalf("expected previous bundle digest %q to remain active, got %#v", activeBundleDigest, bundle)
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
			RiskRecipe: "runtime_anomaly.standard",
			RiskBehavior: []corerisk.PolicyRiskBehavior{
				{RiskType: "risk_type.runtime_anomaly", Tier: "risk_tier.critical", Effect: "effect.deny_temporarily"},
				{RiskType: "risk_type.runtime_anomaly", Tier: "risk_tier.unknown", Effect: "effect.observe"},
			},
			CapabilityGrants: []corebundle.CapabilityGrant{
				{
					ID:                    testCapabilityGrantID,
					AdapterID:             testAdapterID,
					CapabilityID:          testCapabilityID,
					ActionType:            "runtime_action.deny_temporarily_source",
					BindingID:             "binding.test.klshield",
					BindingDigest:         "sha256:binding-test",
					AdapterManifestDigest: "sha256:adapter-manifest-test",
					ActionDigest:          "sha256:action-test",
					AllowedTargetScopes:   []string{"source"},
					MaxTTL:                "2m",
					Stage:                 "prod",
					Owner:                 "security-platform",
					ApprovalRef:           "build.policy.runtime",
				},
				{
					ID:                    "grant.nginx.klshield.runtime.source_mitigation",
					AdapterID:             testAdapterIDAlt,
					CapabilityID:          testCapabilityID,
					ActionType:            "runtime_action.deny_temporarily_source",
					BindingID:             "binding.test.nginx-klshield",
					BindingDigest:         "sha256:binding-nginx-klshield-test",
					AdapterManifestDigest: "sha256:adapter-manifest-nginx-test",
					ActionDigest:          "sha256:action-nginx-klshield-test",
					AllowedTargetScopes:   []string{"source"},
					MaxTTL:                "2m",
					Stage:                 "prod",
					Owner:                 "security-platform",
					ApprovalRef:           "build.policy.runtime",
				},
				{
					ID:                    "grant.klshield.nginx.runtime.route_mitigation",
					AdapterID:             testAdapterID,
					CapabilityID:          testCapabilityIDAlt,
					ActionType:            "runtime_action.deny_temporarily_source",
					BindingID:             "binding.test.klshield-nginx",
					BindingDigest:         "sha256:binding-klshield-nginx-test",
					AdapterManifestDigest: "sha256:adapter-manifest-klshield-test",
					ActionDigest:          "sha256:action-klshield-nginx-test",
					AllowedTargetScopes:   []string{"source"},
					MaxTTL:                "2m",
					Stage:                 "prod",
					Owner:                 "security-platform",
					ApprovalRef:           "build.policy.runtime",
				},
			},
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

type auditFailStore struct {
	actionstate.Store
}

func (s auditFailStore) AppendAudit(context.Context, actionstate.AuditRecord) error {
	return fmt.Errorf("audit spool unavailable")
}

type recordingExecutor struct {
	calls int
}

func (e *recordingExecutor) Execute(context.Context, actionstate.RuntimeActionLease, []byte) error {
	e.calls++
	return nil
}

func (e *recordingExecutor) Cleanup(context.Context, actionstate.RuntimeActionLease) error {
	return nil
}

type countingExecutor struct {
	executeCalls int
}

func (e *countingExecutor) Execute(context.Context, actionstate.RuntimeActionLease, []byte) error {
	e.executeCalls++
	return nil
}

func (e *countingExecutor) Cleanup(context.Context, actionstate.RuntimeActionLease) error {
	return nil
}
