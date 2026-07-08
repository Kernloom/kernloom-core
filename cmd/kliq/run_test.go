// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
	"github.com/kernloom/kernloom-core/internal/kliq/signals/projector"
)

func TestKLIQRunManagedOncePollsAssignmentAndReports(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	keyPath := filepath.Join(t.TempDir(), "management.ed25519.json")
	signer := runTestSigner(t, keyPath, now)
	runtimeEnvelope := runTestSignedBundleJSON(t, signer, now, now.Add(time.Hour))
	assignment := runTestSignedAssignment(t, signer, runTestAssignment(now, signer.KeyID, 1, runtimeEnvelope), now.Add(time.Hour))
	var assignmentPulls atomic.Int64
	var heartbeats atomic.Int64
	var statuses atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kliq/assignments/kliq.test/latest":
			assignmentPulls.Add(1)
			if r.Header.Get("Authorization") != "Bearer service-token" {
				t.Fatalf("missing service token auth header")
			}
			_ = json.NewEncoder(w).Encode(assignment)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/kliq/heartbeat":
			heartbeats.Add(1)
			var heartbeat domain.KLIQHeartbeat
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Fatal(err)
			}
			if heartbeat.KLIQID != "kliq.test" || heartbeat.AssignmentVersion != 1 {
				t.Fatalf("unexpected heartbeat %#v", heartbeat)
			}
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/kliq/status-reports":
			statuses.Add(1)
			var report domain.KLIQStatusReport
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Fatal(err)
			}
			if report.KLIQID != "kliq.test" || report.AssignmentVersion != 1 {
				t.Fatalf("unexpected status report %#v", report)
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKLIQCredential(ctx, actionstate.KLIQCredential{
		KLIQID:                "kliq.test",
		NodeID:                "node-1",
		Environment:           "prod",
		Stage:                 "prod",
		Scope:                 "edge-prod",
		TrustKeyID:            signer.KeyID,
		AssignmentURL:         server.URL,
		PublicKeyPEM:          "public",
		PrivateKeyPEM:         "private",
		ServiceToken:          "service-token",
		ServiceTokenExpiresAt: now.Add(time.Hour),
		CreatedAt:             now,
		UpdatedAt:             now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if err := runKLIQ(ctx, runOptions{
		Mode:                      kliqRunModeManaged,
		StatePath:                 statePath,
		TrustBundlePath:           keyPath,
		DevAllowPrivateKey:        true,
		DevInsecureForgeTransport: true,
		Once:                      true,
		HTTPClient:                server.Client(),
	}); err != nil {
		t.Fatal(err)
	}
	if assignmentPulls.Load() != 1 || heartbeats.Load() != 1 || statuses.Load() != 1 {
		t.Fatalf("expected one assignment pull, heartbeat and status, got pull=%d heartbeat=%d status=%d", assignmentPulls.Load(), heartbeats.Load(), statuses.Load())
	}
	reopened, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, err := reopened.KLIQManagementState(ctx, "kliq.test")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveAssignmentVersion != 1 || state.ActiveAssignmentDigest != assignment.PayloadSHA256 {
		t.Fatalf("unexpected active assignment state %#v", state)
	}
}

func TestKLIQProductionOptionsRejectDebugPaths(t *testing.T) {
	valid := runOptions{
		Mode:            kliqRunModeManaged,
		ForgeURL:        "https://forge.example",
		Production:      true,
		StatePath:       filepath.Join(t.TempDir(), "state.db"),
		TrustBundlePath: filepath.Join(t.TempDir(), "trust.json"),
	}
	if err := validateKLIQProductionOptions(valid); err != nil {
		t.Fatalf("expected valid production options, got %v", err)
	}
	invalid := valid
	invalid.Once = true
	if err := validateKLIQProductionOptions(invalid); err == nil || !strings.Contains(err.Error(), "--once") {
		t.Fatalf("expected once rejection, got %v", err)
	}
	invalid = valid
	invalid.DecisionSource = "events.json"
	if err := validateKLIQProductionOptions(invalid); err == nil || !strings.Contains(err.Error(), "decision-source") {
		t.Fatalf("expected decision source rejection, got %v", err)
	}
	invalid = valid
	invalid.Adapters = []string{"kernloom.adapter.klshield=127.0.0.1:7443"}
	if err := validateKLIQProductionOptions(invalid); err == nil || !strings.Contains(err.Error(), "adapter") {
		t.Fatalf("expected adapter flag rejection, got %v", err)
	}
	invalid = valid
	invalid.ForgeURL = "http://forge.example"
	if err := validateKLIQProductionOptions(invalid); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("expected plaintext forge url rejection, got %v", err)
	}
}

func TestKLIQRunStandaloneOnceLoadsBundleWithRuntimeCore(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	keyPath := filepath.Join(t.TempDir(), "management.ed25519.json")
	signer := runTestSigner(t, keyPath, now)
	bundlePath := filepath.Join(t.TempDir(), "runtime_bundle.signed.json")
	if err := os.WriteFile(bundlePath, runTestSignedBundleJSON(t, signer, now, now.Add(time.Hour)), 0o644); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "state.db")

	if err := runKLIQ(ctx, runOptions{
		Mode:               kliqRunModeStandalone,
		StatePath:          statePath,
		TrustBundlePath:    keyPath,
		DevAllowPrivateKey: true,
		BundleSource:       "file://" + filepath.Dir(bundlePath),
		Once:               true,
	}); err != nil {
		t.Fatal(err)
	}
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record, err := store.LastBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.BundleID != "runtime_bundle.policy.runtime" || record.PolicyID != "policy.runtime" {
		t.Fatalf("unexpected bundle record %#v", record)
	}
}

func TestRuntimeDecisionSourceFromFileReadsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	data := []byte(`[
		{
			"decision_id": "decision.local.1",
			"adapter_id": "adapter.test",
			"capability_id": "capability.test",
			"capability_grant_id": "grant.test",
			"action_type": "runtime_action.deny_temporarily_source",
			"target_scope": "source",
			"target_key": "192.0.2.10",
			"ttl": "30s",
			"reason": "local decision source smoke",
			"audit_id": "audit.local.1"
		}
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := runtimeDecisionSourceFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	req, ok, err := source.NextDecision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || req.DecisionID != "decision.local.1" || req.AdapterID != "adapter.test" {
		t.Fatalf("unexpected decision source result ok=%v req=%#v", ok, req)
	}
	_, ok, err = source.NextDecision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected decision source to be exhausted")
	}
}

func TestRuntimeDecisionSourceFromFileReadsLocalRuntimeEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	data := []byte(`{
		"kind": "LocalRuntimeEvent",
		"event_id": "event.local.1",
		"event_type": "baseline_deviation",
		"adapter_id": "adapter.test",
		"capability_id": "capability.test",
		"capability_grant_id": "grant.test",
		"action_type": "runtime_action.deny_temporarily_source",
		"target_scope": "source",
		"target_key": "192.0.2.10",
		"ttl": "30s",
		"reason": "local event source smoke",
		"correlation_id": "correlation.local.event"
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := runtimeDecisionSourceFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	req, ok, err := source.NextDecision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.HasPrefix(req.DecisionID, "runtime_decision.") || req.AdapterID != "adapter.test" || req.AuditID == "" {
		t.Fatalf("unexpected local runtime event decision result ok=%v req=%#v", ok, req)
	}
	if req.CorrelationID != "correlation.local.event" || req.Reason != "local event source smoke" {
		t.Fatalf("expected event metadata to propagate, got %#v", req)
	}
}

func TestKLIQDaemonIngestsKLShieldSignalIntoRiskCache(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	version := baseline.VersionRef{
		VersionID: "baseline_version.active",
		View:      baseline.ViewEntity,
		Entity:    "klshield:edge-prod",
		CreatedAt: now.Add(-time.Hour),
	}
	if err := store.SaveBaselineVersion(ctx, version, []baseline.Stats{{
		VersionID:   version.VersionID,
		Key:         baseline.Key{View: baseline.ViewEntity, Entity: "klshield:edge-prod"},
		Metric:      "active_runtime_actions",
		Center:      1,
		Spread:      1,
		SampleCount: 5,
		FrozenAt:    now.Add(-time.Hour),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromoteBaselineVersion(ctx, baseline.PromotionDecision{
		DecisionID: "baseline_promotion.active",
		VersionID:  version.VersionID,
		Action:     baseline.PromotionActionPromote,
		ApprovedBy: "security-platform",
		ApprovedAt: now.Add(-time.Hour),
		Reason:     "test active baseline",
	}); err != nil {
		t.Fatal(err)
	}
	daemon := &runDaemon{
		opts:       runOptions{BaselineRiskRecipe: "runtime_anomaly.standard", BaselineMinSamples: 5},
		store:      store,
		credential: actionstate.KLIQCredential{KLIQID: "kliq.test", Scope: "edge-prod"},
		signalReaders: map[string]AdapterSignalReader{
			projector.KLShieldAdapterID: fakeAdapterSignalReader{signals: []baseline.AdapterSignal{{
				AdapterID:  projector.KLShieldAdapterID,
				SignalID:   "signal.1",
				SignalType: "klshield.runtime_action_counts",
				Labels:     map[string]string{"entity": "edge-prod"},
				Metrics:    map[string]float64{"active_runtime_actions": 10},
				ObservedAt: now,
			}}},
		},
		baselineSamples: map[string][]baseline.Sample{},
		now:             func() time.Time { return now },
	}
	if err := daemon.processAdapterSignals(ctx); err != nil {
		t.Fatal(err)
	}
	riskContext, err := store.RiskContext(ctx, actionstate.RiskCacheKey{RiskType: "runtime_anomaly", Scope: corerisk.ScopeLocal}, now)
	if err != nil {
		t.Fatal(err)
	}
	if riskContext.Tier != corerisk.TierCritical || riskContext.Source != "baseline.local" {
		t.Fatalf("expected critical baseline risk context, got %#v", riskContext)
	}
}

func TestKLIQRunFlushesAuditSpoolToForge(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	var uploads atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/kliq/audit-events" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer service-token" {
			t.Fatalf("missing service token auth header")
		}
		var upload domain.KLIQAuditUpload
		if err := json.NewDecoder(r.Body).Decode(&upload); err != nil {
			t.Fatal(err)
		}
		if upload.KLIQID != "kliq.test" || upload.AuditRecordID != "audit_spool.flush" || upload.PayloadSHA256 == "" {
			t.Fatalf("unexpected audit upload %#v", upload)
		}
		uploads.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(domain.KLIQAuditUploadAck{
			Status:        "accepted",
			AuditRecordID: upload.AuditRecordID,
			AckID:         "ack.test",
			AckedAt:       now,
		})
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SaveKLIQCredential(ctx, actionstate.KLIQCredential{
		KLIQID:                "kliq.test",
		NodeID:                "node-1",
		Environment:           "prod",
		Stage:                 "prod",
		Scope:                 "edge-prod",
		TrustKeyID:            "forge-management-dev-local",
		AssignmentURL:         server.URL,
		PublicKeyPEM:          "public",
		PrivateKeyPEM:         "private",
		ServiceToken:          "service-token",
		ServiceTokenExpiresAt: now.Add(time.Hour),
		CreatedAt:             now,
		UpdatedAt:             now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(ctx, actionstate.AuditRecord{
		ID:              "audit_spool.flush",
		RuntimeActionID: "runtime_action.flush",
		Status:          "pending_upload",
		Payload:         `{"event":"flush"}`,
		CreatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	daemon := &runDaemon{
		opts:       runOptions{Mode: kliqRunModeManaged, DevInsecureForgeTransport: true},
		store:      store,
		credential: mustKLIQCredential(t, store),
		httpClient: server.Client(),
		now:        func() time.Time { return now },
	}
	if err := daemon.flushAuditSpool(ctx); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 1 {
		t.Fatalf("expected one audit upload, got %d", uploads.Load())
	}
	pending, err := store.PendingAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected uploaded audit to leave pending set, got %#v", pending)
	}
}

func TestKLIQRunStandaloneAuditSpoolRemainsLocalOffline(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AppendAudit(ctx, actionstate.AuditRecord{
		ID:              "audit_spool.local",
		RuntimeActionID: "runtime_action.local",
		Status:          "pending_upload",
		Payload:         `{"event":"local"}`,
		CreatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	daemon := &runDaemon{
		opts:  runOptions{Mode: kliqRunModeStandalone},
		store: store,
		now:   func() time.Time { return now },
	}
	if err := daemon.flushAuditSpool(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected standalone audit spool to remain local, got %#v", pending)
	}
	if len(daemon.findings) != 1 || !strings.Contains(daemon.findings[0], "local/offline") {
		t.Fatalf("expected standalone audit export finding, got %#v", daemon.findings)
	}
}

type fakeAdapterSignalReader struct {
	signals []baseline.AdapterSignal
	err     error
}

func (r fakeAdapterSignalReader) ReadSignals(context.Context, string) ([]baseline.AdapterSignal, error) {
	return append([]baseline.AdapterSignal(nil), r.signals...), r.err
}

func runTestSigner(t *testing.T, keyPath string, now time.Time) *signing.DevLocalSigner {
	t.Helper()
	signer, err := signing.LoadOrCreateDevLocalSigner(keyPath, "forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	return signer
}

func mustKLIQCredential(t *testing.T, store *actionstate.SQLiteStore) actionstate.KLIQCredential {
	t.Helper()
	credential, err := store.KLIQCredential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func runTestSignedBundleJSON(t *testing.T, signer *signing.DevLocalSigner, signedAt, expiresAt time.Time) []byte {
	t.Helper()
	signer.Now = func() time.Time { return signedAt }
	payload, err := json.Marshal(runTestRuntimeBundle())
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
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runTestAssignment(now time.Time, trustKeyID string, version int64, runtimeEnvelope []byte) domain.KLIQAssignment {
	return domain.KLIQAssignment{
		AssignmentID:      "kliq_assignment.test",
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
			ArtifactID:   "runtime_bundle.policy.runtime",
			SHA256:       domain.SHA256JSON(runtimeEnvelope),
			Envelope:     append([]byte(nil), runtimeEnvelope...),
		}},
		Status: "active",
	}
}

func runTestSignedAssignment(t *testing.T, signer *signing.DevLocalSigner, assignment domain.KLIQAssignment, expiresAt time.Time) signing.SignedEnvelope {
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

func runTestRuntimeBundle() corebundle.RuntimeBundle {
	return corebundle.RuntimeBundle{
		Kind: "RuntimeBundle",
		Metadata: coreartifact.Metadata{
			ID:            "runtime_bundle.policy.runtime",
			PolicyID:      "policy.runtime",
			ArtifactType:  "runtime_bundle",
			SourceCommit:  "abc123",
			CorrelationID: "correlation.run.test",
			CreatedAt:     time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC),
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
		Status: coreartifact.PlannedStatus("slice 5.10 daemon test bundle"),
	}
}
