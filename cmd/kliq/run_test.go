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
	"sync/atomic"
	"testing"
	"time"

	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
)

func TestKLIQRunManagedOncePollsAssignmentAndReports(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
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
		Mode:               kliqRunModeManaged,
		StatePath:          statePath,
		TrustBundlePath:    keyPath,
		DevAllowPrivateKey: true,
		Once:               true,
		HTTPClient:         server.Client(),
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

func TestKLIQRunStandaloneOnceLoadsBundleWithRuntimeCore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
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
		opts:       runOptions{Mode: kliqRunModeManaged},
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
