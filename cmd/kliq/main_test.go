// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqruntime "github.com/kernloom/kernloom-core/internal/kliq/runtime"
)

func TestStatusRedactionHelpersDoNotReturnRawSensitiveValues(t *testing.T) {
	target := "203.0.113.10"
	if got := redactedHash(target); got == "" || got == target {
		t.Fatalf("expected target hash redaction, got %q", got)
	}

	correlationID := "correlation.long-sensitive-context-id"
	if got := redactID(correlationID); got == "" || got == correlationID {
		t.Fatalf("expected shortened id redaction, got %q", got)
	}
}

func TestStatusSnapshotAndAPIAreRedacted(t *testing.T) {
	store := openStatusTestStore(t)
	defer store.Close()
	seedStatusTestStore(t, store)

	snapshot, err := snapshotForTests(store)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONDoesNotContain(t, snapshot, "203.0.113.10", "secret-token", "journal secret", "idem.secret")

	handler := statusAPIHandler(store, "test-state.db")
	for _, path := range []string{"/status", "/runtime/actions", "/runtime/actions/runtime_action.test", "/audit/pending"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned status %d: %s", path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, forbidden := range []string{"203.0.113.10", "secret-token", "journal secret", "idem.secret"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s leaked forbidden value %q in %s", path, forbidden, body)
			}
		}
	}
}

func TestStatusAPIRequiresLoopbackListenAddress(t *testing.T) {
	if err := validateLocalListenAddress("127.0.0.1:18090"); err != nil {
		t.Fatalf("expected loopback address to be accepted, got %v", err)
	}
	if err := validateLocalListenAddress("0.0.0.0:18090"); err == nil {
		t.Fatal("expected wildcard listen address to be rejected")
	}
}

func openStatusTestStore(t *testing.T) *actionstate.SQLiteStore {
	t.Helper()
	store, err := actionstate.OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func seedStatusTestStore(t *testing.T, store *actionstate.SQLiteStore) {
	t.Helper()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	err := store.SaveBundle(t.Context(), actionstate.BundleRecord{
		BundleID:      "runtime_bundle.policy.test",
		PolicyID:      "policy.test",
		SourceCommit:  "abcdef1234567890",
		CorrelationID: "correlation.secret-sensitive-test-value",
		KeyID:         "key.secret-sensitive-test-value",
		PayloadSHA256: "sha256:payload",
		BundleSource:  "/tmp/secret-token/runtime_bundle.signed.json",
		EnvelopeJSON:  []byte(`{"secret":"secret-token"}`),
		ExpiresAt:     now.Add(time.Hour),
		VerifiedAt:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := actionstate.RuntimeActionLease{
		RuntimeActionID:   "runtime_action.test",
		PlanID:            "runtime_action_plan.test",
		DecisionID:        "decision.test",
		PolicyID:          "policy.test",
		BundleID:          "runtime_bundle.policy.test",
		SourceCommit:      "abcdef1234567890",
		CorrelationID:     "correlation.secret-sensitive-test-value",
		ActionType:        "runtime_action.deny_temporarily_source",
		TargetScope:       "source",
		TargetKey:         "203.0.113.10",
		TTL:               "1m",
		ExpiresAt:         now.Add(time.Minute),
		Reason:            "secret-token reason",
		AuditID:           "audit.test",
		CapabilityGrantID: "grant.test",
		AdapterID:         "kernloom.adapter.klshield",
		CapabilityID:      "klshield.runtime.source_mitigation",
		Mode:              kliqruntime.ActionModeRequired,
		Required:          true,
		IdempotencyKey:    "idem.secret",
		CreatedAt:         now,
		LastReconciledAt:  now,
		Status:            domain.RuntimeActionActive,
	}
	if err := store.UpsertLease(t.Context(), lease); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendJournal(t.Context(), actionstate.JournalEntry{
		ID:              "journal.test",
		RuntimeActionID: lease.RuntimeActionID,
		Event:           "activated",
		Status:          domain.RuntimeActionActive,
		Message:         "journal secret-token message",
		CreatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(t.Context(), actionstate.AuditRecord{
		ID:              "audit_spool.test",
		RuntimeActionID: lease.RuntimeActionID,
		Status:          kliqruntime.AuditPendingUpload,
		Payload:         `{"secret":"secret-token"}`,
		CreatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
}

func assertJSONDoesNotContain(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, needle := range forbidden {
		if strings.Contains(text, needle) {
			t.Fatalf("JSON leaked forbidden value %q in %s", needle, text)
		}
	}
}
