// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actionstate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
)

func TestOpenSQLiteCreatesStateFileWithPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected state db mode 0600, got %o", got)
	}
}

func TestSQLiteAppliesVersionedMigrationsAndActiveArtifacts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	if len(versions) != len(sqliteMigrations()) {
		t.Fatalf("expected %d sqlite migrations, got %#v", len(sqliteMigrations()), versions)
	}
	envelopeJSON, err := json.Marshal(struct {
		Payload []byte `json:"payload"`
	}{Payload: []byte(`{"kind":"RuntimeBundle"}`)})
	if err != nil {
		t.Fatal(err)
	}
	trustBundle := domain.TrustBundle{
		KeyID:     "forge-management-prod",
		PublicKey: "public-key",
		Purpose:   "assignment_verification",
		Status:    "active",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Issuer:    "test",
	}
	trustPayload, err := json.Marshal(trustBundle)
	if err != nil {
		t.Fatal(err)
	}
	trustEnvelopeJSON, err := json.Marshal(struct {
		Payload []byte `json:"payload"`
	}{Payload: trustPayload})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.SaveManagedBundleActivation(ctx, BundleRecord{
		BundleID:      "runtime_bundle.test",
		PolicyID:      "policy.test",
		SourceCommit:  "abc123",
		KeyID:         "dev-local",
		PayloadSHA256: "sha256:bundle",
		BundleSource:  "test",
		EnvelopeJSON:  envelopeJSON,
		ExpiresAt:     now.Add(time.Hour),
		VerifiedAt:    now,
	}, KLIQManagementState{
		KLIQID:                       "kliq.test",
		ActiveAssignmentID:           "assignment.test",
		ActiveAssignmentVersion:      1,
		ActiveAssignmentSourceCommit: "abc123",
		ActiveAssignmentDigest:       "sha256:assignment",
		ActiveAssignmentExpiresAt:    now.Add(time.Hour),
		ActiveAssignmentActivatedAt:  now,
	}, []AssignmentArtifactRecord{{
		KLIQID:            "kliq.test",
		AssignmentID:      "assignment.test",
		AssignmentVersion: 1,
		ArtifactType:      "runtime_bundle",
		ArtifactID:        "runtime_bundle.test",
		SHA256:            "sha256:artifact",
		EnvelopeJSON:      envelopeJSON,
		ActivationStatus:  "activated",
		ActivatedAt:       now,
	}, {
		KLIQID:            "kliq.test",
		AssignmentID:      "assignment.test",
		AssignmentVersion: 1,
		ArtifactType:      "trust_bundle",
		ArtifactID:        "trust_bundle.test",
		SHA256:            "sha256:trust",
		EnvelopeJSON:      trustEnvelopeJSON,
		ActivationStatus:  "activated",
		ActivatedAt:       now,
	}}); err != nil {
		t.Fatal(err)
	}
	active, err := store.ActiveArtifact(ctx, "kliq.test", "runtime_bundle")
	if err != nil {
		t.Fatal(err)
	}
	if string(active.PayloadJSON) != `{"kind":"RuntimeBundle"}` {
		t.Fatalf("unexpected active artifact payload %s", string(active.PayloadJSON))
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.LastLocalTrustBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.KeyID != trustBundle.KeyID || persisted.PublicKey != trustBundle.PublicKey || persisted.Purpose != "assignment_verification" {
		t.Fatalf("expected assignment trust bundle to persist after restart, got %#v", persisted)
	}
}

func TestOpenSQLiteRejectsGroupOrWorldAccessibleStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(path); err == nil {
		t.Fatal("expected group/world-readable state db to be rejected")
	}
}

func TestSQLitePersistsLocalTrustBundle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle := domain.TrustBundle{
		KeyID:     "forge-management-dev-local",
		PublicKey: "public-key",
		Purpose:   "assignment_verification",
		Status:    "active",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Issuer:    "test",
	}
	if err := store.SaveLocalTrustBundle(ctx, bundle, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.LastLocalTrustBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.KeyID != bundle.KeyID || persisted.PublicKey != bundle.PublicKey {
		t.Fatalf("unexpected persisted trust bundle %#v", persisted)
	}
}

func TestSQLiteAuditSpoolDeduplicatesSamePayloadHash(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := AuditRecord{
		ID:              "audit_spool.duplicate",
		RuntimeActionID: "runtime_action.test",
		Status:          "pending_upload",
		Payload:         `{"status":"active"}`,
		CreatedAt:       time.Now().UTC(),
	}
	if err := store.AppendAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(ctx, record); err != nil {
		t.Fatalf("expected duplicate same payload hash to be idempotent: %v", err)
	}
	record.Payload = `{"status":"expired"}`
	if err := store.AppendAudit(ctx, record); err == nil {
		t.Fatal("expected duplicate audit id with different payload hash to be rejected")
	}
}
