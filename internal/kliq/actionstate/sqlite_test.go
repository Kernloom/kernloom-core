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
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
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

func TestSQLiteAuditSpoolBuildsHashChain(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	first := AuditRecord{ID: "audit_spool.1", RuntimeActionID: "runtime_action.1", Status: "pending_upload", Payload: `{"n":1}`, CreatedAt: now}
	second := AuditRecord{ID: "audit_spool.2", RuntimeActionID: "runtime_action.2", Status: "pending_upload", Payload: `{"n":2}`, CreatedAt: now.Add(time.Second)}
	if err := store.AppendAudit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(ctx, second); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two pending records, got %#v", records)
	}
	if records[0].RecordHash == "" || records[1].PreviousHash != records[0].RecordHash || records[1].RecordHash == "" {
		t.Fatalf("expected linked audit hash chain, got %#v", records)
	}
}

func TestSQLiteBaselineAndRiskCacheUnknownOnStale(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	version := baseline.VersionRef{VersionID: "baseline_version.test", View: baseline.ViewEntity, Entity: "opaque", CreatedAt: now}
	stats := baseline.Stats{VersionID: version.VersionID, Key: baseline.Key{View: version.View, Entity: version.Entity}, Metric: "metric", Center: 10, Spread: 1, SampleCount: 5, FrozenAt: now}
	if err := store.SaveBaselineVersion(ctx, version, []baseline.Stats{stats}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromoteBaselineVersion(ctx, baseline.PromotionDecision{
		DecisionID: "baseline_promotion.approve",
		VersionID:  version.VersionID,
		Action:     baseline.PromotionActionPromote,
		ApprovedBy: "security-platform",
		ApprovedAt: now,
		Reason:     "approved clean baseline for runtime risk",
	}); err != nil {
		t.Fatal(err)
	}
	active, ok, err := store.ActiveBaselineVersion(ctx, baseline.ViewEntity, "opaque")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || active.VersionID != version.VersionID {
		t.Fatalf("expected active baseline version, got %#v ok=%t", active, ok)
	}
	if err := store.SaveRiskContext(ctx, RiskCacheKey{RiskType: "runtime_anomaly", Scope: corerisk.ScopeLocal}, corerisk.RiskContext{
		RiskType:    "runtime_anomaly",
		Tier:        corerisk.TierHigh,
		Confidence:  0.9,
		Source:      "test",
		Scope:       corerisk.ScopeLocal,
		EvaluatedAt: now,
		ValidUntil:  now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	fresh, err := store.RiskContext(ctx, RiskCacheKey{RiskType: "runtime_anomaly", Scope: corerisk.ScopeLocal}, now)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Tier != corerisk.TierHigh {
		t.Fatalf("expected fresh high risk, got %#v", fresh)
	}
	stale, err := store.RiskContext(ctx, RiskCacheKey{RiskType: "runtime_anomaly", Scope: corerisk.ScopeLocal}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if stale.Tier != corerisk.TierUnknown {
		t.Fatalf("expected stale risk to become unknown, got %#v", stale)
	}
}

func TestSQLiteBaselinePromotionRejectAndRollbackAreAudited(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	v1 := baseline.VersionRef{VersionID: "baseline_version.v1", View: baseline.ViewEntity, Entity: "opaque", CreatedAt: now.Add(-2 * time.Hour)}
	v2 := baseline.VersionRef{VersionID: "baseline_version.v2", View: baseline.ViewEntity, Entity: "opaque", CreatedAt: now.Add(-time.Hour)}
	stats1 := baseline.Stats{VersionID: v1.VersionID, Key: baseline.Key{View: v1.View, Entity: v1.Entity}, Metric: "metric", Center: 10, Spread: 1, SampleCount: 5, FrozenAt: v1.CreatedAt}
	stats2 := baseline.Stats{VersionID: v2.VersionID, Key: baseline.Key{View: v2.View, Entity: v2.Entity}, Metric: "metric", Center: 20, Spread: 2, SampleCount: 5, FrozenAt: v2.CreatedAt}
	if err := store.SaveBaselineVersion(ctx, v1, []baseline.Stats{stats1}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBaselineVersion(ctx, v2, []baseline.Stats{stats2}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.ActiveBaselineVersion(ctx, baseline.ViewEntity, "opaque"); err != nil || ok {
		t.Fatalf("expected frozen versions to be inactive before promotion, ok=%t err=%v", ok, err)
	}
	if err := store.RejectBaselineVersion(ctx, baseline.PromotionDecision{
		DecisionID: "baseline_promotion.reject_v2",
		VersionID:  v2.VersionID,
		ApprovedBy: "security-platform",
		ApprovedAt: now,
		Reason:     "window overlaps maintenance activity",
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.ActiveBaselineVersion(ctx, baseline.ViewEntity, "opaque"); err != nil || ok {
		t.Fatalf("expected rejected version to stay inactive, ok=%t err=%v", ok, err)
	}
	if active, err := store.PromoteBaselineVersion(ctx, baseline.PromotionDecision{
		DecisionID: "baseline_promotion.promote_v1",
		VersionID:  v1.VersionID,
		Action:     baseline.PromotionActionPromote,
		ApprovedBy: "security-platform",
		ApprovedAt: now.Add(time.Minute),
		Reason:     "approved clean baseline",
	}); err != nil || active.VersionID != v1.VersionID {
		t.Fatalf("expected v1 promotion, active=%#v err=%v", active, err)
	}
	if active, err := store.PromoteBaselineVersion(ctx, baseline.PromotionDecision{
		DecisionID: "baseline_promotion.rollback_v1",
		VersionID:  v1.VersionID,
		Action:     baseline.PromotionActionRollback,
		ApprovedBy: "security-platform",
		ApprovedAt: now.Add(2 * time.Minute),
		Reason:     "rollback to last known clean baseline",
	}); err != nil || active.VersionID != v1.VersionID {
		t.Fatalf("expected rollback to v1, active=%#v err=%v", active, err)
	}
	decisions, err := store.BaselinePromotionDecisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 3 {
		t.Fatalf("expected three audited decisions, got %#v", decisions)
	}
}
