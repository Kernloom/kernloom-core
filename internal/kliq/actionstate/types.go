// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actionstate

import (
	"context"
	"errors"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
)

var ErrNotFound = errors.New("kliq state record not found")

type BundleRecord struct {
	BundleID      string
	PolicyID      string
	SourceCommit  string
	CorrelationID string
	KeyID         string
	PayloadSHA256 string
	BundleSource  string
	EnvelopeJSON  []byte
	ExpiresAt     time.Time
	VerifiedAt    time.Time
}

type AssignmentArtifactRecord struct {
	KLIQID            string
	AssignmentID      string
	AssignmentVersion int64
	ArtifactType      string
	ArtifactID        string
	ArtifactRef       string
	SHA256            string
	EnvelopeJSON      []byte
	ActivationStatus  string
	ActivationMessage string
	ActivatedAt       time.Time
}

type ActiveArtifactRecord struct {
	KLIQID       string
	ArtifactType string
	ArtifactID   string
	SHA256       string
	PayloadJSON  []byte
	ActivatedAt  time.Time
}

type KLIQManagementState struct {
	KLIQID                       string
	ActiveAssignmentID           string
	ActiveAssignmentVersion      int64
	ActiveAssignmentSourceCommit string
	ActiveAssignmentDigest       string
	ActiveAssignmentExpiresAt    time.Time
	ActiveAssignmentActivatedAt  time.Time
}

type KLIQCredential struct {
	KLIQID                  string
	NodeID                  string
	Environment             string
	Stage                   string
	Scope                   string
	TrustKeyID              string
	AssignmentURL           string
	PublicKeyPEM            string
	PrivateKeyPEM           string
	ServiceIdentityProvider string
	SPIFFEID                string
	CredentialStatus        string
	ServiceToken            string
	ServiceTokenExpiresAt   time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type LocalTrustBundleRecord struct {
	KeyID       string
	BundleJSON  []byte
	PersistedAt time.Time
}

type RuntimeActionLease struct {
	RuntimeActionID       string
	PlanID                string
	DecisionID            string
	PolicyID              string
	BundleID              string
	SourceCommit          string
	CorrelationID         string
	ActionType            string
	TargetScope           string
	TargetKey             string
	TTL                   string
	ExpiresAt             time.Time
	Reason                string
	AuditID               string
	CapabilityGrantID     string
	BindingID             string
	BindingDigest         string
	AdapterManifestDigest string
	ActionDigest          string
	AdapterID             string
	CapabilityID          string
	Mode                  string
	Required              bool
	IdempotencyKey        string
	CreatedAt             time.Time
	LastReconciledAt      time.Time
	Status                domain.RuntimeActionStatus
}

type RuntimeActionSelector struct {
	RuntimeActionID string
	IdempotencyKey  string
	AdapterID       string
	CapabilityID    string
	ActionType      string
	TargetScope     string
	TargetKey       string
}

func (lease RuntimeActionLease) Selector() RuntimeActionSelector {
	return RuntimeActionSelector{
		RuntimeActionID: lease.RuntimeActionID,
		IdempotencyKey:  lease.IdempotencyKey,
		AdapterID:       lease.AdapterID,
		CapabilityID:    lease.CapabilityID,
		ActionType:      lease.ActionType,
		TargetScope:     lease.TargetScope,
		TargetKey:       lease.TargetKey,
	}
}

func (selector RuntimeActionSelector) Valid() bool {
	return selector.RuntimeActionID != "" &&
		selector.IdempotencyKey != "" &&
		selector.AdapterID != "" &&
		selector.CapabilityID != "" &&
		selector.ActionType != "" &&
		selector.TargetScope != "" &&
		selector.TargetKey != ""
}

func (lease RuntimeActionLease) Validate() error {
	required := map[string]string{
		"runtime_action_id":   lease.RuntimeActionID,
		"plan_id":             lease.PlanID,
		"decision_id":         lease.DecisionID,
		"policy_id":           lease.PolicyID,
		"bundle_id":           lease.BundleID,
		"source_commit":       lease.SourceCommit,
		"adapter_id":          lease.AdapterID,
		"capability_id":       lease.CapabilityID,
		"mode":                lease.Mode,
		"action_type":         lease.ActionType,
		"target_scope":        lease.TargetScope,
		"target_key":          lease.TargetKey,
		"ttl":                 lease.TTL,
		"reason":              lease.Reason,
		"audit_id":            lease.AuditID,
		"capability_grant_id": lease.CapabilityGrantID,
		"idempotency_key":     lease.IdempotencyKey,
		"status":              string(lease.Status),
	}
	for field, value := range required {
		if value == "" {
			return errors.New("runtime action lease missing required field " + field)
		}
	}
	if lease.ExpiresAt.IsZero() {
		return errors.New("runtime action lease missing required field expires_at")
	}
	if lease.CreatedAt.IsZero() {
		return errors.New("runtime action lease missing required field created_at")
	}
	if lease.LastReconciledAt.IsZero() {
		return errors.New("runtime action lease missing required field last_reconciled_at")
	}
	return nil
}

type JournalEntry struct {
	ID              string
	RuntimeActionID string
	Event           string
	Status          domain.RuntimeActionStatus
	Message         string
	CreatedAt       time.Time
}

type AuditRecord struct {
	ID                    string
	RuntimeActionID       string
	BindingID             string
	BindingDigest         string
	AdapterManifestDigest string
	ActionDigest          string
	Status                string
	Payload               string
	PayloadSHA256         string
	PreviousHash          string
	RecordHash            string
	CreatedAt             time.Time
	RetryCount            int
	LastAttemptAt         time.Time
	UploadedAt            time.Time
	LastError             string
}

type RuntimeDecisionRecord struct {
	DecisionID      string
	PlanID          string
	PolicyID        string
	BundleID        string
	SourceCommit    string
	CorrelationID   string
	EventType       string
	EventID         string
	Status          string
	PayloadSHA256   string
	CreatedAt       time.Time
	ActivatedAction string
}

type RiskCacheKey struct {
	RiskType string
	Scope    string
}

type Store interface {
	SaveBundle(ctx context.Context, record BundleRecord) error
	LastBundle(ctx context.Context) (BundleRecord, error)
	SaveManagedBundleActivation(ctx context.Context, record BundleRecord, state KLIQManagementState, artifacts []AssignmentArtifactRecord) error
	AssignmentArtifacts(ctx context.Context, kliqID string) ([]AssignmentArtifactRecord, error)
	ActiveArtifact(ctx context.Context, kliqID, artifactType string) (ActiveArtifactRecord, error)
	SaveKLIQCredential(ctx context.Context, credential KLIQCredential) error
	KLIQCredential(ctx context.Context) (KLIQCredential, error)
	SaveLocalTrustBundle(ctx context.Context, bundle domain.TrustBundle, persistedAt time.Time) error
	LastLocalTrustBundle(ctx context.Context) (domain.TrustBundle, error)
	SaveKLIQManagementState(ctx context.Context, state KLIQManagementState) error
	KLIQManagementState(ctx context.Context, kliqID string) (KLIQManagementState, error)
	UpsertLease(ctx context.Context, lease RuntimeActionLease) error
	LeaseByDedupKey(ctx context.Context, adapterID, capabilityID, actionType, targetScope, targetKey string) (RuntimeActionLease, error)
	LeaseByID(ctx context.Context, runtimeActionID string) (RuntimeActionLease, error)
	ActiveLeases(ctx context.Context) ([]RuntimeActionLease, error)
	AllLeases(ctx context.Context) ([]RuntimeActionLease, error)
	ExpireLease(ctx context.Context, runtimeActionID string, reconciledAt time.Time) error
	AppendJournal(ctx context.Context, entry JournalEntry) error
	JournalEntries(ctx context.Context, runtimeActionID string) ([]JournalEntry, error)
	AppendAudit(ctx context.Context, record AuditRecord) error
	PendingAudits(ctx context.Context) ([]AuditRecord, error)
	MarkAuditUploaded(ctx context.Context, id string, uploadedAt time.Time) error
	MarkAuditFailed(ctx context.Context, id string, attemptedAt time.Time, message string) error
	AppendRuntimeDecision(ctx context.Context, record RuntimeDecisionRecord) error
	RuntimeDecisions(ctx context.Context, limit int) ([]RuntimeDecisionRecord, error)
	SaveBaselineWindow(ctx context.Context, window baseline.Window) error
	SaveBaselineVersion(ctx context.Context, version baseline.VersionRef, stats []baseline.Stats) error
	PromoteBaselineVersion(ctx context.Context, decision baseline.PromotionDecision) (baseline.VersionRef, error)
	RejectBaselineVersion(ctx context.Context, decision baseline.PromotionDecision) error
	BaselinePromotionDecisions(ctx context.Context) ([]baseline.PromotionDecision, error)
	ActiveBaselineVersion(ctx context.Context, view, entity string) (baseline.VersionRef, bool, error)
	BaselineStats(ctx context.Context, versionID, metric string) (baseline.Stats, error)
	SaveBaselineDeviation(ctx context.Context, event baseline.DeviationEvent) error
	SaveRiskContext(ctx context.Context, key RiskCacheKey, riskContext corerisk.RiskContext) error
	RiskContext(ctx context.Context, key RiskCacheKey, now time.Time) (corerisk.RiskContext, error)
	Close() error
}
