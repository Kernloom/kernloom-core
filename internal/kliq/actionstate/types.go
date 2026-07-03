// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actionstate

import (
	"context"
	"errors"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
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

type KLIQManagementState struct {
	KLIQID                       string
	ActiveAssignmentID           string
	ActiveAssignmentVersion      int64
	ActiveAssignmentSourceCommit string
	ActiveAssignmentDigest       string
	ActiveAssignmentExpiresAt    time.Time
	ActiveAssignmentActivatedAt  time.Time
}

type RuntimeActionLease struct {
	RuntimeActionID   string
	PlanID            string
	DecisionID        string
	PolicyID          string
	BundleID          string
	SourceCommit      string
	CorrelationID     string
	ActionType        string
	TargetScope       string
	TargetKey         string
	TTL               string
	ExpiresAt         time.Time
	Reason            string
	AuditID           string
	CapabilityGrantID string
	AdapterID         string
	CapabilityID      string
	Mode              string
	Required          bool
	IdempotencyKey    string
	CreatedAt         time.Time
	LastReconciledAt  time.Time
	Status            domain.RuntimeActionStatus
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
	ID              string
	RuntimeActionID string
	Status          string
	Payload         string
	CreatedAt       time.Time
}

type Store interface {
	SaveBundle(ctx context.Context, record BundleRecord) error
	LastBundle(ctx context.Context) (BundleRecord, error)
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
	Close() error
}
