// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqruntime "github.com/kernloom/kernloom-core/internal/kliq/runtime"
)

type statusSnapshot struct {
	GeneratedAt       string              `json:"generated_at"`
	StatePath         string              `json:"state_path"`
	Assignment        *assignmentView     `json:"assignment,omitempty"`
	Bundle            *bundleStatusView   `json:"bundle,omitempty"`
	RuntimeActions    []runtimeActionView `json:"runtime_actions"`
	RuntimeCounts     map[string]int      `json:"runtime_counts"`
	PendingAuditCount int                 `json:"pending_audit_count"`
	Adapters          []adapterStatusView `json:"adapters"`
	Findings          []string            `json:"findings,omitempty"`
}

type assignmentView struct {
	KLIQID          string `json:"kliq_id"`
	AssignmentID    string `json:"assignment_id"`
	Version         int64  `json:"version"`
	SourceCommit    string `json:"source_commit"`
	Digest          string `json:"digest"`
	ExpiresAt       string `json:"expires_at"`
	ActivatedAt     string `json:"activated_at"`
	CredentialState string `json:"credential_state,omitempty"`
}

type bundleStatusView struct {
	BundleID           string `json:"bundle_id"`
	PolicyID           string `json:"policy_id"`
	SourceCommit       string `json:"source_commit"`
	CorrelationID      string `json:"correlation_id,omitempty"`
	KeyID              string `json:"key_id,omitempty"`
	PayloadSHA256      string `json:"payload_sha256"`
	BundleSourceSHA256 string `json:"bundle_source_sha256,omitempty"`
	ExpiresAt          string `json:"expires_at"`
	VerifiedAt         string `json:"verified_at"`
}

type runtimeActionView struct {
	RuntimeActionID      string `json:"runtime_action_id"`
	PlanID               string `json:"plan_id"`
	DecisionID           string `json:"decision_id"`
	PolicyID             string `json:"policy_id"`
	BundleID             string `json:"bundle_id"`
	SourceCommit         string `json:"source_commit"`
	CorrelationID        string `json:"correlation_id,omitempty"`
	AdapterID            string `json:"adapter_id"`
	CapabilityID         string `json:"capability_id"`
	Mode                 string `json:"mode"`
	Required             bool   `json:"required"`
	ActionType           string `json:"action_type"`
	TargetScope          string `json:"target_scope"`
	TargetKeySHA256      string `json:"target_key_sha256"`
	IdempotencyKeySHA256 string `json:"idempotency_key_sha256"`
	Status               string `json:"status"`
	ExpiresAt            string `json:"expires_at"`
	CreatedAt            string `json:"created_at"`
	LastReconciledAt     string `json:"last_reconciled_at"`
}

type adapterStatusView struct {
	AdapterID  string `json:"adapter_id"`
	Registered bool   `json:"registered"`
	Health     string `json:"health"`
	Leases     int    `json:"leases"`
	Active     int    `json:"active"`
	Expired    int    `json:"expired"`
	Unknown    int    `json:"unknown"`
}

type journalEntryView struct {
	ID              string `json:"id"`
	RuntimeActionID string `json:"runtime_action_id"`
	Event           string `json:"event"`
	Status          string `json:"status"`
	MessageSHA256   string `json:"message_sha256,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type auditRecordView struct {
	ID              string `json:"id"`
	RuntimeActionID string `json:"runtime_action_id"`
	Status          string `json:"status"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
	CreatedAt       string `json:"created_at"`
}

func buildStatusSnapshot(ctx context.Context, store actionstate.Store, statePath string, registry kliqruntime.AdapterRuntimeRegistry) (statusSnapshot, error) {
	bundle, bundleErr := store.LastBundle(ctx)
	if bundleErr != nil && !errors.Is(bundleErr, actionstate.ErrNotFound) {
		return statusSnapshot{}, bundleErr
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		return statusSnapshot{}, err
	}
	audits, err := store.PendingAudits(ctx)
	if err != nil {
		return statusSnapshot{}, err
	}
	snapshot := statusSnapshot{
		GeneratedAt:       formatStatusTime(time.Now().UTC()),
		StatePath:         statePath,
		RuntimeActions:    runtimeActionViews(leases),
		RuntimeCounts:     runtimeCounts(leases),
		PendingAuditCount: len(audits),
		Adapters:          adapterStatusViews(leases, registry),
	}
	if credential, err := store.KLIQCredential(ctx); err == nil {
		if state, err := store.KLIQManagementState(ctx, credential.KLIQID); err == nil {
			snapshot.Assignment = &assignmentView{
				KLIQID:          state.KLIQID,
				AssignmentID:    state.ActiveAssignmentID,
				Version:         state.ActiveAssignmentVersion,
				SourceCommit:    redactID(state.ActiveAssignmentSourceCommit),
				Digest:          state.ActiveAssignmentDigest,
				ExpiresAt:       formatStatusTime(state.ActiveAssignmentExpiresAt),
				ActivatedAt:     formatStatusTime(state.ActiveAssignmentActivatedAt),
				CredentialState: credentialStatus(credential),
			}
		}
	}
	if bundleErr == nil {
		view := bundleStatus(bundle)
		snapshot.Bundle = &view
	} else {
		snapshot.Findings = append(snapshot.Findings, "bundle unavailable")
	}
	return snapshot, nil
}

func credentialStatus(credential actionstate.KLIQCredential) string {
	if credential.ServiceTokenExpiresAt.IsZero() {
		return "unknown"
	}
	if time.Now().UTC().Before(credential.ServiceTokenExpiresAt.UTC()) {
		return "valid"
	}
	return "expired"
}

func bundleStatus(record actionstate.BundleRecord) bundleStatusView {
	return bundleStatusView{
		BundleID:           record.BundleID,
		PolicyID:           record.PolicyID,
		SourceCommit:       redactID(record.SourceCommit),
		CorrelationID:      redactID(record.CorrelationID),
		KeyID:              redactID(record.KeyID),
		PayloadSHA256:      record.PayloadSHA256,
		BundleSourceSHA256: redactedHash(record.BundleSource),
		ExpiresAt:          formatStatusTime(record.ExpiresAt),
		VerifiedAt:         formatStatusTime(record.VerifiedAt),
	}
}

func runtimeActionViews(leases []actionstate.RuntimeActionLease) []runtimeActionView {
	views := make([]runtimeActionView, 0, len(leases))
	for _, lease := range leases {
		views = append(views, runtimeActionView{
			RuntimeActionID:      lease.RuntimeActionID,
			PlanID:               lease.PlanID,
			DecisionID:           lease.DecisionID,
			PolicyID:             lease.PolicyID,
			BundleID:             lease.BundleID,
			SourceCommit:         redactID(lease.SourceCommit),
			CorrelationID:        redactID(lease.CorrelationID),
			AdapterID:            lease.AdapterID,
			CapabilityID:         lease.CapabilityID,
			Mode:                 lease.Mode,
			Required:             lease.Required,
			ActionType:           lease.ActionType,
			TargetScope:          lease.TargetScope,
			TargetKeySHA256:      redactedHash(lease.TargetKey),
			IdempotencyKeySHA256: redactedHash(lease.IdempotencyKey),
			Status:               string(lease.Status),
			ExpiresAt:            formatStatusTime(lease.ExpiresAt),
			CreatedAt:            formatStatusTime(lease.CreatedAt),
			LastReconciledAt:     formatStatusTime(lease.LastReconciledAt),
		})
	}
	return views
}

func runtimeCounts(leases []actionstate.RuntimeActionLease) map[string]int {
	counts := map[string]int{}
	for _, lease := range leases {
		counts[string(lease.Status)]++
	}
	return counts
}

func adapterStatusViews(leases []actionstate.RuntimeActionLease, registry kliqruntime.AdapterRuntimeRegistry) []adapterStatusView {
	byAdapter := map[string]*adapterStatusView{}
	for _, lease := range leases {
		view := byAdapter[lease.AdapterID]
		if view == nil {
			view = &adapterStatusView{AdapterID: lease.AdapterID, Health: "unknown"}
			byAdapter[lease.AdapterID] = view
		}
		view.Leases++
		switch lease.Status {
		case domain.RuntimeActionActive:
			view.Active++
		case domain.RuntimeActionExpired:
			view.Expired++
		default:
			view.Unknown++
		}
	}
	if registry != nil {
		for _, descriptor := range registry.List() {
			view := byAdapter[descriptor.AdapterID]
			if view == nil {
				view = &adapterStatusView{AdapterID: descriptor.AdapterID}
				byAdapter[descriptor.AdapterID] = view
			}
			view.Registered = true
			if descriptor.Healthy {
				view.Health = "healthy"
			} else {
				view.Health = "unhealthy"
			}
		}
	}
	keys := make([]string, 0, len(byAdapter))
	for key := range byAdapter {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	views := make([]adapterStatusView, 0, len(keys))
	for _, key := range keys {
		views = append(views, *byAdapter[key])
	}
	return views
}

func journalEntryViews(entries []actionstate.JournalEntry) []journalEntryView {
	views := make([]journalEntryView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, journalEntryView{
			ID:              entry.ID,
			RuntimeActionID: entry.RuntimeActionID,
			Event:           entry.Event,
			Status:          string(entry.Status),
			MessageSHA256:   redactedHash(entry.Message),
			CreatedAt:       formatStatusTime(entry.CreatedAt),
		})
	}
	return views
}

func auditRecordViews(records []actionstate.AuditRecord) []auditRecordView {
	views := make([]auditRecordView, 0, len(records))
	for _, record := range records {
		views = append(views, auditRecordView{
			ID:              record.ID,
			RuntimeActionID: record.RuntimeActionID,
			Status:          record.Status,
			PayloadSHA256:   redactedHash(record.Payload),
			CreatedAt:       formatStatusTime(record.CreatedAt),
		})
	}
	return views
}

func findRuntimeAction(leases []actionstate.RuntimeActionLease, runtimeActionID string) (runtimeActionView, bool) {
	for _, view := range runtimeActionViews(leases) {
		if view.RuntimeActionID == runtimeActionID {
			return view, true
		}
	}
	return runtimeActionView{}, false
}

func formatStatusTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
