// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
)

const AuditPendingUpload = "pending_upload"

type Manager struct {
	Store       actionstate.Store
	Verifier    signing.Verifier
	TrustBundle domain.TrustBundle
	Registry    AdapterRuntimeRegistry
	Now         func() time.Time
}

type managedActivationStore interface {
	SaveManagedBundleActivation(ctx context.Context, record actionstate.BundleRecord, state actionstate.KLIQManagementState, artifacts []actionstate.AssignmentArtifactRecord) error
}

type ExecuteRequest struct {
	DecisionID                  string `json:"decision_id"`
	AdapterID                   string `json:"adapter_id"`
	CapabilityID                string `json:"capability_id"`
	CapabilityGrantID           string `json:"capability_grant_id"`
	Mode                        string `json:"mode,omitempty"`
	ActionType                  string `json:"action_type"`
	TargetScope                 string `json:"target_scope,omitempty"`
	TargetKey                   string `json:"target_key"`
	TTL                         string `json:"ttl,omitempty"`
	Reason                      string `json:"reason"`
	AuditID                     string `json:"audit_id,omitempty"`
	CorrelationID               string `json:"correlation_id,omitempty"`
	DeriveAuditIDFromDecisionID bool   `json:"derive_audit_id_from_decision_id,omitempty"`
}

type RuntimeActionExecutionResult struct {
	Lease   actionstate.RuntimeActionLease
	Applied bool
	Message string
}

type ExecuteResult struct {
	Plan    RuntimeActionPlan
	Results []RuntimeActionExecutionResult
}

type AdapterReconcileResult struct {
	AdapterID string
	Expired   int
	Active    int
	Unknown   int
	Findings  []string
}

type ReconcileResult struct {
	Expired        int
	Active         int
	Unknown        int
	Findings       []string
	AdapterResults map[string]AdapterReconcileResult
}

func (m Manager) LoadBundle(ctx context.Context, source kliqbundle.Source) (actionstate.BundleRecord, error) {
	if m.Store == nil {
		return actionstate.BundleRecord{}, fmt.Errorf("kliq runtime manager requires state store")
	}
	if m.Verifier == nil {
		return actionstate.BundleRecord{}, fmt.Errorf("kliq runtime manager requires bundle verifier")
	}
	return m.loadBundle(ctx, source)
}

func (m Manager) LoadManagedBundle(ctx context.Context, source *kliqbundle.ManagedAssignmentSource) (actionstate.BundleRecord, error) {
	if m.Store == nil {
		return actionstate.BundleRecord{}, fmt.Errorf("kliq runtime manager requires state store")
	}
	if m.Verifier == nil {
		return actionstate.BundleRecord{}, fmt.Errorf("kliq runtime manager requires bundle verifier")
	}
	if source == nil {
		return actionstate.BundleRecord{}, fmt.Errorf("managed assignment source is required")
	}
	if source.Verifier == nil {
		source.Verifier = m.Verifier
	}
	if source.KLIQID != "" {
		state, err := m.Store.KLIQManagementState(ctx, source.KLIQID)
		if err != nil && !errors.Is(err, actionstate.ErrNotFound) {
			return actionstate.BundleRecord{}, err
		}
		if err == nil {
			source.SetActiveAssignment(state.ActiveAssignmentVersion, state.ActiveAssignmentDigest)
		}
	}
	record, err := m.buildBundleRecord(ctx, source)
	if err != nil {
		return actionstate.BundleRecord{}, err
	}
	activation, ok := source.AssignmentActivation()
	if !ok {
		return actionstate.BundleRecord{}, fmt.Errorf("managed assignment source did not expose activated assignment state")
	}
	stagedArtifacts := assignmentArtifactRecords(activation, source.AssignmentArtifacts(), m.now())
	state := actionstate.KLIQManagementState{
		KLIQID:                       activation.KLIQID,
		ActiveAssignmentID:           activation.AssignmentID,
		ActiveAssignmentVersion:      activation.AssignmentVersion,
		ActiveAssignmentSourceCommit: activation.SourceCommit,
		ActiveAssignmentDigest:       activation.AssignmentDigest,
		ActiveAssignmentExpiresAt:    activation.ExpiresAt,
		ActiveAssignmentActivatedAt:  m.now(),
	}
	if atomicStore, ok := m.Store.(managedActivationStore); ok {
		if err := atomicStore.SaveManagedBundleActivation(ctx, record, state, stagedArtifacts); err != nil {
			return actionstate.BundleRecord{}, err
		}
		return record, nil
	}
	if err := m.Store.SaveBundle(ctx, record); err != nil {
		return actionstate.BundleRecord{}, err
	}
	if err := m.Store.SaveKLIQManagementState(ctx, state); err != nil {
		return actionstate.BundleRecord{}, err
	}
	return record, nil
}

func assignmentArtifactRecords(activation kliqbundle.ManagedAssignmentActivation, artifacts []domain.KLIQAssignedArtifact, activatedAt time.Time) []actionstate.AssignmentArtifactRecord {
	records := make([]actionstate.AssignmentArtifactRecord, 0, len(artifacts))
	for _, artifact := range artifacts {
		records = append(records, actionstate.AssignmentArtifactRecord{
			KLIQID:            activation.KLIQID,
			AssignmentID:      activation.AssignmentID,
			AssignmentVersion: activation.AssignmentVersion,
			ArtifactType:      artifact.ArtifactType,
			ArtifactID:        artifact.ArtifactID,
			ArtifactRef:       artifact.ArtifactRef,
			SHA256:            artifact.SHA256,
			EnvelopeJSON:      append([]byte(nil), artifact.Envelope...),
			ActivationStatus:  assignmentArtifactActivationStatus(artifact.ArtifactType),
			ActivationMessage: assignmentArtifactActivationMessage(artifact.ArtifactType),
			ActivatedAt:       activatedAt,
		})
	}
	return records
}

func assignmentArtifactActivationStatus(artifactType string) string {
	switch artifactType {
	case "runtime_bundle":
		return "activated"
	case "adapter_assignment", "context_route_pack", "conformance_expectation", "trust_bundle", "management_profile", "fallback_profile":
		return "validated_staged"
	default:
		return "unknown"
	}
}

func assignmentArtifactActivationMessage(artifactType string) string {
	switch artifactType {
	case "runtime_bundle":
		return "runtime bundle verified and active"
	case "adapter_assignment":
		return "adapter assignment staged; daemon registry activation runs after bundle activation"
	case "context_route_pack":
		return "context route pack staged for future context projection activation"
	case "conformance_expectation":
		return "conformance expectation staged for future evidence activation"
	case "trust_bundle":
		return "trust bundle artifact staged; local trust bundle file remains current verifier source"
	case "management_profile":
		return "management profile staged for future runtime loop configuration"
	case "fallback_profile":
		return "fallback profile staged for future failure policy activation"
	default:
		return "artifact type not recognized by activation status mapper"
	}
}

func (m Manager) loadBundle(ctx context.Context, source kliqbundle.Source) (actionstate.BundleRecord, error) {
	record, err := m.buildBundleRecord(ctx, source)
	if err != nil {
		return actionstate.BundleRecord{}, err
	}
	if err := m.Store.SaveBundle(ctx, record); err != nil {
		return actionstate.BundleRecord{}, err
	}
	return record, nil
}

func (m Manager) buildBundleRecord(ctx context.Context, source kliqbundle.Source) (actionstate.BundleRecord, error) {
	data, sourceRef, err := source.Load(ctx)
	if err != nil {
		return actionstate.BundleRecord{}, err
	}
	verified, err := kliqbundle.VerifySignedRuntimeBundle(ctx, data, m.Verifier)
	if err != nil {
		return actionstate.BundleRecord{}, err
	}
	now := m.now()
	record := actionstate.BundleRecord{
		BundleID:      verified.Bundle.Metadata.ID,
		PolicyID:      verified.Bundle.Metadata.PolicyID,
		SourceCommit:  verified.Bundle.Metadata.SourceCommit,
		CorrelationID: verified.Bundle.Metadata.CorrelationID,
		KeyID:         verified.Envelope.KeyID,
		PayloadSHA256: verified.Envelope.PayloadSHA256,
		BundleSource:  sourceRef,
		EnvelopeJSON:  append([]byte(nil), data...),
		ExpiresAt:     verified.Envelope.ExpiresAt.UTC(),
		VerifiedAt:    now,
	}
	return record, nil
}

func (m Manager) CachedBundle(ctx context.Context) (kliqbundle.RuntimeBundleVerification, actionstate.BundleRecord, error) {
	if m.Store == nil {
		return kliqbundle.RuntimeBundleVerification{}, actionstate.BundleRecord{}, fmt.Errorf("kliq runtime manager requires state store")
	}
	if m.Verifier == nil {
		return kliqbundle.RuntimeBundleVerification{}, actionstate.BundleRecord{}, fmt.Errorf("kliq runtime manager requires bundle verifier")
	}
	record, err := m.Store.LastBundle(ctx)
	if err != nil {
		return kliqbundle.RuntimeBundleVerification{}, actionstate.BundleRecord{}, err
	}
	verified, err := kliqbundle.VerifySignedRuntimeBundle(ctx, record.EnvelopeJSON, m.Verifier)
	if err != nil {
		return kliqbundle.RuntimeBundleVerification{}, actionstate.BundleRecord{}, err
	}
	return verified, record, nil
}

func (m Manager) ExecuteAction(ctx context.Context, req ExecuteRequest) (ExecuteResult, error) {
	plan, signedBundle, err := m.planFromRequest(ctx, req)
	if err != nil {
		return ExecuteResult{}, err
	}
	return m.ExecutePlan(ctx, plan, signedBundle)
}

func (m Manager) ExecutePlan(ctx context.Context, plan RuntimeActionPlan, signedBundle []byte) (ExecuteResult, error) {
	if m.Store == nil {
		return ExecuteResult{}, fmt.Errorf("kliq runtime manager requires state store")
	}
	if len(plan.Actions) == 0 {
		return ExecuteResult{}, fmt.Errorf("runtime action plan requires at least one planned action")
	}
	if len(plan.Actions) > 1 {
		return ExecuteResult{}, fmt.Errorf("multi-action runtime plans are modeled but not executable in this slice")
	}
	action := plan.Actions[0]
	if err := validateActionMode(action.Mode); err != nil {
		return ExecuteResult{}, err
	}
	if action.Mode != ActionModeRequired || !action.Required {
		return ExecuteResult{}, fmt.Errorf("slice 5.5 execution supports exactly one required action")
	}
	executor, ok := m.executorFor(action.AdapterID)
	if !ok {
		return ExecuteResult{}, fmt.Errorf("runtime adapter %q is not registered", action.AdapterID)
	}
	result, err := m.executePlannedAction(ctx, plan, action, executor, signedBundle)
	if err != nil {
		return ExecuteResult{}, err
	}
	return ExecuteResult{Plan: plan, Results: []RuntimeActionExecutionResult{result}}, nil
}

func (m Manager) planFromRequest(ctx context.Context, req ExecuteRequest) (RuntimeActionPlan, []byte, error) {
	decisionID := strings.TrimSpace(req.DecisionID)
	if decisionID == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("decision id is required")
	}
	adapterID := strings.TrimSpace(req.AdapterID)
	if adapterID == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("adapter id is required")
	}
	capabilityID := strings.TrimSpace(req.CapabilityID)
	if capabilityID == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("capability id is required")
	}
	capabilityGrantID := strings.TrimSpace(req.CapabilityGrantID)
	if capabilityGrantID == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("capability grant id is required")
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime action mode is required")
	}
	if err := validateActionMode(mode); err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime action reason is required")
	}
	auditID := strings.TrimSpace(req.AuditID)
	if auditID == "" {
		if !req.DeriveAuditIDFromDecisionID {
			return RuntimeActionPlan{}, nil, fmt.Errorf("audit id is required unless explicit derivation from decision_id is requested")
		}
		auditID = "audit." + shortHash(decisionID)
	}
	verified, bundleRecord, err := m.CachedBundle(ctx)
	if err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	if err := m.ensureActiveAssignmentAllowsNewActions(ctx); err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	runtimeBundle := verified.Bundle
	if !runtimeBundle.Spec.RuntimeAllowed {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime bundle %q does not allow runtime actions", runtimeBundle.Metadata.ID)
	}
	actionType := strings.TrimSpace(req.ActionType)
	if actionType == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime action type is required")
	}
	if !actionAllowed(runtimeBundle, actionType) {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime action %q is not allowed by bundle %q", actionType, runtimeBundle.Metadata.ID)
	}
	ttlText := strings.TrimSpace(req.TTL)
	if ttlText == "" {
		ttlText = runtimeBundle.Spec.MaxTTL
	}
	ttl, err := parsePositiveDuration(ttlText, "ttl")
	if err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	maxTTL, err := parsePositiveDuration(runtimeBundle.Spec.MaxTTL, "bundle max_ttl")
	if err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	if ttl > maxTTL {
		return RuntimeActionPlan{}, nil, fmt.Errorf("ttl %s exceeds bundle max_ttl %s", ttl, maxTTL)
	}
	targetScope := strings.TrimSpace(req.TargetScope)
	if targetScope == "" {
		targetScope = runtimeBundle.Spec.MaxScope
	}
	if targetScope == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("target scope is required")
	}
	if runtimeBundle.Spec.MaxScope != "" && targetScope != runtimeBundle.Spec.MaxScope {
		return RuntimeActionPlan{}, nil, fmt.Errorf("target scope %q does not match bundle max_scope %q", targetScope, runtimeBundle.Spec.MaxScope)
	}
	targetKey := strings.TrimSpace(req.TargetKey)
	if targetKey == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("target key is required")
	}
	correlationID := strings.TrimSpace(req.CorrelationID)
	if correlationID == "" {
		correlationID = strings.TrimSpace(runtimeBundle.Metadata.CorrelationID)
	}
	if correlationID == "" {
		correlationID = "correlation.local." + shortHash(runtimeBundle.Metadata.ID+"\x00"+decisionID)
	}
	planID := "runtime_action_plan." + shortHash(runtimeBundle.Metadata.ID+"\x00"+decisionID)
	actionID := "planned_runtime_action." + shortHash(planID+"\x00"+adapterID+"\x00"+capabilityID+"\x00"+actionType+"\x00"+targetScope+"\x00"+targetKey)
	plan := RuntimeActionPlan{
		PlanID:        planID,
		DecisionID:    decisionID,
		BundleID:      runtimeBundle.Metadata.ID,
		PolicyID:      runtimeBundle.Metadata.PolicyID,
		SourceCommit:  runtimeBundle.Metadata.SourceCommit,
		CorrelationID: correlationID,
		Actions: []PlannedRuntimeAction{{
			ActionID:          actionID,
			AdapterID:         adapterID,
			CapabilityID:      capabilityID,
			CapabilityGrantID: capabilityGrantID,
			CorrelationID:     correlationID,
			Mode:              mode,
			Required:          mode == ActionModeRequired,
			ActionType:        actionType,
			TargetScope:       targetScope,
			TargetKey:         targetKey,
			TTL:               ttlText,
			Reason:            reason,
			AuditID:           auditID,
			Context: map[string]any{
				"target_scope":   targetScope,
				"target_key":     targetKey,
				"reason":         reason,
				"ttl":            ttlText,
				"correlation_id": correlationID,
			},
		}},
	}
	return plan, bundleRecord.EnvelopeJSON, nil
}

func (m Manager) ensureActiveAssignmentAllowsNewActions(ctx context.Context) error {
	credential, err := m.Store.KLIQCredential(ctx)
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	state, err := m.Store.KLIQManagementState(ctx, credential.KLIQID)
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !m.now().UTC().Before(state.ActiveAssignmentExpiresAt.UTC()) {
		return fmt.Errorf("active assignment %q is expired; denying new runtime actions", state.ActiveAssignmentID)
	}
	return nil
}

func (m Manager) executePlannedAction(ctx context.Context, plan RuntimeActionPlan, action PlannedRuntimeAction, executor RuntimeExecutor, signedBundle []byte) (RuntimeActionExecutionResult, error) {
	now := m.now()
	existing, err := m.Store.LeaseByDedupKey(ctx, action.AdapterID, action.CapabilityID, action.ActionType, action.TargetScope, action.TargetKey)
	switch {
	case err == nil && now.Before(existing.ExpiresAt):
		_ = m.Store.AppendJournal(ctx, journal(existing.RuntimeActionID, "deduplicated", existing.Status, "active lease already exists for adapter/capability; ttl was not extended", now))
		return RuntimeActionExecutionResult{Lease: existing, Applied: false, Message: "active lease already exists; ttl not extended"}, nil
	case err == nil:
		if err := m.expireLease(ctx, executor, existing, now, "expired before new runtime action"); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
	case errors.Is(err, actionstate.ErrNotFound):
	default:
		return RuntimeActionExecutionResult{}, err
	}
	lease := leaseFromPlannedAction(plan, action, now)
	if err := executor.Execute(ctx, lease, signedBundle); err != nil {
		return m.recoverAfterExecuteError(ctx, executor, lease, now, err)
	}
	if err := m.Store.UpsertLease(ctx, lease); err != nil {
		return RuntimeActionExecutionResult{}, err
	}
	if err := m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "activated", lease.Status, "runtime action activated", now)); err != nil {
		return RuntimeActionExecutionResult{}, err
	}
	if err := m.Store.AppendAudit(ctx, audit(lease, "runtime action activated", now)); err != nil {
		return RuntimeActionExecutionResult{}, err
	}
	return RuntimeActionExecutionResult{Lease: lease, Applied: true, Message: "runtime action activated"}, nil
}

func leaseFromPlannedAction(plan RuntimeActionPlan, action PlannedRuntimeAction, now time.Time) actionstate.RuntimeActionLease {
	ttl, _ := time.ParseDuration(action.TTL)
	idempotencyKey := idempotencyKey(plan.BundleID, plan.DecisionID, action.AdapterID, action.CapabilityID, action.ActionType, action.TargetScope, action.TargetKey)
	return actionstate.RuntimeActionLease{
		RuntimeActionID:   "runtime_action." + shortHash(idempotencyKey),
		PlanID:            plan.PlanID,
		DecisionID:        plan.DecisionID,
		PolicyID:          plan.PolicyID,
		BundleID:          plan.BundleID,
		SourceCommit:      plan.SourceCommit,
		CorrelationID:     plan.CorrelationID,
		ActionType:        action.ActionType,
		TargetScope:       action.TargetScope,
		TargetKey:         action.TargetKey,
		TTL:               action.TTL,
		ExpiresAt:         now.Add(ttl).UTC(),
		Reason:            action.Reason,
		AuditID:           action.AuditID,
		CapabilityGrantID: action.CapabilityGrantID,
		AdapterID:         action.AdapterID,
		CapabilityID:      action.CapabilityID,
		Mode:              action.Mode,
		Required:          action.Required,
		IdempotencyKey:    idempotencyKey,
		CreatedAt:         now,
		LastReconciledAt:  now,
		Status:            domain.RuntimeActionActive,
	}
}

func (m Manager) recoverAfterExecuteError(ctx context.Context, executor RuntimeExecutor, lease actionstate.RuntimeActionLease, now time.Time, executeErr error) (RuntimeActionExecutionResult, error) {
	stateReader, ok := executor.(RuntimeStateReader)
	if !ok {
		return RuntimeActionExecutionResult{}, m.recordFailedExecute(ctx, lease, now, "execute_failed", executeErr.Error(), executeErr)
	}
	status, err := stateReader.State(ctx, lease)
	if err != nil {
		message := "execute failed and adapter readback failed: " + err.Error()
		return RuntimeActionExecutionResult{}, m.recordFailedExecute(ctx, lease, now, "execute_readback_failed", message, executeErr)
	}
	switch status {
	case domain.RuntimeActionActive:
		lease.Status = domain.RuntimeActionActive
		if err := m.Store.UpsertLease(ctx, lease); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
		message := "adapter execute response was lost; active state recovered by readback"
		if err := m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "execute_recovered_by_readback", lease.Status, message, now)); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
		if err := m.Store.AppendAudit(ctx, audit(lease, message, now)); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
		return RuntimeActionExecutionResult{Lease: lease, Applied: true, Message: message}, nil
	case domain.RuntimeActionExpired:
		lease.Status = domain.RuntimeActionExpired
		lease.LastReconciledAt = now
		if err := m.Store.UpsertLease(ctx, lease); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
		message := "adapter execute response was lost; expired state recovered by readback"
		if err := m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "execute_recovered_expired_by_readback", lease.Status, message, now)); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
		if err := m.Store.AppendAudit(ctx, audit(lease, message, now)); err != nil {
			return RuntimeActionExecutionResult{}, err
		}
		return RuntimeActionExecutionResult{Lease: lease, Applied: false, Message: message}, nil
	case domain.RuntimeActionUnknown, domain.RuntimeActionNotFound, "":
		message := "execute failed and adapter readback returned unknown state"
		return RuntimeActionExecutionResult{}, m.recordFailedExecute(ctx, lease, now, "execute_readback_unknown", message, executeErr)
	default:
		message := "execute failed and adapter readback returned unsupported state " + string(status)
		return RuntimeActionExecutionResult{}, m.recordFailedExecute(ctx, lease, now, "execute_readback_unsupported", message, executeErr)
	}
}

func (m Manager) recordFailedExecute(ctx context.Context, lease actionstate.RuntimeActionLease, now time.Time, event, message string, err error) error {
	lease.Status = domain.RuntimeActionFailed
	lease.LastReconciledAt = now
	_ = m.Store.UpsertLease(ctx, lease)
	_ = m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, event, lease.Status, message, now))
	_ = m.Store.AppendAudit(ctx, audit(lease, message, now))
	return err
}

func (m Manager) Reconcile(ctx context.Context) (ReconcileResult, error) {
	if m.Store == nil {
		return ReconcileResult{}, fmt.Errorf("kliq runtime manager requires state store")
	}
	result := ReconcileResult{AdapterResults: map[string]AdapterReconcileResult{}}
	bundleAuthorityDegraded := false
	if _, _, err := m.CachedBundle(ctx); err != nil {
		bundleAuthorityDegraded = true
		result.Findings = append(result.Findings, "cached runtime bundle unavailable or invalid: "+err.Error())
	}
	now := m.now()
	leases, err := m.Store.ActiveLeases(ctx)
	if err != nil {
		return ReconcileResult{}, err
	}
	grouped := groupLeasesByAdapter(leases)
	adapterIDs := make([]string, 0, len(grouped))
	for adapterID := range grouped {
		adapterIDs = append(adapterIDs, adapterID)
	}
	sort.Strings(adapterIDs)
	for _, adapterID := range adapterIDs {
		adapterResult := AdapterReconcileResult{AdapterID: adapterID}
		executor, ok := m.executorFor(adapterID)
		if !ok {
			for _, lease := range grouped[adapterID] {
				message := fmt.Sprintf("runtime adapter %q is not registered for lease %s", adapterID, lease.RuntimeActionID)
				_ = m.markLeaseUnknown(ctx, lease, now, message)
				adapterResult.Unknown++
				adapterResult.Findings = append(adapterResult.Findings, message)
				result.Unknown++
				result.Findings = append(result.Findings, message)
			}
			result.AdapterResults[adapterID] = adapterResult
			continue
		}
		for _, lease := range grouped[adapterID] {
			if now.Before(lease.ExpiresAt) {
				m.reconcileActiveLease(ctx, executor, lease, now, &result, &adapterResult)
				continue
			}
			if err := m.expireLease(ctx, executor, lease, now, "ttl expired during restart reconciliation"); err != nil {
				message := "failed to cleanup expired runtime action " + lease.RuntimeActionID + ": " + err.Error()
				adapterResult.Findings = append(adapterResult.Findings, message)
				result.Findings = append(result.Findings, message)
				continue
			}
			adapterResult.Expired++
			result.Expired++
		}
		result.AdapterResults[adapterID] = adapterResult
	}
	if result.Expired > 0 {
		result.Findings = append(result.Findings, "expired runtime action leases were cleaned up")
		if bundleAuthorityDegraded {
			result.Findings = append(result.Findings, "cleanup executed with degraded bundle authority")
		}
	}
	return result, nil
}

func (m Manager) ReconcileDryRun(ctx context.Context) (ReconcileResult, error) {
	if m.Store == nil {
		return ReconcileResult{}, fmt.Errorf("kliq runtime manager requires state store")
	}
	result := ReconcileResult{AdapterResults: map[string]AdapterReconcileResult{}}
	if _, err := m.Store.LastBundle(ctx); err != nil {
		result.Findings = append(result.Findings, "cached runtime bundle unavailable: "+err.Error())
	}
	now := m.now()
	leases, err := m.Store.ActiveLeases(ctx)
	if err != nil {
		return ReconcileResult{}, err
	}
	grouped := groupLeasesByAdapter(leases)
	adapterIDs := make([]string, 0, len(grouped))
	for adapterID := range grouped {
		adapterIDs = append(adapterIDs, adapterID)
	}
	sort.Strings(adapterIDs)
	for _, adapterID := range adapterIDs {
		adapterResult := AdapterReconcileResult{AdapterID: adapterID}
		for _, lease := range grouped[adapterID] {
			if !lease.Selector().Valid() {
				message := "runtime action lease " + lease.RuntimeActionID + " has incomplete selector"
				adapterResult.Unknown++
				adapterResult.Findings = append(adapterResult.Findings, message)
				result.Unknown++
				result.Findings = append(result.Findings, message)
				continue
			}
			if now.Before(lease.ExpiresAt) {
				adapterResult.Active++
				result.Active++
				continue
			}
			adapterResult.Expired++
			result.Expired++
		}
		result.AdapterResults[adapterID] = adapterResult
	}
	if result.Expired > 0 {
		result.Findings = append(result.Findings, "expired runtime action leases would be cleaned up")
	}
	return result, nil
}

func (m Manager) reconcileActiveLease(ctx context.Context, executor RuntimeExecutor, lease actionstate.RuntimeActionLease, now time.Time, result *ReconcileResult, adapterResult *AdapterReconcileResult) {
	stateReader, ok := executor.(RuntimeStateReader)
	if !ok {
		lease.LastReconciledAt = now
		_ = m.Store.UpsertLease(ctx, lease)
		result.Active++
		adapterResult.Active++
		return
	}
	status, err := stateReader.State(ctx, lease)
	if err != nil {
		message := "failed to read runtime action state " + lease.RuntimeActionID + ": " + err.Error()
		_ = m.markLeaseUnknown(ctx, lease, now, message)
		result.Unknown++
		adapterResult.Unknown++
		result.Findings = append(result.Findings, message)
		adapterResult.Findings = append(adapterResult.Findings, message)
		return
	}
	switch status {
	case domain.RuntimeActionActive:
		lease.Status = domain.RuntimeActionActive
		lease.LastReconciledAt = now
		_ = m.Store.UpsertLease(ctx, lease)
		result.Active++
		adapterResult.Active++
	case domain.RuntimeActionExpired:
		_ = m.Store.ExpireLease(ctx, lease.RuntimeActionID, now)
		expired := lease
		expired.Status = domain.RuntimeActionExpired
		expired.LastReconciledAt = now
		_ = m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "adapter_readback_expired", domain.RuntimeActionExpired, "adapter readback reported expired action", now))
		_ = m.Store.AppendAudit(ctx, audit(expired, "adapter readback reported expired action", now))
		result.Expired++
		adapterResult.Expired++
	default:
		message := "adapter readback returned unknown runtime action state for " + lease.RuntimeActionID
		_ = m.markLeaseUnknown(ctx, lease, now, message)
		result.Unknown++
		adapterResult.Unknown++
		result.Findings = append(result.Findings, message)
		adapterResult.Findings = append(adapterResult.Findings, message)
	}
}

func (m Manager) markLeaseUnknown(ctx context.Context, lease actionstate.RuntimeActionLease, now time.Time, message string) error {
	lease.Status = domain.RuntimeActionUnknown
	lease.LastReconciledAt = now
	if err := m.Store.UpsertLease(ctx, lease); err != nil {
		return err
	}
	if err := m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "unknown", lease.Status, message, now)); err != nil {
		return err
	}
	return m.Store.AppendAudit(ctx, audit(lease, message, now))
}

func (m Manager) expireLease(ctx context.Context, executor RuntimeExecutor, lease actionstate.RuntimeActionLease, now time.Time, message string) error {
	if err := executor.Cleanup(ctx, lease); err != nil {
		return err
	}
	if err := m.Store.ExpireLease(ctx, lease.RuntimeActionID, now); err != nil {
		return err
	}
	expired := lease
	expired.Status = domain.RuntimeActionExpired
	expired.LastReconciledAt = now
	if err := m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "expired", domain.RuntimeActionExpired, message, now)); err != nil {
		return err
	}
	return m.Store.AppendAudit(ctx, audit(expired, message, now))
}

func (m Manager) executorFor(adapterID string) (RuntimeExecutor, bool) {
	if m.Registry == nil {
		return nil, false
	}
	return m.Registry.Get(adapterID)
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func groupLeasesByAdapter(leases []actionstate.RuntimeActionLease) map[string][]actionstate.RuntimeActionLease {
	grouped := map[string][]actionstate.RuntimeActionLease{}
	for _, lease := range leases {
		grouped[lease.AdapterID] = append(grouped[lease.AdapterID], lease)
	}
	return grouped
}

func actionAllowed(runtimeBundle corebundle.RuntimeBundle, actionType string) bool {
	for _, action := range runtimeBundle.Spec.RuntimeActions {
		if action.CanonicalID == actionType || action.Label == actionType {
			return true
		}
	}
	return false
}

func parsePositiveDuration(value, field string) (time.Duration, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", field)
	}
	return parsed, nil
}

func idempotencyKey(bundleID, decisionID, adapterID, capabilityID, actionType, targetScope, targetKey string) string {
	return "sha256:" + hex.EncodeToString(hashBytes(bundleID+"\x00"+decisionID+"\x00"+adapterID+"\x00"+capabilityID+"\x00"+actionType+"\x00"+targetScope+"\x00"+targetKey))
}

func shortHash(value string) string {
	return hex.EncodeToString(hashBytes(value))[:16]
}

func hashBytes(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func journal(runtimeActionID, event string, status domain.RuntimeActionStatus, message string, now time.Time) actionstate.JournalEntry {
	return actionstate.JournalEntry{
		ID:              "journal." + shortHash(runtimeActionID+event+now.Format(time.RFC3339Nano)),
		RuntimeActionID: runtimeActionID,
		Event:           event,
		Status:          status,
		Message:         message,
		CreatedAt:       now,
	}
}

func audit(lease actionstate.RuntimeActionLease, message string, now time.Time) actionstate.AuditRecord {
	data, _ := json.Marshal(map[string]string{
		"runtime_action_id": lease.RuntimeActionID,
		"plan_id":           lease.PlanID,
		"decision_id":       lease.DecisionID,
		"policy_id":         lease.PolicyID,
		"bundle_id":         lease.BundleID,
		"source_commit":     lease.SourceCommit,
		"correlation_id":    lease.CorrelationID,
		"adapter_id":        lease.AdapterID,
		"capability_id":     lease.CapabilityID,
		"mode":              lease.Mode,
		"action_type":       lease.ActionType,
		"target_scope":      lease.TargetScope,
		"audit_id":          lease.AuditID,
		"status":            string(lease.Status),
		"message":           message,
		"expires_at":        lease.ExpiresAt.Format(time.RFC3339Nano),
	})
	return actionstate.AuditRecord{
		ID:              "audit_spool." + shortHash(lease.RuntimeActionID+string(lease.Status)+now.Format(time.RFC3339Nano)),
		RuntimeActionID: lease.RuntimeActionID,
		Status:          AuditPendingUpload,
		Payload:         string(data),
		CreatedAt:       now,
	}
}
