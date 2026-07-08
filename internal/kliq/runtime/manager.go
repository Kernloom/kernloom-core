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
	"github.com/kernloom/kernloom-core/internal/core/conformance"
	corecontext "github.com/kernloom/kernloom-core/internal/core/context"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
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
	EventType                   string `json:"event_type,omitempty"`
	EventID                     string `json:"event_id,omitempty"`
	RiskType                    string `json:"risk_type,omitempty"`
	AdapterID                   string `json:"adapter_id"`
	CapabilityID                string `json:"capability_id"`
	CapabilityGrantID           string `json:"capability_grant_id"`
	BindingID                   string `json:"binding_id,omitempty"`
	BindingDigest               string `json:"binding_digest,omitempty"`
	AdapterManifestDigest       string `json:"adapter_manifest_digest,omitempty"`
	ActionDigest                string `json:"action_digest,omitempty"`
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
	artifacts := source.AssignmentArtifacts()
	if err := validateManagedAssignmentArtifacts(artifacts, m.now()); err != nil {
		return actionstate.BundleRecord{}, err
	}
	stagedArtifacts := assignmentArtifactRecords(activation, artifacts, m.now())
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
	case "runtime_bundle", "adapter_manifest", "adapter_assignment", "context_route_pack", "conformance_expectation", "trust_bundle", "management_profile", "fallback_profile":
		return "activated"
	default:
		return "unknown"
	}
}

func assignmentArtifactActivationMessage(artifactType string) string {
	switch artifactType {
	case "runtime_bundle":
		return "runtime bundle verified and active"
	case "adapter_manifest":
		return "adapter manifest verified and active for approved runtime adapter provenance"
	case "adapter_assignment":
		return "adapter assignment validated and available for daemon registry activation"
	case "context_route_pack":
		return "context route pack validated and active for local context routing"
	case "conformance_expectation":
		return "conformance expectation validated and active for local evidence expectations"
	case "trust_bundle":
		return "trust bundle validated and active in assignment artifact state"
	case "management_profile":
		return "management profile validated and available for daemon interval control"
	case "fallback_profile":
		return "fallback profile validated and active for local fallback behavior"
	default:
		return "artifact type not recognized by activation status mapper"
	}
}

func validateManagedAssignmentArtifacts(artifacts []domain.KLIQAssignedArtifact, now time.Time) error {
	seenRuntimeBundle := false
	for _, artifact := range artifacts {
		payload, err := assignmentArtifactPayload(artifact)
		if err != nil {
			return fmt.Errorf("assignment artifact %q payload unavailable: %w", artifact.ArtifactID, err)
		}
		switch artifact.ArtifactType {
		case "runtime_bundle":
			seenRuntimeBundle = true
			if err := validateRuntimeBundleArtifact(payload); err != nil {
				return fmt.Errorf("runtime bundle artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		case "adapter_assignment":
			if err := validateAdapterAssignmentArtifact(payload); err != nil {
				return fmt.Errorf("adapter assignment artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		case "context_route_pack":
			if err := validateContextRoutePackArtifact(payload); err != nil {
				return fmt.Errorf("context route pack artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		case "conformance_expectation":
			if err := validateConformanceExpectationArtifact(payload); err != nil {
				return fmt.Errorf("conformance expectation artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		case "trust_bundle":
			if err := validateTrustBundleArtifact(payload, now); err != nil {
				return fmt.Errorf("trust bundle artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		case "management_profile":
			if err := validateManagementProfileArtifact(payload); err != nil {
				return fmt.Errorf("management profile artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		case "fallback_profile":
			if err := validateFallbackProfileArtifact(payload); err != nil {
				return fmt.Errorf("fallback profile artifact %q invalid: %w", artifact.ArtifactID, err)
			}
		default:
			return fmt.Errorf("unsupported assignment artifact type %q", artifact.ArtifactType)
		}
	}
	if !seenRuntimeBundle {
		return fmt.Errorf("managed assignment requires runtime_bundle artifact")
	}
	return nil
}

func assignmentArtifactPayload(artifact domain.KLIQAssignedArtifact) ([]byte, error) {
	var envelope signing.SignedEnvelope
	if err := json.Unmarshal(artifact.Envelope, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Payload) == 0 {
		return nil, fmt.Errorf("signed envelope payload is empty")
	}
	return envelope.Payload, nil
}

func validateRuntimeBundleArtifact(payload []byte) error {
	var bundle corebundle.RuntimeBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return err
	}
	switch {
	case bundle.Kind != "RuntimeBundle":
		return fmt.Errorf("kind must be RuntimeBundle")
	case strings.TrimSpace(bundle.Metadata.ID) == "":
		return fmt.Errorf("metadata.id is required")
	case strings.TrimSpace(bundle.Metadata.PolicyID) == "":
		return fmt.Errorf("metadata.policy_id is required")
	case strings.TrimSpace(bundle.Spec.PolicyID) == "":
		return fmt.Errorf("spec.policy_id is required")
	}
	return nil
}

func validateAdapterAssignmentArtifact(payload []byte) error {
	var assignment domain.AdapterAssignment
	if err := json.Unmarshal(payload, &assignment); err != nil {
		return err
	}
	switch {
	case assignment.Kind != "AdapterAssignment":
		return fmt.Errorf("kind must be AdapterAssignment")
	case strings.TrimSpace(assignment.AdapterID) == "":
		return fmt.Errorf("adapter_id is required")
	case strings.TrimSpace(assignment.Endpoint) == "":
		return fmt.Errorf("endpoint is required")
	}
	return nil
}

func validateContextRoutePackArtifact(payload []byte) error {
	var pack corecontext.ContextRoutePack
	if err := json.Unmarshal(payload, &pack); err != nil {
		return err
	}
	switch {
	case pack.Kind != "ContextRoutePack":
		return fmt.Errorf("kind must be ContextRoutePack")
	case strings.TrimSpace(pack.Spec.PolicyID) == "":
		return fmt.Errorf("spec.policy_id is required")
	case strings.TrimSpace(pack.Spec.Target) == "":
		return fmt.Errorf("spec.target is required")
	case strings.TrimSpace(pack.Spec.Stage) == "":
		return fmt.Errorf("spec.stage is required")
	case len(pack.Spec.Routes) == 0:
		return fmt.Errorf("spec.routes is required")
	}
	for _, route := range pack.Spec.Routes {
		if strings.TrimSpace(route.Name) == "" {
			return fmt.Errorf("route.name is required")
		}
	}
	return nil
}

func validateConformanceExpectationArtifact(payload []byte) error {
	var expectation conformance.ConformanceExpectation
	if err := json.Unmarshal(payload, &expectation); err != nil {
		return err
	}
	switch {
	case expectation.Kind != "ConformanceExpectation":
		return fmt.Errorf("kind must be ConformanceExpectation")
	case strings.TrimSpace(expectation.Spec.PolicyID) == "":
		return fmt.Errorf("spec.policy_id is required")
	case strings.TrimSpace(expectation.Spec.Target) == "":
		return fmt.Errorf("spec.target is required")
	case strings.TrimSpace(expectation.Spec.Stage) == "":
		return fmt.Errorf("spec.stage is required")
	case len(expectation.Spec.Expectations) == 0 && len(expectation.Spec.Prohibit) == 0:
		return fmt.Errorf("spec.expectations or spec.prohibit is required")
	}
	return nil
}

func validateTrustBundleArtifact(payload []byte, now time.Time) error {
	var bundle domain.TrustBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(bundle.KeyID) == "":
		return fmt.Errorf("key_id is required")
	case strings.TrimSpace(bundle.PublicKey) == "":
		return fmt.Errorf("public_key is required")
	case !validTrustBundlePurpose(bundle.Purpose):
		return fmt.Errorf("unsupported trust bundle purpose %q", bundle.Purpose)
	case bundle.Status != "active" && bundle.Status != "previous":
		return fmt.Errorf("trust bundle status %q cannot verify managed assignments", bundle.Status)
	case !bundle.ExpiresAt.IsZero() && !now.UTC().Before(bundle.ExpiresAt.UTC()):
		return fmt.Errorf("trust bundle is expired")
	}
	return nil
}

func validTrustBundlePurpose(purpose string) bool {
	switch strings.TrimSpace(purpose) {
	case "assignment_verification", "artifact_verification":
		return true
	default:
		return false
	}
}

func validateManagementProfileArtifact(payload []byte) error {
	var profile domain.KLIQManagementProfile
	if err := json.Unmarshal(payload, &profile); err != nil {
		return err
	}
	if profile.Kind != "" && profile.Kind != "KLIQManagementProfile" && profile.Kind != "ManagementProfile" {
		return fmt.Errorf("unsupported management profile kind %q", profile.Kind)
	}
	if strings.TrimSpace(profile.ProfileID) == "" {
		return fmt.Errorf("profile_id is required")
	}
	if strings.TrimSpace(profile.Mode) == "" {
		return fmt.Errorf("mode is required")
	}
	for name, value := range map[string]string{
		"poll_interval":        profile.PollInterval,
		"heartbeat_interval":   profile.HeartbeatInterval,
		"status_interval":      profile.StatusInterval,
		"decision_interval":    profile.DecisionInterval,
		"reconcile_interval":   profile.ReconcileInterval,
		"audit_flush_interval": profile.AuditFlushInterval,
	} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, err := parsePositiveDuration(value, name); err != nil {
			return err
		}
	}
	return nil
}

func validateFallbackProfileArtifact(payload []byte) error {
	var profile domain.KLIQFallbackProfile
	if err := json.Unmarshal(payload, &profile); err != nil {
		return err
	}
	if profile.Kind != "" && profile.Kind != "KLIQFallbackProfile" && profile.Kind != "FallbackProfile" {
		return fmt.Errorf("unsupported fallback profile kind %q", profile.Kind)
	}
	if strings.TrimSpace(profile.ProfileID) == "" {
		return fmt.Errorf("profile_id is required")
	}
	if strings.TrimSpace(profile.Mode) == "" {
		return fmt.Errorf("mode is required")
	}
	if !profile.AuditRequired {
		return fmt.Errorf("audit_required must be true")
	}
	return nil
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
	if len(plan.Actions) == 0 {
		if err := m.Store.AppendRuntimeDecision(ctx, noActionRuntimeDecisionRecord(plan, m.now())); err != nil {
			return ExecuteResult{}, err
		}
		return ExecuteResult{Plan: plan}, nil
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
	if err := m.Store.AppendRuntimeDecision(ctx, runtimeDecisionRecord(plan, result, m.now())); err != nil {
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
	if err := m.ensureActiveContextRouteAllowsAction(ctx, adapterID, capabilityID); err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	runtimeBundle := verified.Bundle
	if !runtimeBundle.Spec.RuntimeAllowed {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime bundle %q does not allow runtime actions", runtimeBundle.Metadata.ID)
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
	actionType := strings.TrimSpace(req.ActionType)
	riskContext := corerisk.RiskContext{}
	if actionType == "" {
		derivedAction, derivedRisk, actionable, err := m.actionFromRiskCache(ctx, runtimeBundle, strings.TrimSpace(req.RiskType))
		if err != nil {
			return RuntimeActionPlan{}, nil, err
		}
		riskContext = derivedRisk
		if !actionable {
			return RuntimeActionPlan{
				PlanID:        "runtime_action_plan." + shortHash(runtimeBundle.Metadata.ID+"\x00"+decisionID),
				DecisionID:    decisionID,
				EventType:     strings.TrimSpace(req.EventType),
				EventID:       strings.TrimSpace(req.EventID),
				BundleID:      runtimeBundle.Metadata.ID,
				PolicyID:      runtimeBundle.Metadata.PolicyID,
				SourceCommit:  runtimeBundle.Metadata.SourceCommit,
				CorrelationID: riskCorrelationID(req.CorrelationID, runtimeBundle.Metadata.CorrelationID, runtimeBundle.Metadata.ID, decisionID),
			}, bundleRecord.EnvelopeJSON, nil
		}
		actionType = derivedAction
	}
	if actionType == "" {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime action type is required")
	}
	if !actionAllowed(runtimeBundle, actionType) {
		return RuntimeActionPlan{}, nil, fmt.Errorf("runtime action %q is not allowed by bundle %q", actionType, runtimeBundle.Metadata.ID)
	}
	grant, err := validateCapabilityGrant(runtimeBundle, adapterID, capabilityID, actionType, targetScope, capabilityGrantID, ttl, m.now())
	if err != nil {
		return RuntimeActionPlan{}, nil, err
	}
	if err := validateRequestedProvenance(req, grant); err != nil {
		return RuntimeActionPlan{}, nil, err
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
		EventType:     strings.TrimSpace(req.EventType),
		EventID:       strings.TrimSpace(req.EventID),
		BundleID:      runtimeBundle.Metadata.ID,
		PolicyID:      runtimeBundle.Metadata.PolicyID,
		SourceCommit:  runtimeBundle.Metadata.SourceCommit,
		CorrelationID: correlationID,
		Actions: []PlannedRuntimeAction{{
			ActionID:              actionID,
			AdapterID:             adapterID,
			CapabilityID:          capabilityID,
			CapabilityGrantID:     capabilityGrantID,
			BindingID:             strings.TrimSpace(grant.BindingID),
			BindingDigest:         strings.TrimSpace(grant.BindingDigest),
			AdapterManifestDigest: strings.TrimSpace(grant.AdapterManifestDigest),
			ActionDigest:          strings.TrimSpace(grant.ActionDigest),
			CorrelationID:         correlationID,
			Mode:                  mode,
			Required:              mode == ActionModeRequired,
			ActionType:            actionType,
			TargetScope:           targetScope,
			TargetKey:             targetKey,
			TTL:                   ttlText,
			Reason:                reason,
			AuditID:               auditID,
			Context: map[string]any{
				"target_scope":   targetScope,
				"target_key":     targetKey,
				"reason":         reason,
				"ttl":            ttlText,
				"correlation_id": correlationID,
				"risk_type":      riskContext.RiskType,
				"risk_tier":      riskContext.Tier,
			},
		}},
	}
	return plan, bundleRecord.EnvelopeJSON, nil
}

func (m Manager) actionFromRiskCache(ctx context.Context, runtimeBundle corebundle.RuntimeBundle, requestedRiskType string) (string, corerisk.RiskContext, bool, error) {
	riskType := corerisk.NormalizeType(requestedRiskType)
	if riskType == "" {
		return "", corerisk.RiskContext{}, false, fmt.Errorf("risk_type is required when action_type is omitted")
	}
	riskContext, err := m.Store.RiskContext(ctx, actionstate.RiskCacheKey{RiskType: riskType, Scope: corerisk.ScopeLocal}, m.now())
	if err != nil {
		return "", corerisk.RiskContext{}, false, err
	}
	behavior, ok := corerisk.MatchBehavior(runtimeBundle.Spec.RiskBehavior, riskContext)
	if !ok {
		return "", riskContext, false, nil
	}
	actionType, actionable := corerisk.RuntimeActionForEffect(behavior.Effect)
	return actionType, riskContext, actionable, nil
}

func riskCorrelationID(requested, bundleCorrelationID, bundleID, decisionID string) string {
	correlationID := strings.TrimSpace(requested)
	if correlationID == "" {
		correlationID = strings.TrimSpace(bundleCorrelationID)
	}
	if correlationID == "" {
		correlationID = "correlation.local." + shortHash(bundleID+"\x00"+decisionID)
	}
	return correlationID
}

func runtimeDecisionRecord(plan RuntimeActionPlan, result RuntimeActionExecutionResult, now time.Time) actionstate.RuntimeDecisionRecord {
	status := "planned"
	activatedAction := ""
	if result.Applied {
		status = "executed"
		activatedAction = result.Lease.RuntimeActionID
	} else if result.Message != "" {
		status = "deduplicated"
		activatedAction = result.Lease.RuntimeActionID
	}
	data, _ := json.Marshal(map[string]any{
		"decision_id":      plan.DecisionID,
		"event_type":       plan.EventType,
		"event_id":         plan.EventID,
		"plan_id":          plan.PlanID,
		"bundle_id":        plan.BundleID,
		"policy_id":        plan.PolicyID,
		"source_commit":    plan.SourceCommit,
		"correlation_id":   plan.CorrelationID,
		"activated_action": activatedAction,
		"status":           status,
	})
	return actionstate.RuntimeDecisionRecord{
		DecisionID:      plan.DecisionID,
		PlanID:          plan.PlanID,
		PolicyID:        plan.PolicyID,
		BundleID:        plan.BundleID,
		SourceCommit:    plan.SourceCommit,
		CorrelationID:   plan.CorrelationID,
		EventType:       plan.EventType,
		EventID:         plan.EventID,
		Status:          status,
		PayloadSHA256:   domain.SHA256JSON(data),
		CreatedAt:       now.UTC(),
		ActivatedAction: activatedAction,
	}
}

func noActionRuntimeDecisionRecord(plan RuntimeActionPlan, now time.Time) actionstate.RuntimeDecisionRecord {
	data, _ := json.Marshal(map[string]any{
		"decision_id":    plan.DecisionID,
		"event_type":     plan.EventType,
		"event_id":       plan.EventID,
		"plan_id":        plan.PlanID,
		"bundle_id":      plan.BundleID,
		"policy_id":      plan.PolicyID,
		"source_commit":  plan.SourceCommit,
		"correlation_id": plan.CorrelationID,
		"status":         "no_action",
	})
	return actionstate.RuntimeDecisionRecord{
		DecisionID:    plan.DecisionID,
		PlanID:        plan.PlanID,
		PolicyID:      plan.PolicyID,
		BundleID:      plan.BundleID,
		SourceCommit:  plan.SourceCommit,
		CorrelationID: plan.CorrelationID,
		EventType:     plan.EventType,
		EventID:       plan.EventID,
		Status:        "no_action",
		PayloadSHA256: domain.SHA256JSON(data),
		CreatedAt:     now.UTC(),
	}
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

func (m Manager) ensureActiveContextRouteAllowsAction(ctx context.Context, adapterID, capabilityID string) error {
	credential, err := m.Store.KLIQCredential(ctx)
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	record, err := m.Store.ActiveArtifact(ctx, credential.KLIQID, "context_route_pack")
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var pack corecontext.ContextRoutePack
	if err := json.Unmarshal(record.PayloadJSON, &pack); err != nil {
		return err
	}
	for _, route := range pack.Spec.Routes {
		if routeAllowsConsumer(route.Consumers, adapterID, capabilityID) {
			return nil
		}
	}
	return fmt.Errorf("active context route pack %q does not allow adapter %q capability %q", record.ArtifactID, adapterID, capabilityID)
}

func routeAllowsConsumer(consumers []string, adapterID, capabilityID string) bool {
	for _, consumer := range consumers {
		switch strings.TrimSpace(consumer) {
		case "*", adapterID, capabilityID:
			return true
		}
	}
	return false
}

func (m Manager) ensureActiveFallbackAllowsExecution(ctx context.Context) error {
	credential, err := m.Store.KLIQCredential(ctx)
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	record, err := m.Store.ActiveArtifact(ctx, credential.KLIQID, "fallback_profile")
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var profile domain.KLIQFallbackProfile
	if err := json.Unmarshal(record.PayloadJSON, &profile); err != nil {
		return err
	}
	if !profile.AuditRequired {
		return fmt.Errorf("active fallback profile %q disables required audit; denying runtime action", profile.ProfileID)
	}
	if !profile.DenyNewActionsWhenDegraded {
		return nil
	}
	pending, err := m.Store.PendingAudits(ctx)
	if err != nil {
		return fmt.Errorf("audit spool unavailable under fallback profile %q: %w", profile.ProfileID, err)
	}
	for _, record := range pending {
		if record.RetryCount > 0 || record.LastError != "" {
			return fmt.Errorf("active fallback profile %q denies new runtime actions while audit spool is degraded", profile.ProfileID)
		}
	}
	return nil
}

func (m Manager) appendActiveConformanceExpectationAudit(ctx context.Context, lease actionstate.RuntimeActionLease, now time.Time) error {
	credential, err := m.Store.KLIQCredential(ctx)
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	record, err := m.Store.ActiveArtifact(ctx, credential.KLIQID, "conformance_expectation")
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var expectation conformance.ConformanceExpectation
	if err := json.Unmarshal(record.PayloadJSON, &expectation); err != nil {
		return err
	}
	if len(expectation.Spec.Expectations) == 0 && len(expectation.Spec.Prohibit) == 0 {
		return nil
	}
	return m.Store.AppendAudit(ctx, audit(lease, "conformance expectations active for runtime action", now))
}

func (m Manager) executePlannedAction(ctx context.Context, plan RuntimeActionPlan, action PlannedRuntimeAction, executor RuntimeExecutor, signedBundle []byte) (RuntimeActionExecutionResult, error) {
	now := m.now()
	if err := m.ensureActiveFallbackAllowsExecution(ctx); err != nil {
		return RuntimeActionExecutionResult{}, err
	}
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
	if err := m.appendActiveConformanceExpectationAudit(ctx, lease, now); err != nil {
		return RuntimeActionExecutionResult{}, fmt.Errorf("local conformance audit write failed; denying runtime action: %w", err)
	}
	if err := m.Store.AppendAudit(ctx, audit(lease, "runtime action activation authorized", now)); err != nil {
		return RuntimeActionExecutionResult{}, fmt.Errorf("local audit write failed; denying runtime action: %w", err)
	}
	if err := executor.Execute(ctx, lease, signedBundle); err != nil {
		return m.recoverAfterExecuteError(ctx, executor, lease, now, err)
	}
	if err := m.Store.UpsertLease(ctx, lease); err != nil {
		return RuntimeActionExecutionResult{}, err
	}
	if err := m.Store.AppendJournal(ctx, journal(lease.RuntimeActionID, "activated", lease.Status, "runtime action activated", now)); err != nil {
		return RuntimeActionExecutionResult{}, err
	}
	return RuntimeActionExecutionResult{Lease: lease, Applied: true, Message: "runtime action activated"}, nil
}

func leaseFromPlannedAction(plan RuntimeActionPlan, action PlannedRuntimeAction, now time.Time) actionstate.RuntimeActionLease {
	ttl, _ := time.ParseDuration(action.TTL)
	idempotencyKey := idempotencyKey(plan.BundleID, plan.DecisionID, action.AdapterID, action.CapabilityID, action.ActionType, action.TargetScope, action.TargetKey)
	return actionstate.RuntimeActionLease{
		RuntimeActionID:       "runtime_action." + shortHash(idempotencyKey),
		PlanID:                plan.PlanID,
		DecisionID:            plan.DecisionID,
		PolicyID:              plan.PolicyID,
		BundleID:              plan.BundleID,
		SourceCommit:          plan.SourceCommit,
		CorrelationID:         plan.CorrelationID,
		ActionType:            action.ActionType,
		TargetScope:           action.TargetScope,
		TargetKey:             action.TargetKey,
		TTL:                   action.TTL,
		ExpiresAt:             now.Add(ttl).UTC(),
		Reason:                action.Reason,
		AuditID:               action.AuditID,
		CapabilityGrantID:     action.CapabilityGrantID,
		BindingID:             action.BindingID,
		BindingDigest:         action.BindingDigest,
		AdapterManifestDigest: action.AdapterManifestDigest,
		ActionDigest:          action.ActionDigest,
		AdapterID:             action.AdapterID,
		CapabilityID:          action.CapabilityID,
		Mode:                  action.Mode,
		Required:              action.Required,
		IdempotencyKey:        idempotencyKey,
		CreatedAt:             now,
		LastReconciledAt:      now,
		Status:                domain.RuntimeActionActive,
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

func validateCapabilityGrant(runtimeBundle corebundle.RuntimeBundle, adapterID, capabilityID, actionType, targetScope, grantID string, ttl time.Duration, now time.Time) (corebundle.CapabilityGrant, error) {
	var grant corebundle.CapabilityGrant
	found := false
	for _, candidate := range runtimeBundle.Spec.CapabilityGrants {
		if candidate.ID == grantID {
			grant = candidate
			found = true
			break
		}
	}
	if !found {
		return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q is not present in runtime bundle %q", grantID, runtimeBundle.Metadata.ID)
	}
	if strings.TrimSpace(grant.AdapterID) != adapterID {
		return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q adapter_id %q does not match requested adapter %q", grantID, grant.AdapterID, adapterID)
	}
	if strings.TrimSpace(grant.CapabilityID) != capabilityID {
		return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q capability_id %q does not match requested capability %q", grantID, grant.CapabilityID, capabilityID)
	}
	if strings.TrimSpace(grant.ActionType) != actionType {
		return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q action_type %q does not match requested action %q", grantID, grant.ActionType, actionType)
	}
	if !grantAllowsScope(grant, targetScope) {
		return corebundle.CapabilityGrant{}, fmt.Errorf("target scope %q is not allowed by capability grant %q", targetScope, grantID)
	}
	if strings.TrimSpace(grant.MaxTTL) != "" {
		maxTTL, err := parsePositiveDuration(grant.MaxTTL, "capability grant max_ttl")
		if err != nil {
			return corebundle.CapabilityGrant{}, err
		}
		if ttl > maxTTL {
			return corebundle.CapabilityGrant{}, fmt.Errorf("ttl %s exceeds capability grant max_ttl %s", ttl, maxTTL)
		}
	}
	if strings.TrimSpace(grant.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(grant.ExpiresAt))
		if err != nil {
			return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q expires_at is invalid: %w", grantID, err)
		}
		if !now.UTC().Before(expiresAt.UTC()) {
			return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q is expired", grantID)
		}
	}
	requiredProvenance := map[string]string{
		"binding_id":              grant.BindingID,
		"binding_digest":          grant.BindingDigest,
		"adapter_manifest_digest": grant.AdapterManifestDigest,
		"action_digest":           grant.ActionDigest,
	}
	for field, value := range requiredProvenance {
		if strings.TrimSpace(value) == "" {
			return corebundle.CapabilityGrant{}, fmt.Errorf("capability grant %q missing required provenance field %s", grantID, field)
		}
	}
	return grant, nil
}

func grantAllowsScope(grant corebundle.CapabilityGrant, targetScope string) bool {
	for _, scope := range grant.AllowedTargetScopes {
		if strings.TrimSpace(scope) == targetScope {
			return true
		}
	}
	return false
}

func validateRequestedProvenance(req ExecuteRequest, grant corebundle.CapabilityGrant) error {
	checks := []struct {
		field     string
		requested string
		expected  string
	}{
		{field: "binding_id", requested: req.BindingID, expected: grant.BindingID},
		{field: "binding_digest", requested: req.BindingDigest, expected: grant.BindingDigest},
		{field: "adapter_manifest_digest", requested: req.AdapterManifestDigest, expected: grant.AdapterManifestDigest},
		{field: "action_digest", requested: req.ActionDigest, expected: grant.ActionDigest},
	}
	for _, check := range checks {
		requested := strings.TrimSpace(check.requested)
		if requested == "" {
			continue
		}
		expected := strings.TrimSpace(check.expected)
		if requested != expected {
			return fmt.Errorf("requested %s %q does not match runtime bundle grant %q", check.field, requested, expected)
		}
	}
	return nil
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
		"runtime_action_id":       lease.RuntimeActionID,
		"plan_id":                 lease.PlanID,
		"decision_id":             lease.DecisionID,
		"policy_id":               lease.PolicyID,
		"bundle_id":               lease.BundleID,
		"source_commit":           lease.SourceCommit,
		"correlation_id":          lease.CorrelationID,
		"adapter_id":              lease.AdapterID,
		"capability_id":           lease.CapabilityID,
		"capability_grant_id":     lease.CapabilityGrantID,
		"binding_id":              lease.BindingID,
		"binding_digest":          lease.BindingDigest,
		"adapter_manifest_digest": lease.AdapterManifestDigest,
		"action_digest":           lease.ActionDigest,
		"mode":                    lease.Mode,
		"action_type":             lease.ActionType,
		"target_scope":            lease.TargetScope,
		"audit_id":                lease.AuditID,
		"status":                  string(lease.Status),
		"message":                 message,
		"expires_at":              lease.ExpiresAt.Format(time.RFC3339Nano),
	})
	return actionstate.AuditRecord{
		ID:                    "audit_spool." + shortHash(lease.RuntimeActionID+string(lease.Status)+message+now.Format(time.RFC3339Nano)),
		RuntimeActionID:       lease.RuntimeActionID,
		BindingID:             lease.BindingID,
		BindingDigest:         lease.BindingDigest,
		AdapterManifestDigest: lease.AdapterManifestDigest,
		ActionDigest:          lease.ActionDigest,
		Status:                AuditPendingUpload,
		Payload:               string(data),
		PayloadSHA256:         domain.SHA256JSON(data),
		CreatedAt:             now,
	}
}
