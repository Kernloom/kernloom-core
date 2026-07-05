// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/management"
)

type enrollmentTokenRequest struct {
	Environment string      `json:"environment"`
	Stage       string      `json:"stage"`
	Scope       string      `json:"scope"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	ScopeAuth   authn.Scope `json:"scope_auth,omitempty"`
}

type enrollmentTokenResponse struct {
	Token       domain.KLIQEnrollmentToken `json:"token"`
	SecretToken string                     `json:"secret_token"`
}

type enrollmentRequest struct {
	EnrollmentToken string   `json:"enrollment_token"`
	NodeID          string   `json:"node_id"`
	Environment     string   `json:"environment"`
	Stage           string   `json:"stage"`
	Scope           string   `json:"scope"`
	Version         string   `json:"version"`
	Adapters        []string `json:"adapter_inventory,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Attestation     string   `json:"attestation_state,omitempty"`
	TrustKeyID      string   `json:"trust_key_id,omitempty"`
	PublicKeyPEM    string   `json:"public_key_pem,omitempty"`
	CSRPEM          string   `json:"csr_pem,omitempty"`
	SPIFFEID        string   `json:"spiffe_id,omitempty"`
}

type enrollmentResponse struct {
	Registration domain.KLIQRegistration `json:"registration"`
	ServiceToken string                  `json:"service_token,omitempty"`
}

type serviceTokenRefreshResponse struct {
	ServiceToken string    `json:"service_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type buildApprovalRequest struct {
	BuildRef      coreartifact.Ref `json:"build_ref"`
	Environment   string           `json:"environment"`
	Stage         string           `json:"stage"`
	Scope         string           `json:"scope"`
	AuthorityID   string           `json:"authority_id,omitempty"`
	AuthorityKind string           `json:"authority_kind,omitempty"`
	ExpiresAt     *time.Time       `json:"expires_at,omitempty"`
}

type buildApprovalResponse struct {
	ApprovedBuildRef coreartifact.Ref             `json:"approved_build_ref"`
	Manifest         compiler.PolicyBuildManifest `json:"manifest"`
}

type assignmentPlanRequest struct {
	KLIQID           string                        `json:"kliq_id"`
	SourceCommit     string                        `json:"source_commit"`
	TrustBundleRef   string                        `json:"trust_bundle_ref,omitempty"`
	ApprovedBuildRef coreartifact.Ref              `json:"approved_build_ref"`
	ExpiresAt        time.Time                     `json:"expires_at"`
	ApprovedRollback bool                          `json:"approved_rollback,omitempty"`
	Artifacts        []domain.KLIQAssignedArtifact `json:"artifacts"`
}

type revocationRequest struct {
	Reason string `json:"reason"`
}

type trustBundleRotationRequest struct {
	Next   domain.TrustBundle `json:"next"`
	Reason string             `json:"reason,omitempty"`
}

func (s Server) approvePolicyBuildManifest(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Artifacts == nil || s.ManagementSign == nil {
		writeError(w, http.StatusInternalServerError, "build_approval_not_configured")
		return
	}
	var req buildApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if strings.TrimSpace(req.BuildRef.URI) == "" || strings.TrimSpace(req.BuildRef.SHA256) == "" ||
		strings.TrimSpace(req.Environment) == "" || strings.TrimSpace(req.Stage) == "" || strings.TrimSpace(req.Scope) == "" {
		writeError(w, http.StatusBadRequest, "invalid_build_approval_request")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "policy_build_manifest.approve",
		AllowedRoles: authz.PolicyBuildApproveRoles(),
		Scope: authn.Scope{
			Environment: strings.TrimSpace(req.Environment),
			Stage:       strings.TrimSpace(req.Stage),
		},
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	payload, err := s.Artifacts.Get(r.Context(), req.BuildRef)
	if err != nil {
		writeError(w, http.StatusBadRequest, "build_manifest_unavailable")
		return
	}
	payload, err = s.verifyApprovedBuildManifestEnvelope(r, payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var manifest compiler.PolicyBuildManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		writeError(w, http.StatusBadRequest, "build_manifest_invalid")
		return
	}
	if manifest.Kind != "PolicyBuildManifest" {
		writeError(w, http.StatusBadRequest, "build_manifest_invalid_kind")
		return
	}
	if strings.TrimSpace(manifest.Approval.Status) != "pending_review" {
		writeError(w, http.StatusBadRequest, "build_manifest_not_pending_review")
		return
	}
	if err := validateBuildManifestApprovalReadiness(manifest); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if samePrincipal(manifest.Metadata.CreatedBy, principal.Subject) {
		writeError(w, http.StatusForbidden, "build_manifest_self_approval_rejected")
		return
	}
	now := time.Now().UTC()
	authorityID := strings.TrimSpace(req.AuthorityID)
	if authorityID == "" {
		authorityID = principal.Subject
	}
	authorityKind := strings.TrimSpace(req.AuthorityKind)
	if authorityKind == "" {
		authorityKind = "forge-api-approval"
	}
	manifest.Approval = compiler.ManifestApproval{
		Status:        "approved",
		ApprovedBy:    principal.Subject,
		ApprovedAt:    now,
		AuthorityID:   authorityID,
		AuthorityKind: authorityKind,
		Environment:   strings.TrimSpace(req.Environment),
		Stage:         strings.TrimSpace(req.Stage),
		Scope:         strings.TrimSpace(req.Scope),
	}
	approvedPayload, err := json.Marshal(manifest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build_manifest_marshal_failed")
		return
	}
	expiresAt := now.Add(24 * time.Hour)
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt.UTC()
	}
	envelope, err := s.ManagementSign.Sign(r.Context(), approvedPayload, signing.Metadata{
		SourceCommit: manifest.Spec.PolicyRepo.Commit,
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build_manifest_signing_failed")
		return
	}
	envelopePayload, err := json.Marshal(envelope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build_manifest_envelope_marshal_failed")
		return
	}
	policyID := strings.TrimPrefix(manifest.Metadata.ID, "build.")
	ref, err := s.Artifacts.Put(r.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{
			ID:            "approved." + manifest.Metadata.ID,
			PolicyID:      policyID,
			ArtifactType:  "policy_build_manifest_signed_envelope",
			SourceCommit:  manifest.Spec.PolicyRepo.Commit,
			CorrelationID: manifest.Metadata.CorrelationID,
			CreatedAt:     now,
		},
		Payload: envelopePayload,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "approved_build_manifest_store_failed")
		return
	}
	if s.Management != nil {
		_ = s.Management.SaveAuditEvent(r.Context(), domain.ManagementAuditEvent{
			EventType:   "policy_build_manifest_approved",
			Actor:       principal.Subject,
			TargetType:  "policy_build_manifest",
			TargetID:    manifest.Metadata.ID,
			Environment: manifest.Approval.Environment,
			Stage:       manifest.Approval.Stage,
			Scope:       manifest.Approval.Scope,
			Metadata: map[string]any{
				"source_commit":      manifest.Spec.PolicyRepo.Commit,
				"approved_build_ref": ref.URI,
				"authority_id":       manifest.Approval.AuthorityID,
				"authority_kind":     manifest.Approval.AuthorityKind,
			},
			CreatedAt: now,
		})
	}
	writeJSON(w, http.StatusCreated, buildApprovalResponse{ApprovedBuildRef: ref, Manifest: manifest})
}

func validateBuildManifestApprovalReadiness(manifest compiler.PolicyBuildManifest) error {
	if strings.TrimSpace(manifest.Metadata.ID) == "" {
		return fmt.Errorf("build_manifest_missing_id")
	}
	if strings.TrimSpace(manifest.Metadata.CreatedBy) == "" {
		return fmt.Errorf("build_manifest_missing_created_by")
	}
	if strings.TrimSpace(manifest.Spec.PolicyRepo.Commit) == "" {
		return fmt.Errorf("build_manifest_missing_source_commit")
	}
	if manifest.Spec.CoreRegistry.ContentDigest == "" ||
		manifest.Spec.EnterpriseRegistry.ContentDigest == "" ||
		manifest.Spec.CatalogDigest == "" ||
		manifest.Spec.Profile.Digest == "" ||
		manifest.Spec.RiskRecipe.Digest == "" {
		return fmt.Errorf("build_manifest_missing_provenance")
	}
	if len(manifest.Spec.SignedOutputs) == 0 {
		return fmt.Errorf("build_manifest_missing_signed_outputs")
	}
	for artifactType, signed := range manifest.Spec.SignedOutputs {
		if strings.TrimSpace(artifactType) == "" ||
			strings.TrimSpace(signed.ArtifactRef.URI) == "" ||
			strings.TrimSpace(signed.ArtifactRef.SHA256) == "" ||
			strings.TrimSpace(signed.EnvelopeSHA256) == "" ||
			strings.TrimSpace(signed.PayloadSHA256) == "" ||
			strings.TrimSpace(signed.KeyID) == "" {
			return fmt.Errorf("build_manifest_incomplete_signed_output")
		}
	}
	return nil
}

func samePrincipal(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func (s Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	var req enrollmentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.enrollment_token.create",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope: authn.Scope{
			Environment: req.Environment,
			Stage:       req.Stage,
		},
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	secret, err := management.NewEnrollmentSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_generation_failed")
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour)
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt.UTC()
	}
	tokenHash := management.TokenSHA256(secret)
	tokenID := "kliq_enrollment_token." + strings.TrimPrefix(tokenHash, "sha256:")[:16]
	token := domain.KLIQEnrollmentToken{
		TokenID:     tokenID,
		TokenSHA256: tokenHash,
		Environment: strings.TrimSpace(req.Environment),
		Stage:       strings.TrimSpace(req.Stage),
		Scope:       strings.TrimSpace(req.Scope),
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
	}
	if err := s.Management.CreateEnrollmentToken(r.Context(), token, secret); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_enrollment_token")
		return
	}
	token.TokenSHA256 = management.TokenSHA256(secret)
	writeJSON(w, http.StatusCreated, enrollmentTokenResponse{Token: token, SecretToken: secret})
}

func (s Server) enrollKLIQ(w http.ResponseWriter, r *http.Request) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	var req enrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if strings.TrimSpace(req.EnrollmentToken) == "" || strings.TrimSpace(req.NodeID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_enrollment_request")
		return
	}
	if strings.TrimSpace(req.PublicKeyPEM) == "" && strings.TrimSpace(req.CSRPEM) == "" {
		writeError(w, http.StatusBadRequest, "missing_identity_material")
		return
	}
	if err := validateIdentityMaterial(req.PublicKeyPEM, req.CSRPEM); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_identity_material")
		return
	}
	now := time.Now().UTC()
	token, err := s.Management.UseEnrollmentToken(r.Context(), req.EnrollmentToken, req.Environment, req.Stage, req.Scope, now)
	if err != nil {
		writeError(w, http.StatusForbidden, "invalid_enrollment_token")
		return
	}
	trustKeyID := strings.TrimSpace(req.TrustKeyID)
	if trustKeyID == "" {
		trustKeyID = "dev-local"
	}
	kliqID := management.StableKLIQID(req.NodeID, req.Environment, req.Stage, req.Scope)
	spiffeID := strings.TrimSpace(req.SPIFFEID)
	if spiffeID == "" {
		spiffeID = authn.DefaultKLIQSPIFFEID(kliqID, req.Environment, req.Stage, req.Scope)
	}
	identity := domain.KLIQIdentity{
		IdentityID:              "kliq_identity." + kliqID,
		KLIQID:                  kliqID,
		NodeID:                  req.NodeID,
		Environment:             req.Environment,
		Stage:                   req.Stage,
		Scope:                   req.Scope,
		TrustKeyID:              trustKeyID,
		PublicKeyPEM:            strings.TrimSpace(req.PublicKeyPEM),
		CSRPEM:                  strings.TrimSpace(req.CSRPEM),
		ServiceIdentityProvider: authn.ServiceIdentityProviderSPIFFEReady,
		SPIFFEID:                spiffeID,
		CredentialStatus:        "active",
		CredentialExpiresAt:     now.Add(24 * time.Hour),
		Status:                  "active",
		IssuedAt:                now,
	}
	registration := domain.KLIQRegistration{
		RegistrationID:    "kliq_registration." + kliqID,
		KLIQID:            kliqID,
		NodeID:            req.NodeID,
		Environment:       req.Environment,
		Stage:             req.Stage,
		Scope:             req.Scope,
		Version:           req.Version,
		AdapterInventory:  append([]string(nil), req.Adapters...),
		Capabilities:      append([]string(nil), req.Capabilities...),
		AttestationState:  req.Attestation,
		Identity:          identity,
		ManagementProfile: defaultManagementProfile(kliqID),
		Status:            "active",
		RegisteredAt:      now,
	}
	registerCtx := management.WithAuditMetadata(r.Context(), map[string]any{
		"enrollment_token_id": token.TokenID,
		"kliq_id":             kliqID,
	})
	if err := s.Management.Register(registerCtx, registration); err != nil {
		writeError(w, http.StatusInternalServerError, "registration_failed")
		return
	}
	var serviceToken string
	if s.KLIQService != nil {
		token, err := s.KLIQService.IssueForIdentity(identity, 24*time.Hour)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "service_token_issue_failed")
			return
		}
		serviceToken = token
	}
	writeJSON(w, http.StatusCreated, enrollmentResponse{Registration: registration, ServiceToken: serviceToken})
}

func (s Server) refreshKLIQServiceToken(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil || s.KLIQService == nil {
		writeError(w, http.StatusInternalServerError, "kliq_service_refresh_not_configured")
		return
	}
	kliqID := authn.PrincipalKLIQID(principal)
	registration, err := s.Management.Registration(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := authorizeKLIQServicePrincipal(principal, registration); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	token, err := s.KLIQService.IssueForIdentity(registration.Identity, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "service_token_issue_failed")
		return
	}
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	writeJSON(w, http.StatusOK, serviceTokenRefreshResponse{ServiceToken: token, ExpiresAt: expiresAt})
}

func (s Server) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	token, err := s.Management.EnrollmentToken(r.Context(), strings.TrimSpace(r.PathValue("token_id")))
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "enrollment_token_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "enrollment_token_read_failed")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.enrollment_token.revoke",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope: authn.Scope{
			Environment: token.Environment,
			Stage:       token.Stage,
		},
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	reason := decodeRevocationReason(r)
	if err := s.Management.RevokeEnrollmentToken(r.Context(), token.TokenID, reason, time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "enrollment_token_revoke_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "revoked"})
}

func (s Server) planKLIQAssignment(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil || s.ManagementSign == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_not_configured")
		return
	}
	if s.Artifacts == nil {
		writeError(w, http.StatusInternalServerError, "artifact_store_not_configured")
		return
	}
	var req assignmentPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	registration, err := s.Management.Registration(r.Context(), strings.TrimSpace(req.KLIQID))
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.assignment.plan",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if strings.TrimSpace(req.SourceCommit) == "" || req.ExpiresAt.IsZero() || len(req.Artifacts) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_assignment_plan")
		return
	}
	if err := rejectRawAssignmentArtifactEnvelopes(req.Artifacts); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	approvedBuild, err := s.validateApprovedBuild(r, registration, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	artifacts, err := s.resolveAssignmentArtifacts(r, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	version, err := s.Management.NextAssignmentVersion(r.Context(), registration.KLIQID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "assignment_version_failed")
		return
	}
	trustBundleRef := strings.TrimSpace(req.TrustBundleRef)
	if trustBundleRef == "" {
		trustBundleRef = registration.Identity.TrustKeyID
	}
	now := time.Now().UTC()
	assignment := domain.KLIQAssignment{
		AssignmentID:      fmt.Sprintf("kliq_assignment.%s.%s.v%d", registration.KLIQID, req.SourceCommit, version),
		AssignmentVersion: version,
		KLIQID:            registration.KLIQID,
		Environment:       registration.Environment,
		Stage:             registration.Stage,
		Scope:             registration.Scope,
		SourceCommit:      req.SourceCommit,
		TrustKeyID:        registration.Identity.TrustKeyID,
		TrustBundleRef:    trustBundleRef,
		CreatedAt:         now,
		ExpiresAt:         req.ExpiresAt.UTC(),
		ApprovedRollback:  req.ApprovedRollback,
		Artifacts:         artifacts,
		Status:            "active",
	}
	envelope, err := s.signAndStoreAssignment(r, assignment)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.Management.SaveAuditEvent(r.Context(), domain.ManagementAuditEvent{
		EventType:   "assignment_planned",
		Actor:       principal.Subject,
		TargetType:  "kliq_assignment",
		TargetID:    assignment.AssignmentID,
		KLIQID:      assignment.KLIQID,
		Environment: assignment.Environment,
		Stage:       assignment.Stage,
		Scope:       assignment.Scope,
		Metadata: map[string]any{
			"assignment_version": assignment.AssignmentVersion,
			"source_commit":      assignment.SourceCommit,
			"approved_build_id":  approvedBuild.Metadata.ID,
			"approved_build_ref": req.ApprovedBuildRef.URI,
		},
		CreatedAt: now,
	})
	writeJSON(w, http.StatusCreated, envelope)
}

func (s Server) validateApprovedBuild(r *http.Request, registration domain.KLIQRegistration, req assignmentPlanRequest) (compiler.PolicyBuildManifest, error) {
	if strings.TrimSpace(req.ApprovedBuildRef.URI) == "" || strings.TrimSpace(req.ApprovedBuildRef.SHA256) == "" {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_required")
	}
	payload, err := s.Artifacts.Get(r.Context(), req.ApprovedBuildRef)
	if err != nil {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_unavailable")
	}
	payload, err = s.verifyApprovedBuildManifestEnvelope(r, payload)
	if err != nil {
		return compiler.PolicyBuildManifest{}, err
	}
	var manifest compiler.PolicyBuildManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_invalid")
	}
	if manifest.Kind != "PolicyBuildManifest" {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_invalid_kind")
	}
	if manifest.Approval.Status != "approved" {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_not_approved")
	}
	if err := validateApprovedBuildAuthority(manifest, registration); err != nil {
		return compiler.PolicyBuildManifest{}, err
	}
	if strings.TrimSpace(manifest.Spec.PolicyRepo.Commit) != strings.TrimSpace(req.SourceCommit) {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_source_commit_mismatch")
	}
	if manifest.Spec.CoreRegistry.ContentDigest == "" ||
		manifest.Spec.EnterpriseRegistry.ContentDigest == "" ||
		manifest.Spec.CatalogDigest == "" ||
		manifest.Spec.Profile.Digest == "" ||
		manifest.Spec.RiskRecipe.Digest == "" {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_missing_provenance")
	}
	if manifest.Metadata.ID == "" {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("approved_build_missing_id")
	}
	if registration.Environment == "" || registration.Stage == "" || registration.Scope == "" {
		return compiler.PolicyBuildManifest{}, fmt.Errorf("kliq_registration_scope_incomplete")
	}
	for _, requested := range req.Artifacts {
		if err := validateArtifactInApprovedBuild(manifest, requested); err != nil {
			return compiler.PolicyBuildManifest{}, err
		}
	}
	return manifest, nil
}

func (s Server) verifyApprovedBuildManifestEnvelope(r *http.Request, payload []byte) ([]byte, error) {
	var envelope signing.SignedEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("approved_build_must_be_signed")
	}
	if envelope.Kind != "SignedEnvelope" || envelope.PayloadSHA256 == "" || len(envelope.Payload) == 0 {
		return nil, fmt.Errorf("approved_build_must_be_signed")
	}
	verifier, ok := s.ManagementSign.(signing.Verifier)
	if !ok {
		return nil, fmt.Errorf("approved_build_verifier_unavailable")
	}
	result, err := verifier.Verify(r.Context(), envelope)
	if err != nil {
		return nil, fmt.Errorf("approved_build_signature_verification_failed")
	}
	if !result.Valid {
		return nil, fmt.Errorf("approved_build_signature_invalid")
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(envelope.Payload, &header); err != nil {
		return nil, fmt.Errorf("approved_build_invalid")
	}
	if header.Kind != "PolicyBuildManifest" {
		return nil, fmt.Errorf("approved_build_invalid_kind")
	}
	return envelope.Payload, nil
}

func validateApprovedBuildAuthority(manifest compiler.PolicyBuildManifest, registration domain.KLIQRegistration) error {
	if strings.TrimSpace(manifest.Metadata.CreatedBy) == "" {
		return fmt.Errorf("approved_build_missing_created_by")
	}
	if strings.TrimSpace(manifest.Approval.ApprovedBy) == "" ||
		manifest.Approval.ApprovedAt.IsZero() ||
		strings.TrimSpace(manifest.Approval.AuthorityID) == "" ||
		strings.TrimSpace(manifest.Approval.AuthorityKind) == "" {
		return fmt.Errorf("approved_build_missing_approval_authority")
	}
	if samePrincipal(manifest.Metadata.CreatedBy, manifest.Approval.ApprovedBy) {
		return fmt.Errorf("approved_build_self_approval_rejected")
	}
	if strings.TrimSpace(manifest.Approval.Environment) == "" ||
		strings.TrimSpace(manifest.Approval.Stage) == "" ||
		strings.TrimSpace(manifest.Approval.Scope) == "" {
		return fmt.Errorf("approved_build_missing_scope_binding")
	}
	if strings.TrimSpace(manifest.Approval.Environment) != strings.TrimSpace(registration.Environment) ||
		strings.TrimSpace(manifest.Approval.Stage) != strings.TrimSpace(registration.Stage) ||
		strings.TrimSpace(manifest.Approval.Scope) != strings.TrimSpace(registration.Scope) {
		return fmt.Errorf("approved_build_scope_mismatch")
	}
	return nil
}

func validateArtifactInApprovedBuild(manifest compiler.PolicyBuildManifest, requested domain.KLIQAssignedArtifact) error {
	artifactType := strings.TrimSpace(requested.ArtifactType)
	ref := coreartifact.Ref{URI: strings.TrimSpace(requested.ArtifactRef), SHA256: strings.TrimSpace(requested.SHA256)}
	if ref.URI == "" || ref.SHA256 == "" {
		return fmt.Errorf("invalid_artifact_ref")
	}
	if signed, ok := manifest.Spec.SignedOutputs[artifactType]; ok {
		if signed.ArtifactRef.URI == ref.URI &&
			signed.ArtifactRef.SHA256 == ref.SHA256 &&
			signed.EnvelopeSHA256 == ref.SHA256 &&
			strings.TrimSpace(signed.KeyID) != "" {
			return nil
		}
		return fmt.Errorf("artifact_not_in_approved_build")
	}
	if unsigned, ok := manifest.Spec.ArtifactRefs[artifactType]; ok {
		if unsigned.URI == ref.URI && unsigned.SHA256 == ref.SHA256 {
			return nil
		}
		return fmt.Errorf("artifact_not_in_approved_build")
	}
	return fmt.Errorf("artifact_not_in_approved_build")
}

func (s Server) resolveAssignmentArtifacts(r *http.Request, req assignmentPlanRequest) ([]domain.KLIQAssignedArtifact, error) {
	artifacts := make([]domain.KLIQAssignedArtifact, 0, len(req.Artifacts))
	for _, requested := range req.Artifacts {
		if strings.TrimSpace(requested.ArtifactType) == "" || strings.TrimSpace(requested.ArtifactID) == "" {
			return nil, fmt.Errorf("invalid_artifact_ref")
		}
		if !allowedAssignmentArtifactType(requested.ArtifactType) {
			return nil, fmt.Errorf("unsupported_assignment_artifact_type")
		}
		ref := coreartifact.Ref{
			URI:    strings.TrimSpace(requested.ArtifactRef),
			SHA256: strings.TrimSpace(requested.SHA256),
		}
		if ref.URI == "" || ref.SHA256 == "" {
			return nil, fmt.Errorf("invalid_artifact_ref")
		}
		payload, err := s.Artifacts.Get(r.Context(), ref)
		if err != nil {
			return nil, fmt.Errorf("artifact_ref_unavailable")
		}
		var envelope signing.SignedEnvelope
		if err := json.Unmarshal(payload, &envelope); err != nil {
			return nil, fmt.Errorf("artifact_ref_not_signed_envelope")
		}
		if envelope.Kind != "SignedEnvelope" || envelope.PayloadSHA256 == "" {
			return nil, fmt.Errorf("artifact_ref_not_signed_envelope")
		}
		if err := s.verifyAssignmentArtifactEnvelope(r, requested.ArtifactType, envelope); err != nil {
			return nil, err
		}
		if strings.TrimSpace(envelope.SourceCommit) != strings.TrimSpace(req.SourceCommit) {
			return nil, fmt.Errorf("artifact_source_commit_mismatch")
		}
		artifacts = append(artifacts, domain.KLIQAssignedArtifact{
			ArtifactType: strings.TrimSpace(requested.ArtifactType),
			ArtifactID:   strings.TrimSpace(requested.ArtifactID),
			ArtifactRef:  ref.URI,
			SHA256:       ref.SHA256,
			Envelope:     json.RawMessage(payload),
		})
	}
	return artifacts, nil
}

func rejectRawAssignmentArtifactEnvelopes(artifacts []domain.KLIQAssignedArtifact) error {
	for _, artifact := range artifacts {
		if len(artifact.Envelope) > 0 && strings.TrimSpace(string(artifact.Envelope)) != "null" {
			return fmt.Errorf("raw_artifact_envelope_not_allowed")
		}
	}
	return nil
}

func allowedAssignmentArtifactType(artifactType string) bool {
	return domain.SupportedAssignmentArtifactType(strings.TrimSpace(artifactType))
}

func (s Server) verifyAssignmentArtifactEnvelope(r *http.Request, artifactType string, envelope signing.SignedEnvelope) error {
	verifier, ok := s.ManagementSign.(signing.Verifier)
	if !ok {
		return fmt.Errorf("artifact_signature_verifier_unavailable")
	}
	result, err := verifier.Verify(r.Context(), envelope)
	if err != nil {
		return fmt.Errorf("artifact_signature_verification_failed")
	}
	if !result.Valid {
		return fmt.Errorf("artifact_signature_invalid")
	}
	if err := validateAssignmentArtifactPayloadType(artifactType, envelope.Payload); err != nil {
		return err
	}
	return nil
}

func validateAssignmentArtifactPayloadType(artifactType string, payload []byte) error {
	var header struct {
		Kind     string `json:"kind"`
		Metadata struct {
			ArtifactType string `json:"artifact_type"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return fmt.Errorf("artifact_payload_invalid")
	}
	if expected := expectedAssignmentArtifactKind(artifactType); expected != "" && header.Kind != expected {
		return fmt.Errorf("artifact_payload_kind_mismatch")
	}
	if header.Metadata.ArtifactType != "" && header.Metadata.ArtifactType != artifactType {
		return fmt.Errorf("artifact_payload_type_mismatch")
	}
	return nil
}

func expectedAssignmentArtifactKind(artifactType string) string {
	switch strings.TrimSpace(artifactType) {
	case "runtime_bundle":
		return "RuntimeBundle"
	case "context_route_pack":
		return "ContextRoutePack"
	case "conformance_expectation":
		return "ConformanceExpectation"
	case "adapter_assignment":
		return "AdapterAssignment"
	default:
		return ""
	}
}

func (s Server) createDevKLIQAssignment(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil || s.ManagementSign == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_not_configured")
		return
	}
	if !s.DevManagement {
		writeError(w, http.StatusForbidden, "dev_management_disabled")
		return
	}
	var assignment domain.KLIQAssignment
	if err := json.NewDecoder(r.Body).Decode(&assignment); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	registration, err := s.Management.Registration(r.Context(), strings.TrimSpace(assignment.KLIQID))
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := validateKLIQScope(registration, assignment.Environment, assignment.Stage, assignment.Scope); err != nil {
		writeError(w, http.StatusBadRequest, "assignment_scope_mismatch")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.assignment.dev_create",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	now := time.Now().UTC()
	if assignment.CreatedAt.IsZero() {
		assignment.CreatedAt = now
	}
	if assignment.AssignmentID == "" {
		assignment.AssignmentID = "kliq_assignment." + assignment.KLIQID + "." + assignment.SourceCommit
	}
	if assignment.TrustBundleRef == "" {
		assignment.TrustBundleRef = assignment.TrustKeyID
	}
	if assignment.Status == "" {
		assignment.Status = "active"
	}
	envelope, err := s.signAndStoreAssignment(r, assignment)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope)
}

func (s Server) signAndStoreAssignment(r *http.Request, assignment domain.KLIQAssignment) (signing.SignedEnvelope, error) {
	if err := validateAssignmentRequest(assignment); err != nil {
		return signing.SignedEnvelope{}, fmt.Errorf("invalid_assignment")
	}
	for i := range assignment.Artifacts {
		if assignment.Artifacts[i].SHA256 == "" {
			assignment.Artifacts[i].SHA256 = domain.SHA256JSON(assignment.Artifacts[i].Envelope)
		}
	}
	if err := domain.ValidateAssignedArtifactDigests(assignment); err != nil {
		return signing.SignedEnvelope{}, fmt.Errorf("invalid_assignment_artifact")
	}
	manifestData, err := json.Marshal(domain.AssignmentManifestFor(assignment))
	if err != nil {
		return signing.SignedEnvelope{}, fmt.Errorf("invalid_assignment_manifest")
	}
	assignment.ManifestDigest = domain.SHA256JSON(manifestData)
	assignment.SignatureValid = false
	assignment.ManifestSignatureValid = false
	payload, err := json.Marshal(assignment)
	if err != nil {
		return signing.SignedEnvelope{}, fmt.Errorf("invalid_assignment_payload")
	}
	envelope, err := s.ManagementSign.Sign(r.Context(), payload, signing.Metadata{
		SourceCommit: assignment.SourceCommit,
		ExpiresAt:    &assignment.ExpiresAt,
	})
	if err != nil {
		return signing.SignedEnvelope{}, fmt.Errorf("assignment_signing_failed")
	}
	if err := s.Management.SaveAssignment(r.Context(), assignment.KLIQID, assignment.AssignmentVersion, envelope); err != nil {
		return signing.SignedEnvelope{}, fmt.Errorf("assignment_store_failed")
	}
	return envelope, nil
}

func (s Server) latestKLIQAssignment(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	kliqID := strings.TrimSpace(r.PathValue("kliq_id"))
	registration, err := s.Management.Registration(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := s.authorizeKLIQAssignmentRead(principal, registration); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	envelope, err := s.Management.LatestAssignment(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "assignment_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "assignment_read_failed")
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

func (s Server) revokeKLIQAssignment(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	kliqID := strings.TrimSpace(r.PathValue("kliq_id"))
	version, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("version")), 10, 64)
	if err != nil || version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_assignment_version")
		return
	}
	registration, err := s.Management.Registration(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.assignment.revoke",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.Management.RevokeAssignment(r.Context(), kliqID, version, decodeRevocationReason(r), time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "assignment_revoke_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "revoked"})
}

func (s Server) revokeKLIQRegistration(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	kliqID := strings.TrimSpace(r.PathValue("kliq_id"))
	registration, err := s.Management.Registration(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.registration.revoke",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.Management.RevokeKLIQ(r.Context(), kliqID, decodeRevocationReason(r), time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "kliq_registration_revoke_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "revoked"})
}

func (s Server) rotateTrustBundle(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.trust_bundle.rotate",
		AllowedRoles: authz.KLIQManageRoles(),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req trustBundleRotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := s.Management.RotateTrustBundle(r.Context(), strings.TrimSpace(r.PathValue("key_id")), req.Next, strings.TrimSpace(req.Reason), time.Now().UTC()); err != nil {
		if errors.Is(err, management.ErrNotFound) {
			writeError(w, http.StatusNotFound, "trust_bundle_not_found")
			return
		}
		writeError(w, http.StatusBadRequest, "trust_bundle_rotate_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "rotated"})
}

func (s Server) revokeTrustBundle(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.trust_bundle.revoke",
		AllowedRoles: authz.KLIQManageRoles(),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.Management.RevokeTrustBundle(r.Context(), strings.TrimSpace(r.PathValue("key_id")), decodeRevocationReason(r), time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "trust_bundle_revoke_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "revoked"})
}

func (s Server) recordKLIQHeartbeat(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	var heartbeat domain.KLIQHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	registration, err := s.Management.Registration(r.Context(), strings.TrimSpace(heartbeat.KLIQID))
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := validateKLIQScope(registration, heartbeat.Environment, heartbeat.Stage, heartbeat.Scope); err != nil {
		writeError(w, http.StatusBadRequest, "heartbeat_scope_mismatch")
		return
	}
	if err := authorizeKLIQServicePrincipal(principal, registration); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if heartbeat.ReportedAt.IsZero() {
		heartbeat.ReportedAt = time.Now().UTC()
	}
	if err := s.Management.SaveHeartbeat(r.Context(), heartbeat); err != nil {
		writeError(w, http.StatusBadRequest, "heartbeat_store_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s Server) recordKLIQStatusReport(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	var report domain.KLIQStatusReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	registration, err := s.Management.Registration(r.Context(), strings.TrimSpace(report.KLIQID))
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := validateKLIQScope(registration, report.Environment, report.Stage, report.Scope); err != nil {
		writeError(w, http.StatusBadRequest, "status_report_scope_mismatch")
		return
	}
	if err := authorizeKLIQServicePrincipal(principal, registration); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if report.ReportedAt.IsZero() {
		report.ReportedAt = time.Now().UTC()
	}
	if err := s.Management.SaveStatusReport(r.Context(), report); err != nil {
		writeError(w, http.StatusBadRequest, "status_report_store_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s Server) recordKLIQAuditUpload(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	var upload domain.KLIQAuditUpload
	if err := json.NewDecoder(r.Body).Decode(&upload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	registration, err := s.Management.Registration(r.Context(), strings.TrimSpace(upload.KLIQID))
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := validateKLIQScope(registration, upload.Environment, upload.Stage, upload.Scope); err != nil {
		writeError(w, http.StatusBadRequest, "audit_scope_mismatch")
		return
	}
	if err := authorizeKLIQServicePrincipal(principal, registration); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if strings.TrimSpace(upload.AuditRecordID) == "" || strings.TrimSpace(upload.PayloadSHA256) == "" {
		writeError(w, http.StatusBadRequest, "invalid_audit_upload")
		return
	}
	if len(upload.Payload) > 0 && domain.SHA256JSON(upload.Payload) != upload.PayloadSHA256 {
		writeError(w, http.StatusBadRequest, "audit_payload_hash_mismatch")
		return
	}
	if upload.UploadedAt.IsZero() {
		upload.UploadedAt = time.Now().UTC()
	}
	ack := domain.KLIQAuditUploadAck{
		Status:        "accepted",
		AuditRecordID: upload.AuditRecordID,
		AckID:         "kliq_audit_ack." + shortAuditHash(upload.KLIQID+"\x00"+upload.AuditRecordID+"\x00"+upload.PayloadSHA256),
		AckedAt:       upload.UploadedAt,
	}
	if err := s.Management.SaveAuditEvent(r.Context(), domain.ManagementAuditEvent{
		EventType:   "kliq_audit_uploaded",
		Actor:       principal.Subject,
		TargetType:  "kliq_audit_event",
		TargetID:    upload.AuditRecordID,
		KLIQID:      upload.KLIQID,
		Environment: upload.Environment,
		Stage:       upload.Stage,
		Scope:       upload.Scope,
		Metadata: map[string]any{
			"runtime_action_id": upload.RuntimeActionID,
			"payload_sha256":    upload.PayloadSHA256,
			"ack_id":            ack.AckID,
		},
		CreatedAt: upload.UploadedAt,
	}); err != nil {
		writeError(w, http.StatusBadRequest, "audit_upload_store_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, ack)
}

func (s Server) getKLIQStatusReport(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_store_not_configured")
		return
	}
	kliqID := strings.TrimSpace(r.PathValue("kliq_id"))
	registration, err := s.Management.Registration(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "kliq_registration_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration_read_failed")
		return
	}
	if err := ensureKLIQRegistrationActive(registration); err != nil {
		writeError(w, http.StatusForbidden, "kliq_registration_revoked")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.status_report.read",
		AllowedRoles: authz.KLIQReadRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	report, err := s.Management.StatusReport(r.Context(), kliqID)
	if errors.Is(err, management.ErrNotFound) {
		writeError(w, http.StatusNotFound, "status_report_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status_report_read_failed")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func validateAssignmentRequest(assignment domain.KLIQAssignment) error {
	switch {
	case strings.TrimSpace(assignment.AssignmentID) == "":
		return errors.New("assignment_id is required")
	case assignment.AssignmentVersion <= 0:
		return errors.New("assignment_version must be positive")
	case strings.TrimSpace(assignment.KLIQID) == "":
		return errors.New("kliq_id is required")
	case strings.TrimSpace(assignment.Environment) == "":
		return errors.New("environment is required")
	case strings.TrimSpace(assignment.Stage) == "":
		return errors.New("stage is required")
	case strings.TrimSpace(assignment.Scope) == "":
		return errors.New("scope is required")
	case strings.TrimSpace(assignment.SourceCommit) == "":
		return errors.New("source_commit is required")
	case strings.TrimSpace(assignment.TrustKeyID) == "":
		return errors.New("trust_key_id is required")
	case strings.TrimSpace(assignment.TrustBundleRef) == "":
		return errors.New("trust_bundle_ref is required")
	case assignment.ExpiresAt.IsZero():
		return errors.New("expires_at is required")
	case len(assignment.Artifacts) == 0:
		return errors.New("at least one artifact is required")
	}
	return nil
}

func validateIdentityMaterial(publicKeyPEM, csrPEM string) error {
	if strings.TrimSpace(publicKeyPEM) != "" {
		block, _ := pem.Decode([]byte(strings.TrimSpace(publicKeyPEM)))
		if block == nil {
			return errors.New("public key PEM is invalid")
		}
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			return nil
		}
		if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return nil
		}
		return errors.New("public key PEM is not a parseable public key")
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(csrPEM)))
	if block == nil {
		return errors.New("csr PEM is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}

func kliqRegistrationScope(registration domain.KLIQRegistration) authn.Scope {
	return authn.Scope{
		Environment: registration.Environment,
		Stage:       registration.Stage,
	}
}

func validateKLIQScope(registration domain.KLIQRegistration, environment, stage, scope string) error {
	if registration.Environment != environment {
		return errors.New("environment mismatch")
	}
	if registration.Stage != stage {
		return errors.New("stage mismatch")
	}
	if registration.Scope != scope {
		return errors.New("scope mismatch")
	}
	return nil
}

func (s Server) authorizeKLIQAssignmentRead(principal authn.Principal, registration domain.KLIQRegistration) error {
	if principal.HasRole(authz.RoleKLIQService) {
		return authorizeKLIQServicePrincipal(principal, registration)
	}
	return s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.assignment.read",
		AllowedRoles: authz.KLIQReadRoles(),
		Scope:        kliqRegistrationScope(registration),
	})
}

func authorizeKLIQServicePrincipal(principal authn.Principal, registration domain.KLIQRegistration) error {
	if !principal.HasRole(authz.RoleKLIQService) {
		return errors.New("kliq service identity required")
	}
	if authn.PrincipalKLIQID(principal) != registration.KLIQID {
		return errors.New("kliq service identity mismatch")
	}
	if principal.Scope.Environment != "" && principal.Scope.Environment != registration.Environment {
		return errors.New("kliq service environment mismatch")
	}
	if principal.Scope.Stage != "" && principal.Scope.Stage != registration.Stage {
		return errors.New("kliq service stage mismatch")
	}
	if authn.PrincipalKLIQScope(principal) != "" && authn.PrincipalKLIQScope(principal) != registration.Scope {
		return errors.New("kliq service scope mismatch")
	}
	if registration.Identity.ServiceIdentityProvider != "" &&
		authn.PrincipalServiceIdentityProvider(principal) != "" &&
		authn.PrincipalServiceIdentityProvider(principal) != registration.Identity.ServiceIdentityProvider {
		return errors.New("kliq service identity provider mismatch")
	}
	if registration.Identity.SPIFFEID != "" &&
		authn.PrincipalSPIFFEID(principal) != "" &&
		authn.PrincipalSPIFFEID(principal) != registration.Identity.SPIFFEID {
		return errors.New("kliq service spiffe id mismatch")
	}
	if expected := authn.IdentityMaterialSHA256(registration.Identity); expected != "" &&
		authn.PrincipalIdentityMaterialSHA256(principal) != "" &&
		authn.PrincipalIdentityMaterialSHA256(principal) != expected {
		return errors.New("kliq service identity material mismatch")
	}
	return nil
}

func ensureKLIQRegistrationActive(registration domain.KLIQRegistration) error {
	if registration.Status == "revoked" || !registration.RevokedAt.IsZero() {
		return errors.New("kliq registration revoked")
	}
	if registration.Identity.Status == "revoked" || !registration.Identity.RevokedAt.IsZero() {
		return errors.New("kliq identity revoked")
	}
	return nil
}

func decodeRevocationReason(r *http.Request) string {
	var req revocationRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Reason) == "" {
		return "unspecified"
	}
	return strings.TrimSpace(req.Reason)
}

func defaultManagementProfile(kliqID string) domain.KLIQManagementProfile {
	return domain.KLIQManagementProfile{
		ProfileID:          "kliq_management_profile." + kliqID,
		Mode:               "managed_pull",
		PollInterval:       "1m",
		HeartbeatInterval:  "30s",
		StatusInterval:     "1m",
		DecisionInterval:   "5s",
		ReconcileInterval:  "30s",
		AuditFlushInterval: "1m",
		AssignmentSource:   "forge_assignment_api",
	}
}

func shortAuditHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
