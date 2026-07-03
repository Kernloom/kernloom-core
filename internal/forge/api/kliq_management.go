// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
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
	now := time.Now().UTC()
	if _, err := s.Management.UseEnrollmentToken(r.Context(), req.EnrollmentToken, req.Environment, req.Stage, req.Scope, now); err != nil {
		writeError(w, http.StatusForbidden, "invalid_enrollment_token")
		return
	}
	trustKeyID := strings.TrimSpace(req.TrustKeyID)
	if trustKeyID == "" {
		trustKeyID = "dev-local"
	}
	kliqID := management.StableKLIQID(req.NodeID, req.Environment, req.Stage, req.Scope)
	identity := domain.KLIQIdentity{
		KLIQID:      kliqID,
		NodeID:      req.NodeID,
		Environment: req.Environment,
		Stage:       req.Stage,
		Scope:       req.Scope,
		TrustKeyID:  trustKeyID,
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
		RegisteredAt:      now,
	}
	if err := s.Management.Register(r.Context(), registration); err != nil {
		writeError(w, http.StatusInternalServerError, "registration_failed")
		return
	}
	writeJSON(w, http.StatusCreated, registration)
}

func (s Server) createKLIQAssignment(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Management == nil || s.ManagementSign == nil {
		writeError(w, http.StatusInternalServerError, "kliq_management_not_configured")
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
		Action:       "kliq.assignment.create",
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
	if err := validateAssignmentRequest(assignment); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_assignment")
		return
	}
	for i := range assignment.Artifacts {
		if assignment.Artifacts[i].SHA256 == "" {
			assignment.Artifacts[i].SHA256 = domain.SHA256JSON(assignment.Artifacts[i].Envelope)
		}
	}
	if err := domain.ValidateAssignedArtifactDigests(assignment); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_assignment_artifact")
		return
	}
	assignment.SignatureValid = false
	assignment.ManifestSignatureValid = false
	payload, err := json.Marshal(assignment)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_assignment_payload")
		return
	}
	envelope, err := s.ManagementSign.Sign(r.Context(), payload, signing.Metadata{
		SourceCommit: assignment.SourceCommit,
		ExpiresAt:    &assignment.ExpiresAt,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "assignment_signing_failed")
		return
	}
	if err := s.Management.SaveAssignment(r.Context(), assignment.KLIQID, assignment.AssignmentVersion, envelope); err != nil {
		writeError(w, http.StatusBadRequest, "assignment_store_failed")
		return
	}
	writeJSON(w, http.StatusCreated, envelope)
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
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.assignment.read",
		AllowedRoles: authz.KLIQReadRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
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
	if err := validateKLIQScope(registration, heartbeat.Environment, heartbeat.Stage, heartbeat.Scope); err != nil {
		writeError(w, http.StatusBadRequest, "heartbeat_scope_mismatch")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.heartbeat.write",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
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
	if err := validateKLIQScope(registration, report.Environment, report.Stage, report.Scope); err != nil {
		writeError(w, http.StatusBadRequest, "status_report_scope_mismatch")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "kliq.status_report.write",
		AllowedRoles: authz.KLIQManageRoles(),
		Scope:        kliqRegistrationScope(registration),
	}); err != nil {
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
	case assignment.ExpiresAt.IsZero():
		return errors.New("expires_at is required")
	case len(assignment.Artifacts) == 0:
		return errors.New("at least one artifact is required")
	}
	return nil
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

func defaultManagementProfile(kliqID string) domain.KLIQManagementProfile {
	return domain.KLIQManagementProfile{
		ProfileID:        "kliq_management_profile." + kliqID,
		Mode:             "managed_pull",
		PollInterval:     "1m",
		AssignmentSource: "forge_assignment_api",
	}
}
