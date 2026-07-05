// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
	"github.com/kernloom/kernloom-core/internal/forge/management"
	"github.com/kernloom/kernloom-core/internal/storage/artifactstore"
)

type Server struct {
	Authenticator  authn.Verifier
	Authorizer     authz.Authorizer
	Store          jobs.Store
	Management     management.Store
	ManagementSign signing.Signer
	Artifacts      artifactstore.ArtifactStore
	KLIQService    *authn.KLIQServiceTokenIssuer
	DevManagement  bool
}

type SimulationJobRequest struct {
	PolicyRepo         string      `json:"policy_repo,omitempty"`
	PolicyFile         string      `json:"policy_file,omitempty"`
	CoreRegistry       string      `json:"core_registry,omitempty"`
	EnterpriseRegistry string      `json:"enterprise_registry,omitempty"`
	OutputDir          string      `json:"output_dir,omitempty"`
	Scope              authn.Scope `json:"scope,omitempty"`
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /v1/me", s.requireAuth(s.me))
	mux.HandleFunc("POST /v1/simulation-jobs", s.requireAuth(s.createSimulationJob))
	mux.HandleFunc("GET /v1/jobs/{id}", s.requireAuth(s.getJob))
	mux.HandleFunc("POST /v1/policy-build-manifests/approve", s.requireAuth(s.approvePolicyBuildManifest))
	mux.HandleFunc("POST /v1/kliq/enrollment-tokens", s.requireAuth(s.createEnrollmentToken))
	mux.HandleFunc("POST /v1/kliq/enrollment-tokens/{token_id}/revoke", s.requireAuth(s.revokeEnrollmentToken))
	mux.HandleFunc("POST /v1/kliq/enroll", s.enrollKLIQ)
	mux.HandleFunc("POST /v1/kliq/assignments", s.requireAuth(s.planKLIQAssignment))
	mux.HandleFunc("POST /v1/kliq/dev/assignments", s.requireAuth(s.createDevKLIQAssignment))
	mux.HandleFunc("GET /v1/kliq/assignments/{kliq_id}/latest", s.requireAuth(s.latestKLIQAssignment))
	mux.HandleFunc("POST /v1/kliq/assignments/{kliq_id}/{version}/revoke", s.requireAuth(s.revokeKLIQAssignment))
	mux.HandleFunc("POST /v1/kliq/registrations/{kliq_id}/revoke", s.requireAuth(s.revokeKLIQRegistration))
	mux.HandleFunc("POST /v1/kliq/trust-bundles/{key_id}/revoke", s.requireAuth(s.revokeTrustBundle))
	mux.HandleFunc("POST /v1/kliq/heartbeat", s.requireAuth(s.recordKLIQHeartbeat))
	mux.HandleFunc("POST /v1/kliq/status-reports", s.requireAuth(s.recordKLIQStatusReport))
	mux.HandleFunc("GET /v1/kliq/status-reports/{kliq_id}", s.requireAuth(s.getKLIQStatusReport))
	mux.HandleFunc("POST /v1/kliq/audit-events", s.requireAuth(s.recordKLIQAuditUpload))
	mux.HandleFunc("POST /v1/kliq/service-token/refresh", s.requireAuth(s.refreshKLIQServiceToken))
	return mux
}

func (s Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s Server) requireAuth(next func(http.ResponseWriter, *http.Request, authn.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Authenticator == nil {
			writeError(w, http.StatusInternalServerError, "authenticator_not_configured")
			return
		}
		if requestVerifier, ok := s.Authenticator.(authn.RequestVerifier); ok {
			principal, err := requestVerifier.VerifyRequest(r.Context(), r)
			if err == nil {
				ctx := authn.WithPrincipal(r.Context(), principal)
				ctx = management.WithAuditActor(ctx, principal.Subject)
				next(w, r.WithContext(ctx), principal)
				return
			}
		}
		token, err := authn.BearerToken(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing_bearer_token")
			return
		}
		principal, err := s.Authenticator.Verify(r.Context(), token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		ctx := authn.WithPrincipal(r.Context(), principal)
		ctx = management.WithAuditActor(ctx, principal.Subject)
		next(w, r.WithContext(ctx), principal)
	}
}

func (s Server) me(w http.ResponseWriter, _ *http.Request, principal authn.Principal) {
	writeJSON(w, http.StatusOK, principal)
}

func (s Server) createSimulationJob(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if s.Store == nil {
		writeError(w, http.StatusInternalServerError, "job_store_not_configured")
		return
	}
	var req SimulationJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "simulation.submit",
		AllowedRoles: authz.SimulationSubmitRoles(),
		Scope:        req.Scope,
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	job, err := jobs.NewJob(jobs.TypeSimulation, principal.Subject, jobs.SimulationPayload{
		PolicyRepo:         req.PolicyRepo,
		PolicyFile:         req.PolicyFile,
		CoreRegistry:       req.CoreRegistry,
		EnterpriseRegistry: req.EnterpriseRegistry,
		OutputDir:          req.OutputDir,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_job_payload")
		return
	}
	if err := s.Store.Create(r.Context(), job); err != nil {
		writeError(w, http.StatusInternalServerError, "job_create_failed")
		return
	}
	if err := s.Store.Enqueue(r.Context(), job.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "job_enqueue_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s Server) getJob(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "job.read",
		AllowedRoles: authz.JobReadRoles(),
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing_job_id")
		return
	}
	job, err := s.Store.Get(r.Context(), id)
	if errors.Is(err, jobs.ErrNotFound) {
		writeError(w, http.StatusNotFound, "job_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "job_read_failed")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
