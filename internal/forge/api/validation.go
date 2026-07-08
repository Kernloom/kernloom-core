// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	"github.com/kernloom/kernloom-core/internal/forge/validation"
)

type ciValidationRequest struct {
	PolicyRepo         string                          `json:"policy_repo,omitempty"`
	CoreRegistry       string                          `json:"core_registry,omitempty"`
	EnterpriseRegistry string                          `json:"enterprise_registry,omitempty"`
	Tenant             string                          `json:"tenant"`
	Environment        string                          `json:"environment"`
	Provider           string                          `json:"provider,omitempty"`
	Repository         string                          `json:"repository"`
	Commit             string                          `json:"commit,omitempty"`
	PullRequest        string                          `json:"pull_request,omitempty"`
	BasePath           string                          `json:"base_path,omitempty"`
	TargetID           string                          `json:"target_id,omitempty"`
	ChangedPaths       []string                        `json:"changed_paths,omitempty"`
	ConfigSnapshot     string                          `json:"config_snapshot,omitempty"`
	OutputDir          string                          `json:"output_dir,omitempty"`
	AdapterVerify      validation.AdapterVerifyOptions `json:"adapter_verify,omitempty"`
	Scope              authn.Scope                     `json:"scope,omitempty"`
}

func (s Server) validateCI(w http.ResponseWriter, r *http.Request, principal authn.Principal) {
	var req ciValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	scope := req.Scope
	if scope.Org == "" {
		scope.Org = req.Tenant
	}
	if scope.Environment == "" {
		scope.Environment = req.Environment
	}
	if scope.Repo == "" {
		scope.Repo = req.Repository
	}
	if err := s.Authorizer.Authorize(principal, authz.Request{
		Action:       "validation.ci",
		AllowedRoles: authz.ValidationSubmitRoles(),
		Scope:        scope,
	}); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	opts := s.Validation
	if strings.TrimSpace(req.PolicyRepo) != "" {
		opts.PolicyRepo = req.PolicyRepo
	}
	if strings.TrimSpace(req.CoreRegistry) != "" {
		opts.CoreRegistry = req.CoreRegistry
	}
	if strings.TrimSpace(req.EnterpriseRegistry) != "" {
		opts.EnterpriseRegistry = req.EnterpriseRegistry
	}
	opts.Tenant = req.Tenant
	opts.Environment = req.Environment
	opts.Provider = req.Provider
	opts.Repository = req.Repository
	opts.Commit = req.Commit
	opts.PullRequest = req.PullRequest
	opts.BasePath = req.BasePath
	opts.TargetID = req.TargetID
	opts.ChangedPaths = append([]string(nil), req.ChangedPaths...)
	opts.ConfigSnapshot = req.ConfigSnapshot
	opts.OutputDir = req.OutputDir
	opts.AdapterVerify = req.AdapterVerify
	result := validation.ValidateCI(opts)
	status := http.StatusOK
	if result.Status != "passed" {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, result)
}
