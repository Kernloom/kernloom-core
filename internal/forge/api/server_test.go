// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
)

func TestCreateSimulationJobRequiresAuth(t *testing.T) {
	server := Server{
		Authenticator: authn.DevTokenVerifier{},
		Authorizer:    authz.Authorizer{},
		Store:         jobs.NewMemoryStore(),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/simulation-jobs", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rec.Code)
	}
}

func TestCreateSimulationJobEnqueuesAuthorizedRequest(t *testing.T) {
	store := jobs.NewMemoryStore()
	server := Server{
		Authenticator: authn.DevTokenVerifier{},
		Authorizer:    authz.Authorizer{},
		Store:         store,
	}
	body := bytes.NewBufferString(`{"policy_file":"policies/access/example.intent.kni","scope":{"org":"acme","stage":"prod"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/simulation-jobs", body)
	req.Header.Set("Authorization", "Bearer dev:alice:policy-author:acme:dev:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected accepted, got %d: %s", rec.Code, rec.Body.String())
	}
	var job jobs.Job
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.Status != jobs.StatusPending || job.CreatedBy != "alice" {
		t.Fatalf("unexpected job %#v", job)
	}
	if _, err := store.Dequeue(req.Context()); err != nil {
		t.Fatalf("expected queued job: %v", err)
	}
}

func TestCreateSimulationJobRejectsUnauthorizedRole(t *testing.T) {
	server := Server{
		Authenticator: authn.DevTokenVerifier{},
		Authorizer:    authz.Authorizer{},
		Store:         jobs.NewMemoryStore(),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/simulation-jobs", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer dev:viewer:read-only-viewer:acme:dev:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rec.Code)
	}
}
