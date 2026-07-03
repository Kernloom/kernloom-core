// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
	"github.com/kernloom/kernloom-core/internal/forge/management"
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

func TestKLIQEnrollmentAssignmentHeartbeatAndStatusFlow(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	serviceIssuer := &authn.KLIQServiceTokenIssuer{Secret: []byte("test-kliq-service-secret")}
	server := Server{
		Authenticator:  authn.Chain{authn.DevTokenVerifier{}, serviceIssuer},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: signer,
		KLIQService:    serviceIssuer,
	}
	handler := server.Handler()
	operatorToken := "Bearer dev:ops:operator:acme:prod:prod"

	tokenResp := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/enrollment-tokens", bytes.NewBufferString(`{"environment":"prod","stage":"prod","scope":"edge-prod"}`))
	tokenReq.Header.Set("Authorization", operatorToken)
	handler.ServeHTTP(tokenResp, tokenReq)
	if tokenResp.Code != http.StatusCreated {
		t.Fatalf("expected token created, got %d: %s", tokenResp.Code, tokenResp.Body.String())
	}
	var token enrollmentTokenResponse
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.SecretToken == "" || token.Token.TokenSHA256 == "" {
		t.Fatalf("expected secret and redacted token metadata, got %#v", token)
	}

	enrollResp := httptest.NewRecorder()
	enrollBody := `{"enrollment_token":"` + token.SecretToken + `","node_id":"node-1","environment":"prod","stage":"prod","scope":"edge-prod","version":"test","trust_key_id":"forge-management-dev-local","public_key_pem":"-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----","adapter_inventory":["kernloom.adapter.klshield"],"capabilities":["klshield.runtime.source_mitigation"]}`
	handler.ServeHTTP(enrollResp, httptest.NewRequest(http.MethodPost, "/v1/kliq/enroll", bytes.NewBufferString(enrollBody)))
	if enrollResp.Code != http.StatusCreated {
		t.Fatalf("expected enrollment created, got %d: %s", enrollResp.Code, enrollResp.Body.String())
	}
	var enrollment enrollmentResponse
	if err := json.Unmarshal(enrollResp.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	registration := enrollment.Registration
	if registration.KLIQID == "" || registration.Identity.TrustKeyID != "forge-management-dev-local" {
		t.Fatalf("unexpected registration %#v", registration)
	}
	if enrollment.ServiceToken == "" || registration.Identity.PublicKeyPEM == "" {
		t.Fatalf("expected service token and bound public key, got %#v", enrollment)
	}

	artifactEnvelope := json.RawMessage(`{"kind":"SignedEnvelope","payload":"runtime"}`)
	plan := assignmentPlanRequest{
		KLIQID:       registration.KLIQID,
		SourceCommit: "abc123",
		ExpiresAt:    time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.test",
			Envelope:     artifactEnvelope,
		}},
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	assignResp := httptest.NewRecorder()
	assignReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(body))
	assignReq.Header.Set("Authorization", operatorToken)
	handler.ServeHTTP(assignResp, assignReq)
	if assignResp.Code != http.StatusCreated {
		t.Fatalf("expected assignment created, got %d: %s", assignResp.Code, assignResp.Body.String())
	}
	var envelope signing.SignedEnvelope
	if err := json.Unmarshal(assignResp.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "forge-management-dev-local" || len(envelope.Signature) == 0 {
		t.Fatalf("expected signed assignment envelope, got %#v", envelope)
	}

	latestResp := httptest.NewRecorder()
	latestReq := httptest.NewRequest(http.MethodGet, "/v1/kliq/assignments/"+registration.KLIQID+"/latest", nil)
	latestReq.Header.Set("Authorization", "Bearer "+enrollment.ServiceToken)
	handler.ServeHTTP(latestResp, latestReq)
	if latestResp.Code != http.StatusOK {
		t.Fatalf("expected latest assignment, got %d: %s", latestResp.Code, latestResp.Body.String())
	}

	heartbeatResp := httptest.NewRecorder()
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/heartbeat", bytes.NewBufferString(`{"kliq_id":"`+registration.KLIQID+`","environment":"prod","stage":"prod","scope":"edge-prod","assignment_version":1,"status":"ok"}`))
	heartbeatReq.Header.Set("Authorization", "Bearer "+enrollment.ServiceToken)
	handler.ServeHTTP(heartbeatResp, heartbeatReq)
	if heartbeatResp.Code != http.StatusAccepted {
		t.Fatalf("expected heartbeat accepted, got %d: %s", heartbeatResp.Code, heartbeatResp.Body.String())
	}

	statusResp := httptest.NewRecorder()
	statusReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/status-reports", bytes.NewBufferString(`{"kliq_id":"`+registration.KLIQID+`","environment":"prod","stage":"prod","scope":"edge-prod","assignment_version":1,"status":"ok","runtime_actions":1,"pending_audits":0}`))
	statusReq.Header.Set("Authorization", "Bearer "+enrollment.ServiceToken)
	handler.ServeHTTP(statusResp, statusReq)
	if statusResp.Code != http.StatusAccepted {
		t.Fatalf("expected status report accepted, got %d: %s", statusResp.Code, statusResp.Body.String())
	}

	statusReadResp := httptest.NewRecorder()
	statusReadReq := httptest.NewRequest(http.MethodGet, "/v1/kliq/status-reports/"+registration.KLIQID, nil)
	statusReadReq.Header.Set("Authorization", operatorToken)
	handler.ServeHTTP(statusReadResp, statusReadReq)
	if statusReadResp.Code != http.StatusOK {
		t.Fatalf("expected status report read, got %d: %s", statusReadResp.Code, statusReadResp.Body.String())
	}
}

func TestLatestAssignmentReadEnforcesRegisteredScope(t *testing.T) {
	store := management.NewMemoryStore()
	registration := domain.KLIQRegistration{
		KLIQID:      "kliq.scope-test",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
	}
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(t.Context(), registration.KLIQID, 1, signing.SignedEnvelope{PayloadSHA256: "sha256:assignment"}); err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: testManagementSigner(t),
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/kliq/assignments/"+registration.KLIQID+"/latest", nil)
	req.Header.Set("Authorization", "Bearer dev:viewer:read-only-viewer:acme:dev:dev")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for scope mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKLIQServiceCannotFetchAnotherKLIQAssignment(t *testing.T) {
	store := management.NewMemoryStore()
	first := testRegistration("kliq.first", "node-1")
	second := testRegistration("kliq.second", "node-2")
	if err := store.Register(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(t.Context(), second.KLIQID, 1, signing.SignedEnvelope{PayloadSHA256: "sha256:assignment"}); err != nil {
		t.Fatal(err)
	}
	issuer := &authn.KLIQServiceTokenIssuer{Secret: []byte("test-kliq-service-secret")}
	token, err := issuer.Issue(first.KLIQID, first.Environment, first.Stage, first.Scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator:  authn.Chain{authn.DevTokenVerifier{}, issuer},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: testManagementSigner(t),
		KLIQService:    issuer,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/kliq/assignments/"+second.KLIQID+"/latest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for cross-KLIQ assignment pull, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokedKLIQCannotFetchAssignment(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.revoked", "node-revoked")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(t.Context(), registration.KLIQID, 1, signing.SignedEnvelope{PayloadSHA256: "sha256:assignment"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeKLIQ(t.Context(), registration.KLIQID, "test revocation", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	issuer := &authn.KLIQServiceTokenIssuer{Secret: []byte("test-kliq-service-secret")}
	token, err := issuer.Issue(registration.KLIQID, registration.Environment, registration.Stage, registration.Scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator:  authn.Chain{issuer},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: testManagementSigner(t),
		KLIQService:    issuer,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/kliq/assignments/"+registration.KLIQID+"/latest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for revoked KLIQ, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHeartbeatAndStatusMustMatchRegistrationScope(t *testing.T) {
	store := management.NewMemoryStore()
	registration := domain.KLIQRegistration{
		KLIQID:      "kliq.scope-test",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
	}
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: testManagementSigner(t),
	}
	handler := server.Handler()
	operatorToken := "Bearer dev:ops:operator:acme:prod:prod"

	heartbeatResp := httptest.NewRecorder()
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/heartbeat", bytes.NewBufferString(`{"kliq_id":"`+registration.KLIQID+`","environment":"prod","stage":"dev","scope":"edge-prod","assignment_version":1,"status":"ok"}`))
	heartbeatReq.Header.Set("Authorization", operatorToken)
	handler.ServeHTTP(heartbeatResp, heartbeatReq)
	if heartbeatResp.Code != http.StatusBadRequest {
		t.Fatalf("expected heartbeat scope mismatch rejection, got %d: %s", heartbeatResp.Code, heartbeatResp.Body.String())
	}

	statusResp := httptest.NewRecorder()
	statusReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/status-reports", bytes.NewBufferString(`{"kliq_id":"`+registration.KLIQID+`","environment":"prod","stage":"prod","scope":"other","assignment_version":1,"status":"ok"}`))
	statusReq.Header.Set("Authorization", operatorToken)
	handler.ServeHTTP(statusResp, statusReq)
	if statusResp.Code != http.StatusBadRequest {
		t.Fatalf("expected status scope mismatch rejection, got %d: %s", statusResp.Code, statusResp.Body.String())
	}
}

func testRegistration(kliqID, nodeID string) domain.KLIQRegistration {
	return domain.KLIQRegistration{
		RegistrationID: "registration." + kliqID,
		KLIQID:         kliqID,
		NodeID:         nodeID,
		Environment:    "prod",
		Stage:          "prod",
		Scope:          "edge-prod",
		Status:         "active",
		RegisteredAt:   time.Now().UTC(),
		Identity: domain.KLIQIdentity{
			IdentityID:   "identity." + kliqID,
			KLIQID:       kliqID,
			NodeID:       nodeID,
			Environment:  "prod",
			Stage:        "prod",
			Scope:        "edge-prod",
			TrustKeyID:   "forge-management-dev-local",
			PublicKeyPEM: "public-key",
			Status:       "active",
			IssuedAt:     time.Now().UTC(),
		},
	}
}

func testManagementSigner(t *testing.T) *signing.DevLocalSigner {
	t.Helper()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
