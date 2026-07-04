// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/api/authz"
	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
	"github.com/kernloom/kernloom-core/internal/forge/management"
	"github.com/kernloom/kernloom-core/internal/storage/artifactstore"
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
	artifacts := artifactstore.NewMemoryStore()
	server := Server{
		Authenticator:  authn.Chain{authn.DevTokenVerifier{}, serviceIssuer},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: signer,
		Artifacts:      artifacts,
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
	enrollBody := `{"enrollment_token":"` + token.SecretToken + `","node_id":"node-1","environment":"prod","stage":"prod","scope":"edge-prod","version":"test","trust_key_id":"forge-management-dev-local","public_key_pem":` + quoteJSON(validPublicKeyPEM(t)) + `,"adapter_inventory":["kernloom.adapter.klshield"],"capabilities":["klshield.runtime.source_mitigation"]}`
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
	if registration.Identity.ServiceIdentityProvider != authn.ServiceIdentityProviderSPIFFEReady || registration.Identity.SPIFFEID == "" || registration.Identity.CredentialStatus != "active" {
		t.Fatalf("expected spiffe-ready service identity metadata, got %#v", registration.Identity)
	}
	principal, err := serviceIssuer.Verify(t.Context(), enrollment.ServiceToken)
	if err != nil {
		t.Fatal(err)
	}
	if authn.PrincipalSPIFFEID(principal) != registration.Identity.SPIFFEID || authn.PrincipalServiceIdentityProvider(principal) != registration.Identity.ServiceIdentityProvider {
		t.Fatalf("expected service token claims to bind registered identity, got %#v", principal)
	}
	if authn.PrincipalIdentityMaterialSHA256(principal) != authn.IdentityMaterialSHA256(registration.Identity) {
		t.Fatalf("expected service token identity material hash to bind registered public key, got %#v", principal)
	}

	runtimeEnvelope, err := signer.Sign(t.Context(), []byte(`{"kind":"RuntimeBundle","metadata":{"policy_id":"policy.test"}}`), signing.Metadata{
		SourceCommit: "abc123",
		PolicyID:     "policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimePayload, err := json.Marshal(runtimeEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := artifacts.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{
			ID:           "runtime_bundle.test",
			PolicyID:     "policy.test",
			ArtifactType: "runtime_bundle_signed_envelope",
			SourceCommit: "abc123",
		},
		Payload: runtimePayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	approvedBuildRef := putApprovedBuildManifest(t, artifacts, signer, "abc123", registration.Environment, registration.Stage, registration.Scope, map[string]coreartifact.Ref{
		"runtime_bundle": ref,
	})
	plan := assignmentPlanRequest{
		KLIQID:           registration.KLIQID,
		SourceCommit:     "abc123",
		ApprovedBuildRef: approvedBuildRef,
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.test",
			ArtifactRef:  ref.URI,
			SHA256:       ref.SHA256,
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

	events, err := store.AuditEvents(t.Context(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	tokenCreated := requireAuditEvent(t, events, "enrollment_token_created")
	if tokenCreated.Actor != "ops" || tokenCreated.TargetID != token.Token.TokenID {
		t.Fatalf("expected enrollment token creation actor and target, got %#v", tokenCreated)
	}
	enrolled := requireAuditEvent(t, events, "kliq_enrolled")
	if enrolled.KLIQID != registration.KLIQID || enrolled.Metadata["enrollment_token_id"] != token.Token.TokenID || enrolled.Metadata["kliq_id"] != registration.KLIQID {
		t.Fatalf("expected enrollment audit metadata to bind token and kliq id, got %#v", enrolled)
	}
	planned := requireAuditEvent(t, events, "assignment_planned")
	if planned.Actor != "ops" || planned.KLIQID != registration.KLIQID {
		t.Fatalf("expected assignment planning actor and target KLIQ, got %#v", planned)
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

func TestProductionAssignmentPlannerRejectsRawArtifactEnvelope(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.raw-envelope", "node-raw")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	artifacts := artifactstore.NewMemoryStore()
	approvedBuildRef := putApprovedBuildManifest(t, artifacts, testManagementSigner(t), "abc123", registration.Environment, registration.Stage, registration.Scope, nil)
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: testManagementSigner(t),
		Artifacts:      artifacts,
	}
	plan := assignmentPlanRequest{
		KLIQID:           registration.KLIQID,
		SourceCommit:     "abc123",
		ApprovedBuildRef: approvedBuildRef,
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.raw",
			Envelope:     json.RawMessage(`{"kind":"SignedEnvelope"}`),
		}},
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected raw envelope assignment rejection, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProductionAssignmentPlannerRequiresApprovedBuild(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.approved-build", "node-approved-build")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: testManagementSigner(t),
		Artifacts:      artifactstore.NewMemoryStore(),
	}
	plan := assignmentPlanRequest{
		KLIQID:       registration.KLIQID,
		SourceCommit: "abc123",
		ExpiresAt:    time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.test",
			ArtifactRef:  "memory://runtime_bundle/test.json",
			SHA256:       "sha256:test",
		}},
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "approved_build_required") {
		t.Fatalf("expected approved build requirement, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApprovePolicyBuildManifestMakesPlannerReachable(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.approve-build", "node-approve-build")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	signer := testManagementSigner(t)
	artifacts := artifactstore.NewMemoryStore()
	runtimeEnvelope, err := signer.Sign(t.Context(), []byte(`{"kind":"RuntimeBundle","metadata":{"policy_id":"policy.test"}}`), signing.Metadata{
		SourceCommit: "abc123",
		PolicyID:     "policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimePayload, err := json.Marshal(runtimeEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRef, err := artifacts.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{ID: "runtime_bundle.approve-build", PolicyID: "policy.test", ArtifactType: "runtime_bundle_signed_envelope", SourceCommit: "abc123"},
		Payload:  runtimePayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	pendingBuildRef := putPendingBuildManifest(t, artifacts, signer, "abc123", map[string]coreartifact.Ref{
		"runtime_bundle": runtimeRef,
	})
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: signer,
		Artifacts:      artifacts,
	}
	approvalReq := buildApprovalRequest{
		BuildRef:    pendingBuildRef,
		Environment: registration.Environment,
		Stage:       registration.Stage,
		Scope:       registration.Scope,
		AuthorityID: "change.review.123",
	}
	approvalBody, err := json.Marshal(approvalReq)
	if err != nil {
		t.Fatal(err)
	}
	approvalResp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/policy-build-manifests/approve", bytes.NewReader(approvalBody))
	req.Header.Set("Authorization", "Bearer dev:reviewer:policy-reviewer:acme:prod:prod")
	server.Handler().ServeHTTP(approvalResp, req)
	if approvalResp.Code != http.StatusCreated {
		t.Fatalf("expected build approval, got %d: %s", approvalResp.Code, approvalResp.Body.String())
	}
	var approved buildApprovalResponse
	if err := json.Unmarshal(approvalResp.Body.Bytes(), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.ApprovedBuildRef.URI == "" || approved.Manifest.Approval.Status != "approved" || approved.Manifest.Approval.ApprovedBy != "reviewer" {
		t.Fatalf("expected approved manifest response, got %#v", approved)
	}

	plan := assignmentPlanRequest{
		KLIQID:           registration.KLIQID,
		SourceCommit:     "abc123",
		ApprovedBuildRef: approved.ApprovedBuildRef,
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.approve-build",
			ArtifactRef:  runtimeRef.URI,
			SHA256:       runtimeRef.SHA256,
		}},
	}
	planBody, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planResp := httptest.NewRecorder()
	planReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(planBody))
	planReq.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	server.Handler().ServeHTTP(planResp, planReq)
	if planResp.Code != http.StatusCreated {
		t.Fatalf("expected assignment planner to accept approved build, got %d: %s", planResp.Code, planResp.Body.String())
	}
	events, err := store.AuditEvents(t.Context(), "policy_build_manifest", approved.Manifest.Metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	event := requireAuditEvent(t, events, "policy_build_manifest_approved")
	if event.Actor != "reviewer" || event.Metadata["authority_id"] != "change.review.123" {
		t.Fatalf("expected approval audit event, got %#v", event)
	}
}

func TestProductionAssignmentPlannerRejectsArtifactOutsideApprovedBuild(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.artifact-outside-build", "node-artifact-outside-build")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	signer := testManagementSigner(t)
	artifacts := artifactstore.NewMemoryStore()
	envelope, err := signer.Sign(t.Context(), []byte(`{"kind":"RuntimeBundle","metadata":{"policy_id":"policy.test"}}`), signing.Metadata{
		SourceCommit: "abc123",
		PolicyID:     "policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := artifacts.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{ID: "runtime_bundle.outside", PolicyID: "policy.test", ArtifactType: "runtime_bundle_signed_envelope", SourceCommit: "abc123"},
		Payload:  payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	approvedBuildRef := putApprovedBuildManifest(t, artifacts, signer, "abc123", registration.Environment, registration.Stage, registration.Scope, map[string]coreartifact.Ref{})
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: signer,
		Artifacts:      artifacts,
	}
	plan := assignmentPlanRequest{
		KLIQID:           registration.KLIQID,
		SourceCommit:     "abc123",
		ApprovedBuildRef: approvedBuildRef,
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.outside",
			ArtifactRef:  ref.URI,
			SHA256:       ref.SHA256,
		}},
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "artifact_not_in_approved_build") {
		t.Fatalf("expected approved build artifact rejection, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProductionAssignmentPlannerRejectsUnsignedApprovedBuildManifest(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.unsigned-build", "node-unsigned-build")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	signer := testManagementSigner(t)
	artifacts := artifactstore.NewMemoryStore()
	envelope, err := signer.Sign(t.Context(), []byte(`{"kind":"RuntimeBundle","metadata":{"policy_id":"policy.test"}}`), signing.Metadata{
		SourceCommit: "abc123",
		PolicyID:     "policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := artifacts.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{ID: "runtime_bundle.unsigned-build", PolicyID: "policy.test", ArtifactType: "runtime_bundle_signed_envelope", SourceCommit: "abc123"},
		Payload:  payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := compiler.PolicyBuildManifest{
		Kind:     "PolicyBuildManifest",
		Metadata: compiler.ManifestMetadata{ID: "build.unsigned", CorrelationID: "correlation.test"},
		Approval: compiler.ManifestApproval{
			Status:        "approved",
			ApprovedBy:    "test",
			ApprovedAt:    time.Now().UTC(),
			AuthorityID:   "approval-authority.test",
			AuthorityKind: "forge-management-signature",
			Environment:   registration.Environment,
			Stage:         registration.Stage,
			Scope:         registration.Scope,
		},
		Spec: compiler.ManifestSpec{
			PolicyRepo:         compiler.PolicyRepoRef{Commit: "abc123"},
			EnterpriseRegistry: compiler.RegistryRef{ContentDigest: "sha256:enterprise-registry"},
			CoreRegistry:       compiler.RegistryRef{ContentDigest: "sha256:core-registry"},
			Profile:            compiler.DigestRef{Digest: "sha256:profile"},
			RiskRecipe:         compiler.DigestRef{Digest: "sha256:risk"},
			CatalogDigest:      "sha256:catalog",
			SignedOutputs: map[string]compiler.SignedOutputRef{
				"runtime_bundle": {ArtifactRef: ref, EnvelopeSHA256: ref.SHA256, PayloadSHA256: "sha256:payload-runtime_bundle", KeyID: signer.KeyID},
			},
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	approvedBuildRef, err := artifacts.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{ID: manifest.Metadata.ID, PolicyID: "policy.test", ArtifactType: "policy_build_manifest", SourceCommit: "abc123"},
		Payload:  manifestPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: signer,
		Artifacts:      artifacts,
	}
	plan := assignmentPlanRequest{
		KLIQID:           registration.KLIQID,
		SourceCommit:     "abc123",
		ApprovedBuildRef: approvedBuildRef,
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.unsigned-build",
			ArtifactRef:  ref.URI,
			SHA256:       ref.SHA256,
		}},
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "approved_build_must_be_signed") {
		t.Fatalf("expected unsigned approved build rejection, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProductionAssignmentPlannerRejectsApprovedBuildScopeMismatch(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.scope-build", "node-scope-build")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	signer := testManagementSigner(t)
	artifacts := artifactstore.NewMemoryStore()
	envelope, err := signer.Sign(t.Context(), []byte(`{"kind":"RuntimeBundle","metadata":{"policy_id":"policy.test"}}`), signing.Metadata{
		SourceCommit: "abc123",
		PolicyID:     "policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := artifacts.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{ID: "runtime_bundle.scope-build", PolicyID: "policy.test", ArtifactType: "runtime_bundle_signed_envelope", SourceCommit: "abc123"},
		Payload:  payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	approvedBuildRef := putApprovedBuildManifest(t, artifacts, signer, "abc123", registration.Environment, registration.Stage, "other-scope", map[string]coreartifact.Ref{
		"runtime_bundle": ref,
	})
	server := Server{
		Authenticator:  authn.DevTokenVerifier{},
		Authorizer:     authz.Authorizer{},
		Store:          jobs.NewMemoryStore(),
		Management:     store,
		ManagementSign: signer,
		Artifacts:      artifacts,
	}
	plan := assignmentPlanRequest{
		KLIQID:           registration.KLIQID,
		SourceCommit:     "abc123",
		ApprovedBuildRef: approvedBuildRef,
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.scope-build",
			ArtifactRef:  ref.URI,
			SHA256:       ref.SHA256,
		}},
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/assignments", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "approved_build_scope_mismatch") {
		t.Fatalf("expected approved build scope mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestInvalidEnrollmentIdentityMaterialDoesNotConsumeToken(t *testing.T) {
	store := management.NewMemoryStore()
	server := Server{
		Authenticator: authn.DevTokenVerifier{},
		Authorizer:    authz.Authorizer{},
		Store:         jobs.NewMemoryStore(),
		Management:    store,
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

	invalidResp := httptest.NewRecorder()
	invalidBody := `{"enrollment_token":"` + token.SecretToken + `","node_id":"node-invalid","environment":"prod","stage":"prod","scope":"edge-prod","public_key_pem":"not pem"}`
	handler.ServeHTTP(invalidResp, httptest.NewRequest(http.MethodPost, "/v1/kliq/enroll", bytes.NewBufferString(invalidBody)))
	if invalidResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid identity rejection, got %d: %s", invalidResp.Code, invalidResp.Body.String())
	}

	validResp := httptest.NewRecorder()
	validBody := `{"enrollment_token":"` + token.SecretToken + `","node_id":"node-invalid","environment":"prod","stage":"prod","scope":"edge-prod","public_key_pem":` + quoteJSON(validPublicKeyPEM(t)) + `}`
	handler.ServeHTTP(validResp, httptest.NewRequest(http.MethodPost, "/v1/kliq/enroll", bytes.NewBufferString(validBody)))
	if validResp.Code != http.StatusCreated {
		t.Fatalf("expected token still usable after invalid identity request, got %d: %s", validResp.Code, validResp.Body.String())
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
	token, err := issuer.IssueForIdentity(registration.Identity, time.Hour)
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

func TestRevokedKLIQCannotSendHealthyStatus(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.revoked-status", "node-revoked-status")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeKLIQ(t.Context(), registration.KLIQID, "test revocation", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	issuer := &authn.KLIQServiceTokenIssuer{Secret: []byte("test-kliq-service-secret")}
	token, err := issuer.IssueForIdentity(registration.Identity, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator: authn.Chain{issuer},
		Authorizer:    authz.Authorizer{},
		Store:         jobs.NewMemoryStore(),
		Management:    store,
		KLIQService:   issuer,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/status-reports", bytes.NewBufferString(`{"kliq_id":"`+registration.KLIQID+`","environment":"prod","stage":"prod","scope":"edge-prod","assignment_version":1,"status":"ok"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for revoked KLIQ status, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKLIQServiceCanRefreshOwnToken(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.refresh", "node-refresh")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	issuer := &authn.KLIQServiceTokenIssuer{Secret: []byte("test-kliq-service-secret")}
	token, err := issuer.IssueForIdentity(registration.Identity, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator: authn.Chain{issuer},
		Authorizer:    authz.Authorizer{},
		Store:         jobs.NewMemoryStore(),
		Management:    store,
		KLIQService:   issuer,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/service-token/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected token refresh accepted, got %d: %s", rec.Code, rec.Body.String())
	}
	var refreshed serviceTokenRefreshResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.ServiceToken == "" || refreshed.ServiceToken == token {
		t.Fatalf("expected new service token, got %#v", refreshed)
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

	operatorRuntimeResp := httptest.NewRecorder()
	operatorRuntimeReq := httptest.NewRequest(http.MethodPost, "/v1/kliq/heartbeat", bytes.NewBufferString(`{"kliq_id":"`+registration.KLIQID+`","environment":"prod","stage":"prod","scope":"edge-prod","assignment_version":1,"status":"ok"}`))
	operatorRuntimeReq.Header.Set("Authorization", operatorToken)
	handler.ServeHTTP(operatorRuntimeResp, operatorRuntimeReq)
	if operatorRuntimeResp.Code != http.StatusForbidden {
		t.Fatalf("expected operator token rejected as KLIQ runtime credential, got %d: %s", operatorRuntimeResp.Code, operatorRuntimeResp.Body.String())
	}
}

func TestManagementRevocationAuditIncludesActorAndTarget(t *testing.T) {
	store := management.NewMemoryStore()
	registration := testRegistration("kliq.audit-revoked", "node-audit-revoked")
	if err := store.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	server := Server{
		Authenticator: authn.DevTokenVerifier{},
		Authorizer:    authz.Authorizer{},
		Store:         jobs.NewMemoryStore(),
		Management:    store,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/kliq/registrations/"+registration.KLIQID+"/revoke", bytes.NewBufferString(`{"reason":"audit test"}`))
	req.Header.Set("Authorization", "Bearer dev:ops:operator:acme:prod:prod")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected revocation accepted, got %d: %s", rec.Code, rec.Body.String())
	}
	events, err := store.AuditEvents(t.Context(), "kliq_registration", registration.KLIQID)
	if err != nil {
		t.Fatal(err)
	}
	revocation := requireAuditEvent(t, events, "revocation")
	if revocation.Actor != "ops" || revocation.KLIQID != registration.KLIQID || revocation.TargetID != registration.KLIQID {
		t.Fatalf("expected revocation actor and target, got %#v", revocation)
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

func validPublicKeyPEM(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}))
}

func quoteJSON(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func requireAuditEvent(t *testing.T, events []domain.ManagementAuditEvent, eventType string) domain.ManagementAuditEvent {
	t.Helper()
	for _, event := range events {
		if event.EventType == eventType {
			return event
		}
	}
	t.Fatalf("expected audit event %q in %#v", eventType, events)
	return domain.ManagementAuditEvent{}
}

func putApprovedBuildManifest(t *testing.T, store *artifactstore.MemoryStore, signer *signing.DevLocalSigner, sourceCommit, environment, stage, scope string, outputs map[string]coreartifact.Ref) coreartifact.Ref {
	t.Helper()
	return putBuildManifest(t, store, signer, sourceCommit, compiler.ManifestApproval{
		Status:        "approved",
		ApprovedBy:    "test",
		ApprovedAt:    time.Now().UTC(),
		AuthorityID:   "approval-authority.test",
		AuthorityKind: "forge-management-signature",
		Environment:   environment,
		Stage:         stage,
		Scope:         scope,
	}, outputs)
}

func putPendingBuildManifest(t *testing.T, store *artifactstore.MemoryStore, signer *signing.DevLocalSigner, sourceCommit string, outputs map[string]coreartifact.Ref) coreartifact.Ref {
	t.Helper()
	return putBuildManifest(t, store, signer, sourceCommit, compiler.ManifestApproval{Status: "pending_review"}, outputs)
}

func putBuildManifest(t *testing.T, store *artifactstore.MemoryStore, signer *signing.DevLocalSigner, sourceCommit string, approval compiler.ManifestApproval, outputs map[string]coreartifact.Ref) coreartifact.Ref {
	t.Helper()
	if outputs == nil {
		outputs = map[string]coreartifact.Ref{}
	}
	signedOutputs := map[string]compiler.SignedOutputRef{}
	for artifactType, ref := range outputs {
		signedOutputs[artifactType] = compiler.SignedOutputRef{ArtifactRef: ref, EnvelopeSHA256: ref.SHA256, PayloadSHA256: "sha256:payload-" + artifactType, KeyID: "forge-management-dev-local"}
	}
	manifest := compiler.PolicyBuildManifest{
		Kind: "PolicyBuildManifest",
		Metadata: compiler.ManifestMetadata{
			ID:            "build.test." + strings.ReplaceAll(sourceCommit, "/", "-"),
			CorrelationID: "correlation.test",
		},
		Approval: approval,
		Spec: compiler.ManifestSpec{
			PolicyRepo: compiler.PolicyRepoRef{
				Repo:           "enterprise-kernloom-policies",
				Commit:         sourceCommit,
				PolicyFile:     "policies/runtime/test.intent.kni",
				PolicyFileHash: "sha256:policy",
				ContentDigest:  "sha256:policy-repo",
			},
			EnterpriseRegistry: compiler.RegistryRef{Repo: "enterprise-kernloom-registry", Commit: sourceCommit, ContentDigest: "sha256:enterprise-registry"},
			CoreRegistry:       compiler.RegistryRef{Repo: "kernloom-core-registry", Commit: sourceCommit, ContentDigest: "sha256:core-registry"},
			Profile:            compiler.DigestRef{ID: "profile.test", Digest: "sha256:profile"},
			RiskRecipe:         compiler.DigestRef{ID: "risk.test", Digest: "sha256:risk"},
			CatalogDigest:      "sha256:catalog",
			SignedOutputs:      signedOutputs,
		},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(t.Context(), payload, signing.Metadata{SourceCommit: sourceCommit})
	if err != nil {
		t.Fatal(err)
	}
	envelopePayload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Put(t.Context(), coreartifact.Artifact{
		Metadata: coreartifact.Metadata{
			ID:           manifest.Metadata.ID,
			PolicyID:     "policy.test",
			ArtifactType: "policy_build_manifest_signed_envelope",
			SourceCommit: sourceCommit,
		},
		Payload: envelopePayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
