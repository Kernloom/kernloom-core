// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

func TestManagedAssignmentSourceLoadsVerifiedRuntimeBundleArtifact(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	runtimeEnvelope := managedSourceSignedRuntimeEnvelope(t, signer, now)
	assignment := managedSourceTestAssignment(now, runtimeEnvelope)
	envelope := signedAssignmentEnvelope(t, signer, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("expected bearer token to be sent, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	source := &ManagedAssignmentSource{
		BaseURL:     server.URL,
		BearerToken: "test-token",
		KLIQID:      assignment.KLIQID,
		Environment: assignment.Environment,
		Stage:       assignment.Stage,
		Scope:       assignment.Scope,
		TrustKeyID:  assignment.TrustKeyID,
		Verifier:    signer,
	}
	data, sourceRef, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	activation, ok := source.AssignmentActivation()
	if !ok {
		t.Fatal("expected assignment activation metadata")
	}
	if activation.AssignmentDigest != envelope.PayloadSHA256 {
		t.Fatalf("expected assignment digest %q, got %q", envelope.PayloadSHA256, activation.AssignmentDigest)
	}
	if string(data) != string(runtimeEnvelope) {
		t.Fatalf("expected runtime bundle envelope, got %s", string(data))
	}
	if sourceRef == "" {
		t.Fatal("expected managed source ref")
	}
}

func TestManagedAssignmentSourceAllowsSameVersionSameDigest(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	runtimeEnvelope := managedSourceSignedRuntimeEnvelope(t, signer, now)
	assignment := managedSourceTestAssignment(now, runtimeEnvelope)
	envelope := signedAssignmentEnvelope(t, signer, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	_, _, err = (&ManagedAssignmentSource{
		BaseURL:                 server.URL,
		KLIQID:                  assignment.KLIQID,
		Environment:             assignment.Environment,
		Stage:                   assignment.Stage,
		Scope:                   assignment.Scope,
		TrustKeyID:              assignment.TrustKeyID,
		ActiveAssignmentVersion: assignment.AssignmentVersion,
		ActiveAssignmentDigest:  envelope.PayloadSHA256,
		Verifier:                signer,
	}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedAssignmentSourceRejectsRollbackWithoutApproval(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	assignment := managedSourceTestAssignment(now, managedSourceSignedRuntimeEnvelope(t, signer, now))
	envelope := signedAssignmentEnvelope(t, signer, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	_, _, err = (&ManagedAssignmentSource{
		BaseURL:                 server.URL,
		KLIQID:                  assignment.KLIQID,
		Environment:             assignment.Environment,
		Stage:                   assignment.Stage,
		Scope:                   assignment.Scope,
		TrustKeyID:              assignment.TrustKeyID,
		ActiveAssignmentVersion: 2,
		Verifier:                signer,
	}).Load(context.Background())
	if err == nil {
		t.Fatal("expected rollback assignment to be rejected")
	}
}

func TestManagedAssignmentSourceAcceptsSignedApprovedRollback(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	assignment := managedSourceTestAssignment(now, managedSourceSignedRuntimeEnvelope(t, signer, now))
	assignment.ApprovedRollback = true
	envelope := signedAssignmentEnvelope(t, signer, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	_, _, err = (&ManagedAssignmentSource{
		BaseURL:                 server.URL,
		KLIQID:                  assignment.KLIQID,
		Environment:             assignment.Environment,
		Stage:                   assignment.Stage,
		Scope:                   assignment.Scope,
		TrustKeyID:              assignment.TrustKeyID,
		ActiveAssignmentVersion: 2,
		Verifier:                signer,
	}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedAssignmentSourceUsesArtifactVerificationTrustBundle(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignmentSigner, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	artifactSigner, err := signing.NewDevLocalSigner("artifact-key-1")
	if err != nil {
		t.Fatal(err)
	}
	assignmentSigner.Now = func() time.Time { return now }
	artifactSigner.Now = func() time.Time { return now }
	runtimeEnvelope := managedSourceSignedRuntimeEnvelope(t, artifactSigner, now)
	assignment := managedSourceTestAssignment(now, runtimeEnvelope)
	trustEnvelope := managedSourceSignedTrustBundleEnvelope(t, assignmentSigner, domain.TrustBundle{
		KeyID:     artifactSigner.KeyID,
		PublicKey: base64.StdEncoding.EncodeToString(artifactSigner.PublicKey),
		Purpose:   "artifact_verification",
		Status:    "active",
		ExpiresAt: now.Add(time.Hour),
		Issuer:    "forge-management-test",
	}, now)
	assignment.Artifacts = append([]domain.KLIQAssignedArtifact{{
		ArtifactType: "trust_bundle",
		ArtifactID:   "trust_bundle.artifact-key-1",
		SHA256:       domain.SHA256JSON(trustEnvelope),
		Envelope:     trustEnvelope,
	}}, assignment.Artifacts...)
	envelope := signedAssignmentEnvelope(t, assignmentSigner, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	_, _, err = (&ManagedAssignmentSource{
		BaseURL:     server.URL,
		KLIQID:      assignment.KLIQID,
		Environment: assignment.Environment,
		Stage:       assignment.Stage,
		Scope:       assignment.Scope,
		TrustKeyID:  assignment.TrustKeyID,
		Verifier:    assignmentSigner,
	}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedAssignmentSourceRejectsAssignmentSignedArtifactWhenArtifactTrustBundlePresent(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignmentSigner, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	artifactSigner, err := signing.NewDevLocalSigner("artifact-key-1")
	if err != nil {
		t.Fatal(err)
	}
	assignmentSigner.Now = func() time.Time { return now }
	artifactSigner.Now = func() time.Time { return now }
	runtimeEnvelope := managedSourceSignedRuntimeEnvelope(t, assignmentSigner, now)
	assignment := managedSourceTestAssignment(now, runtimeEnvelope)
	trustEnvelope := managedSourceSignedTrustBundleEnvelope(t, assignmentSigner, domain.TrustBundle{
		KeyID:     artifactSigner.KeyID,
		PublicKey: base64.StdEncoding.EncodeToString(artifactSigner.PublicKey),
		Purpose:   "artifact_verification",
		Status:    "active",
		ExpiresAt: now.Add(time.Hour),
		Issuer:    "forge-management-test",
	}, now)
	assignment.Artifacts = append([]domain.KLIQAssignedArtifact{{
		ArtifactType: "trust_bundle",
		ArtifactID:   "trust_bundle.artifact-key-1",
		SHA256:       domain.SHA256JSON(trustEnvelope),
		Envelope:     trustEnvelope,
	}}, assignment.Artifacts...)
	envelope := signedAssignmentEnvelope(t, assignmentSigner, assignment, now.Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	_, _, err = (&ManagedAssignmentSource{
		BaseURL:     server.URL,
		KLIQID:      assignment.KLIQID,
		Environment: assignment.Environment,
		Stage:       assignment.Stage,
		Scope:       assignment.Scope,
		TrustKeyID:  assignment.TrustKeyID,
		Verifier:    assignmentSigner,
	}).Load(context.Background())
	if err == nil {
		t.Fatal("expected runtime artifact signed by assignment key to be rejected once artifact_verification trust bundle is present")
	}
}

func managedSourceTestAssignment(now time.Time, runtimeEnvelope json.RawMessage) domain.KLIQAssignment {
	return domain.KLIQAssignment{
		AssignmentID:      "kliq_assignment.test",
		AssignmentVersion: 1,
		KLIQID:            "kliq.test",
		Environment:       "prod",
		Stage:             "prod",
		Scope:             "edge-prod",
		SourceCommit:      "abc123",
		TrustKeyID:        "forge-management-dev-local",
		TrustBundleRef:    "forge-management-dev-local",
		CreatedAt:         now,
		ExpiresAt:         now.Add(time.Hour),
		Artifacts: []domain.KLIQAssignedArtifact{{
			ArtifactType: "runtime_bundle",
			ArtifactID:   "runtime_bundle.test",
			SHA256:       domain.SHA256JSON(runtimeEnvelope),
			Envelope:     runtimeEnvelope,
		}},
	}
}

func managedSourceSignedTrustBundleEnvelope(t *testing.T, signer *signing.DevLocalSigner, bundle domain.TrustBundle, now time.Time) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		SourceCommit: "abc123",
		ExpiresAt:    ptrTime(now.Add(time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signedAssignmentEnvelope(t *testing.T, signer *signing.DevLocalSigner, assignment domain.KLIQAssignment, expiresAt time.Time) signing.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		SourceCommit: assignment.SourceCommit,
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func managedSourceSignedRuntimeEnvelope(t *testing.T, signer *signing.DevLocalSigner, now time.Time) json.RawMessage {
	t.Helper()
	payload := []byte(`{"kind":"RuntimeBundle","metadata":{"id":"runtime_bundle.test","policy_id":"policy.test","artifact_type":"runtime_bundle","source_commit":"abc123"}}`)
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		PolicyID:     "policy.test",
		SourceCommit: "abc123",
		ExpiresAt:    ptrTime(now.Add(time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
