// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

//go:build integration

package management

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

func TestPostgresStoreAppliesMigrationsAndPersistsManagedFlow(t *testing.T) {
	dsn := os.Getenv("KERNLOOM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KERNLOOM_TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	store, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	suffix := shortHash(t.Name() + now.Format(time.RFC3339Nano))
	secret := "kliq_enroll_integration_" + suffix
	token := domain.KLIQEnrollmentToken{
		TokenID:     "kliq_enrollment_token." + suffix,
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
		ExpiresAt:   now.Add(time.Hour),
		CreatedAt:   now,
	}
	if err := store.CreateEnrollmentToken(ctx, token, secret); err != nil {
		t.Fatal(err)
	}
	used, err := store.UseEnrollmentToken(ctx, secret, "prod", "prod", "edge-prod", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if used.TokenSHA256 == "" || used.TokenSHA256 == secret || used.UsedAt.IsZero() {
		t.Fatalf("expected hashed single-use token, got %#v", used)
	}
	if _, err := store.UseEnrollmentToken(ctx, secret, "prod", "prod", "edge-prod", now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected reused enrollment token to be rejected")
	}

	registration := domain.KLIQRegistration{
		RegistrationID: "kliq_registration.integration." + suffix,
		KLIQID:         "kliq.integration." + suffix,
		NodeID:         "node.integration." + suffix,
		Environment:    "prod",
		Stage:          "prod",
		Scope:          "edge-prod",
		Status:         "active",
		RegisteredAt:   now,
		Identity: domain.KLIQIdentity{
			IdentityID:              "kliq_identity.integration." + suffix,
			KLIQID:                  "kliq.integration." + suffix,
			NodeID:                  "node.integration." + suffix,
			Environment:             "prod",
			Stage:                   "prod",
			Scope:                   "edge-prod",
			TrustKeyID:              "trust.integration." + suffix,
			PublicKeyPEM:            "public-key.integration",
			ServiceIdentityProvider: "spiffe-ready",
			SPIFFEID:                "spiffe://kernloom.local/kliq/" + suffix,
			CredentialStatus:        "active",
			Status:                  "active",
			IssuedAt:                now,
		},
	}
	if err := store.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Registration(ctx, registration.KLIQID); err != nil || got.Identity.SPIFFEID != registration.Identity.SPIFFEID {
		t.Fatalf("expected persisted registration, got %#v err=%v", got, err)
	}

	signer, err := signing.NewDevLocalSigner(registration.Identity.TrustKeyID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(ctx, []byte(`{"kind":"KLIQAssignment","assignment_id":"integration"}`), signing.Metadata{SourceCommit: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	version, err := store.NextAssignmentVersion(ctx, registration.KLIQID)
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("expected first assignment version 1, got %d", version)
	}
	if err := store.SaveAssignment(ctx, registration.KLIQID, version, envelope); err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestAssignment(ctx, registration.KLIQID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.PayloadSHA256 != envelope.PayloadSHA256 {
		t.Fatalf("expected latest assignment payload hash %q, got %q", envelope.PayloadSHA256, latest.PayloadSHA256)
	}

	if err := store.SaveHeartbeat(ctx, domain.KLIQHeartbeat{
		KLIQID:            registration.KLIQID,
		Environment:       registration.Environment,
		Stage:             registration.Stage,
		Scope:             registration.Scope,
		AssignmentVersion: version,
		Status:            "ok",
		ReportedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveStatusReport(ctx, domain.KLIQStatusReport{
		KLIQID:            registration.KLIQID,
		Environment:       registration.Environment,
		Stage:             registration.Stage,
		Scope:             registration.Scope,
		AssignmentVersion: version,
		Status:            "ok",
		ReportedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := store.StatusReport(ctx, registration.KLIQID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" || report.Scope != registration.Scope {
		t.Fatalf("expected persisted status report, got %#v", report)
	}
}
