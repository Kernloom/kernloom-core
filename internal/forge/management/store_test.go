// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package management

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

func TestMemoryStoreEnrollmentTokenSingleUseExpiryRevocationAndAudit(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	secret := "enroll-secret"
	token := domain.KLIQEnrollmentToken{
		TokenID:     "token.test",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
		ExpiresAt:   now.Add(time.Hour),
		CreatedAt:   now,
	}

	if err := store.CreateEnrollmentToken(ctx, token, secret); err != nil {
		t.Fatal(err)
	}
	stored, err := store.EnrollmentToken(ctx, token.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.TokenSHA256 == "" || stored.TokenSHA256 == secret {
		t.Fatalf("expected token stored hashed only, got %#v", stored)
	}
	if _, err := store.UseEnrollmentToken(ctx, secret, "prod", "prod", "edge-prod", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UseEnrollmentToken(ctx, secret, "prod", "prod", "edge-prod", now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected reused enrollment token to be rejected")
	}
	events, err := store.AuditEvents(ctx, "kliq_enrollment_token", token.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 {
		t.Fatalf("expected token create/use audit events, got %#v", events)
	}

	expiredSecret := "expired-secret"
	expired := token
	expired.TokenID = "token.expired"
	expired.ExpiresAt = now.Add(-time.Minute)
	if err := store.CreateEnrollmentToken(ctx, expired, expiredSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UseEnrollmentToken(ctx, expiredSecret, "prod", "prod", "edge-prod", now); err == nil {
		t.Fatal("expected expired enrollment token to be rejected")
	}

	revokedSecret := "revoked-secret"
	revoked := token
	revoked.TokenID = "token.revoked"
	if err := store.CreateEnrollmentToken(ctx, revoked, revokedSecret); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeEnrollmentToken(ctx, revoked.TokenID, "test", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UseEnrollmentToken(ctx, revokedSecret, "prod", "prod", "edge-prod", now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected revoked enrollment token to be rejected")
	}
}

func TestMemoryStoreCreatesBoundKLIQIdentityAndAudit(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	registration := domain.KLIQRegistration{
		RegistrationID: "registration.test",
		KLIQID:         "kliq.test",
		NodeID:         "node-1",
		Environment:    "prod",
		Stage:          "prod",
		Scope:          "edge-prod",
		RegisteredAt:   time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		Identity: domain.KLIQIdentity{
			KLIQID:       "kliq.test",
			NodeID:       "node-1",
			Environment:  "prod",
			Stage:        "prod",
			Scope:        "edge-prod",
			TrustKeyID:   "forge-management-dev-local",
			PublicKeyPEM: "public-key",
		},
	}
	if err := store.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	identity, err := store.Identity(ctx, registration.KLIQID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.KLIQID != registration.KLIQID || identity.PublicKeyPEM == "" || identity.Status != "active" {
		t.Fatalf("expected active identity bound to registration, got %#v", identity)
	}
	events, err := store.AuditEvents(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 {
		t.Fatalf("expected enrollment and identity audit events, got %#v", events)
	}
}

func TestMemoryStoreRejectsSameAssignmentVersionDifferentDigest(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	first := signing.SignedEnvelope{PayloadSHA256: "sha256:first"}
	second := signing.SignedEnvelope{PayloadSHA256: "sha256:second"}

	if err := store.SaveAssignment(ctx, "kliq.test", 1, first); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(ctx, "kliq.test", 1, first); err != nil {
		t.Fatalf("expected same version and digest to be idempotent: %v", err)
	}
	if err := store.SaveAssignment(ctx, "kliq.test", 1, second); err == nil {
		t.Fatal("expected same version with different digest to be rejected")
	}
}

func TestMemoryStoreRejectsOlderAssignmentVersion(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.SaveAssignment(ctx, "kliq.test", 2, signing.SignedEnvelope{PayloadSHA256: "sha256:v2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(ctx, "kliq.test", 1, signing.SignedEnvelope{PayloadSHA256: "sha256:v1"}); err == nil {
		t.Fatal("expected older assignment version to be rejected")
	}
}

func TestMemoryStoreDoesNotReactivateRevokedTrustBundle(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	bundle := domain.TrustBundle{
		KeyID:     "forge-management-dev-local",
		PublicKey: "public-key",
		Purpose:   "kliq_assignment",
		Status:    "active",
		ExpiresAt: now.Add(time.Hour),
		Issuer:    "test",
	}
	if err := store.SaveTrustBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeTrustBundle(ctx, bundle.KeyID, "rotation", now); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTrustBundle(ctx, bundle); err == nil {
		t.Fatal("expected active overwrite of revoked trust bundle to be rejected")
	}
}

func TestMemoryStoreLatestAssignmentDoesNotFallbackAfterLatestRevoked(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.SaveAssignment(ctx, "kliq.test", 1, signing.SignedEnvelope{PayloadSHA256: "sha256:v1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(ctx, "kliq.test", 2, signing.SignedEnvelope{PayloadSHA256: "sha256:v2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAssignment(ctx, "kliq.test", 2, "bad assignment", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LatestAssignment(ctx, "kliq.test"); err == nil {
		t.Fatal("expected revoked latest assignment to suppress older fallback")
	}
}

func TestMemoryStoreAuditEventsIncludeActorFromContext(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithAuditActor(context.Background(), "ops")
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	token := domain.KLIQEnrollmentToken{
		TokenID:     "token.actor",
		Environment: "prod",
		Stage:       "prod",
		Scope:       "edge-prod",
		ExpiresAt:   now.Add(time.Hour),
		CreatedAt:   now,
	}
	if err := store.CreateEnrollmentToken(ctx, token, "secret"); err != nil {
		t.Fatal(err)
	}
	events, err := store.AuditEvents(context.Background(), "kliq_enrollment_token", token.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Actor != "ops" {
		t.Fatalf("expected audit actor ops, got %#v", events)
	}
}
