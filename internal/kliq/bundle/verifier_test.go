// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

func TestVerifySignedRuntimeBundleAcceptsValidEnvelope(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	signer := testSigner(t, now)
	envelope := signedRuntimeBundle(t, signer, now.Add(time.Hour))
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySignedRuntimeBundle(context.Background(), data, signer)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Bundle.Metadata.PolicyID != "policy.test" {
		t.Fatalf("unexpected policy id %q", verified.Bundle.Metadata.PolicyID)
	}
}

func TestVerifySignedRuntimeBundleRejectsUnsignedPayload(t *testing.T) {
	payload, err := json.Marshal(runtimeBundle())
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySignedRuntimeBundle(context.Background(), payload, testSigner(t, time.Now()))
	if err == nil {
		t.Fatal("expected unsigned runtime bundle to be rejected")
	}
}

func TestVerifySignedRuntimeBundleRejectsExpiredEnvelope(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	signer := testSigner(t, now)
	envelope := signedRuntimeBundle(t, signer, now.Add(-time.Minute))
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySignedRuntimeBundle(context.Background(), data, signer)
	if err == nil {
		t.Fatal("expected expired runtime bundle to be rejected")
	}
}

func TestVerifySignedRuntimeBundleRejectsMissingExpiresAt(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	signer := testSigner(t, now)
	payload, err := json.Marshal(runtimeBundle())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		PolicyID:     "policy.test",
		SourceCommit: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySignedRuntimeBundle(context.Background(), data, signer)
	if err == nil {
		t.Fatal("expected runtime bundle without expires_at to be rejected")
	}
}

func TestVerifySignedRuntimeBundleRejectsProtectedMetadataTampering(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	signer := testSigner(t, now)
	envelope := signedRuntimeBundle(t, signer, now.Add(time.Hour))

	tests := map[string]func(signing.SignedEnvelope) signing.SignedEnvelope{
		"expires_at extended": func(envelope signing.SignedEnvelope) signing.SignedEnvelope {
			extended := now.Add(365 * 24 * time.Hour)
			envelope.ExpiresAt = &extended
			return envelope
		},
		"key_id changed": func(envelope signing.SignedEnvelope) signing.SignedEnvelope {
			envelope.KeyID = "prod-key"
			return envelope
		},
		"policy_id changed": func(envelope signing.SignedEnvelope) signing.SignedEnvelope {
			envelope.PolicyID = "policy.other"
			return envelope
		},
		"source_commit changed": func(envelope signing.SignedEnvelope) signing.SignedEnvelope {
			envelope.SourceCommit = "def456"
			return envelope
		},
		"payload_type changed": func(envelope signing.SignedEnvelope) signing.SignedEnvelope {
			envelope.PayloadType = "application/json"
			return envelope
		},
	}

	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(tamper(envelope))
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifySignedRuntimeBundle(context.Background(), data, signer)
			if err == nil {
				t.Fatal("expected protected metadata tampering to be rejected")
			}
		})
	}
}

func TestVerifySignedRuntimeBundleRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	signer := testSigner(t, now)
	envelope := signedRuntimeBundle(t, signer, now.Add(time.Hour))
	envelope.Signature[0] ^= 0xff
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySignedRuntimeBundle(context.Background(), data, signer)
	if err == nil {
		t.Fatal("expected invalid runtime bundle signature to be rejected")
	}
}

func testSigner(t *testing.T, now time.Time) *signing.DevLocalSigner {
	t.Helper()
	signer, err := signing.NewDevLocalSigner("dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	return signer
}

func signedRuntimeBundle(t *testing.T, signer *signing.DevLocalSigner, expiresAt time.Time) signing.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(runtimeBundle())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), payload, signing.Metadata{
		PolicyID:     "policy.test",
		SourceCommit: "abc123",
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func runtimeBundle() corebundle.RuntimeBundle {
	return corebundle.RuntimeBundle{
		Kind: "RuntimeBundle",
		Metadata: coreartifact.Metadata{
			ID:           "runtime_bundle.policy.test",
			PolicyID:     "policy.test",
			ArtifactType: "runtime_bundle",
			SourceCommit: "abc123",
			CreatedAt:    time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC),
		},
		Spec: corebundle.RuntimeBundleSpec{
			PolicyID: "policy.test",
			MaxTTL:   "15m",
			MaxScope: "user",
		},
		Status: coreartifact.PlannedStatus("test"),
	}
}
