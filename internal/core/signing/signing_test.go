// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDevLocalSignerSignsAndVerifies(t *testing.T) {
	signer, err := NewDevLocalSigner("dev-local")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), []byte(`{"kind":"RuntimeBundle"}`), Metadata{
		PolicyID:     "policy.test",
		SourceCommit: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := signer.Verify(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("expected valid signature, got %#v", result)
	}
}

func TestDevLocalSignerRejectsProtectedMetadataTampering(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	signer, err := NewDevLocalSigner("dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	envelope, err := signer.Sign(context.Background(), []byte(`{"kind":"RuntimeBundle"}`), Metadata{
		PolicyID:     "policy.test",
		SourceCommit: "abc123",
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(signingEnvelope SignedEnvelope) SignedEnvelope{
		"expires_at extended": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			extended := now.Add(365 * 24 * time.Hour)
			signingEnvelope.ExpiresAt = &extended
			return signingEnvelope
		},
		"expires_at removed": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			signingEnvelope.ExpiresAt = nil
			return signingEnvelope
		},
		"key_id changed": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			signingEnvelope.KeyID = "prod-key"
			return signingEnvelope
		},
		"policy_id changed": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			signingEnvelope.PolicyID = "policy.other"
			return signingEnvelope
		},
		"source_commit changed": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			signingEnvelope.SourceCommit = "def456"
			return signingEnvelope
		},
		"payload_type changed": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			signingEnvelope.PayloadType = "application/json"
			return signingEnvelope
		},
		"payload changed": func(signingEnvelope SignedEnvelope) SignedEnvelope {
			signingEnvelope.Payload = []byte(`{"kind":"Other"}`)
			return signingEnvelope
		},
	}

	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := signer.Verify(context.Background(), tamper(envelope))
			if err != nil {
				t.Fatal(err)
			}
			if result.Valid {
				t.Fatalf("expected tampered envelope to be rejected")
			}
		})
	}
}

func TestDevLocalSignerRejectsExpiredEnvelope(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	signer, err := NewDevLocalSigner("dev-local")
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return now }
	expiresAt := now.Add(-time.Minute)
	envelope, err := signer.Sign(context.Background(), []byte(`{"kind":"RuntimeBundle"}`), Metadata{
		PolicyID:  "policy.test",
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := signer.Verify(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Error != "signed envelope expired" {
		t.Fatalf("expected expired envelope to be rejected, got %#v", result)
	}
}

func TestLoadOrCreateDevLocalSignerPersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "dev-local.ed25519.json")
	signer, err := LoadOrCreateDevLocalSigner(path, "dev-local")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(context.Background(), []byte(`{"kind":"RuntimeBundle"}`), Metadata{
		PolicyID: "policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := LoadDevLocalVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("expected persisted verifier to validate signature, got %#v", result)
	}
}
