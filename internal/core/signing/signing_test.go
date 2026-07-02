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
