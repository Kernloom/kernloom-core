// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/management"
)

func TestValidateOrSeedManagementTrustBundleRequiresExplicitDevSeed(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, false); err == nil {
		t.Fatal("expected missing trust bundle to require explicit dev seed")
	}
}

func TestValidateOrSeedManagementTrustBundleDoesNotExtendExistingBundle(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, true); err != nil {
		t.Fatal(err)
	}
	first, err := store.TrustBundle(context.Background(), signer.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, false); err != nil {
		t.Fatal(err)
	}
	second, err := store.TrustBundle(context.Background(), signer.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ExpiresAt.Equal(second.ExpiresAt) {
		t.Fatalf("expected startup seed to leave expiry unchanged, got first=%s second=%s", first.ExpiresAt, second.ExpiresAt)
	}
}

func TestValidateOrSeedManagementTrustBundleRejectsMismatchedPublicKey(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTrustBundle(context.Background(), domain.TrustBundle{
		KeyID:     signer.KeyID,
		PublicKey: "different-public-key",
		Purpose:   "assignment_verification",
		Status:    "active",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Issuer:    "test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, false); err == nil {
		t.Fatal("expected startup seed to reject mismatched public key")
	}
}

func TestLoadKLIQServiceTokenSecretRejectsCLISecretWithoutDevGate(t *testing.T) {
	_, err := loadKLIQServiceTokenSecret("secret", "", false)
	if err == nil || !strings.Contains(err.Error(), "process argv") {
		t.Fatalf("expected argv secret to require explicit dev gate, got %v", err)
	}
	secret, err := loadKLIQServiceTokenSecret("secret", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "secret" {
		t.Fatalf("unexpected secret %q", string(secret))
	}
}

func TestLoadKLIQServiceTokenSecretPrefersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KERNLOOM_KLIQ_SERVICE_TOKEN_SECRET", "env-secret")
	secret, err := loadKLIQServiceTokenSecret("", path, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "file-secret" {
		t.Fatalf("expected file secret, got %q", string(secret))
	}
}
