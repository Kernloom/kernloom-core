// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/management"
)

func TestSeedManagementTrustBundleDoesNotExtendExistingBundle(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := seedManagementTrustBundle(store, signer); err != nil {
		t.Fatal(err)
	}
	first, err := store.TrustBundle(context.Background(), signer.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedManagementTrustBundle(store, signer); err != nil {
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

func TestSeedManagementTrustBundleRejectsMismatchedPublicKey(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTrustBundle(context.Background(), domain.TrustBundle{
		KeyID:     signer.KeyID,
		PublicKey: "different-public-key",
		Purpose:   "kliq_assignment",
		Status:    "active",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Issuer:    "test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := seedManagementTrustBundle(store, signer); err == nil {
		t.Fatal("expected startup seed to reject mismatched public key")
	}
}
