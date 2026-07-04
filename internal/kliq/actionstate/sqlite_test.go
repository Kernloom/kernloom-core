// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actionstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
)

func TestOpenSQLiteCreatesStateFileWithPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected state db mode 0600, got %o", got)
	}
}

func TestOpenSQLiteRejectsGroupOrWorldAccessibleStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(path); err == nil {
		t.Fatal("expected group/world-readable state db to be rejected")
	}
}

func TestSQLitePersistsLocalTrustBundle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle := domain.TrustBundle{
		KeyID:     "forge-management-dev-local",
		PublicKey: "public-key",
		Purpose:   "kliq_assignment",
		Status:    "active",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Issuer:    "test",
	}
	if err := store.SaveLocalTrustBundle(ctx, bundle, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.LastLocalTrustBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.KeyID != bundle.KeyID || persisted.PublicKey != bundle.PublicKey {
		t.Fatalf("unexpected persisted trust bundle %#v", persisted)
	}
}
