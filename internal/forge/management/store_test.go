// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package management

import (
	"context"
	"testing"

	"github.com/kernloom/kernloom-core/internal/core/signing"
)

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
