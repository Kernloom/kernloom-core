// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing

import (
	"context"
	"testing"
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
