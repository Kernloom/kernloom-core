// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package artifactstore

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/artifact"
)

func TestMemoryStorePutGet(t *testing.T) {
	store := NewMemoryStore()
	ref, err := store.Put(context.Background(), artifact.Artifact{
		Metadata: artifact.Metadata{
			ID:           "artifact.test",
			ArtifactType: "resolved_policy",
			CreatedAt:    time.Now().UTC(),
		},
		Payload: []byte(`{"kind":"Test"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"kind":"Test"}` {
		t.Fatalf("unexpected data %s", data)
	}
}

func TestFSStorePutGet(t *testing.T) {
	store := NewFSStore(t.TempDir(), "acme", "dev")
	ref, err := store.Put(context.Background(), artifact.Artifact{
		Metadata: artifact.Metadata{
			ID:           "artifact.test",
			ArtifactType: "runtime_bundle",
			SourceCommit: "abc123",
			CreatedAt:    time.Now().UTC(),
		},
		Payload: []byte(`{"kind":"RuntimeBundle"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"kind":"RuntimeBundle"}` {
		t.Fatalf("unexpected data %s", data)
	}
}
