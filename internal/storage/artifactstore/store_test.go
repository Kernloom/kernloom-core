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
	art := artifact.Artifact{
		Metadata: artifact.Metadata{
			ID:           "artifact.test",
			ArtifactType: "resolved_policy",
			CreatedAt:    time.Now().UTC(),
		},
		Payload: []byte(`{"kind":"Test"}`),
	}
	ref, err := store.Put(context.Background(), art)
	if err != nil {
		t.Fatal(err)
	}
	secondRef, err := store.Put(context.Background(), art)
	if err != nil {
		t.Fatal(err)
	}
	if secondRef != ref {
		t.Fatalf("expected idempotent put to return same ref, got %#v and %#v", ref, secondRef)
	}
	if err := store.Verify(context.Background(), ref); err != nil {
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
	art := artifact.Artifact{
		Metadata: artifact.Metadata{
			ID:           "artifact.test",
			ArtifactType: "runtime_bundle",
			SourceCommit: "abc123",
			CreatedAt:    time.Now().UTC(),
		},
		Payload: []byte(`{"kind":"RuntimeBundle"}`),
	}
	ref, err := store.Put(context.Background(), art)
	if err != nil {
		t.Fatal(err)
	}
	secondRef, err := store.Put(context.Background(), art)
	if err != nil {
		t.Fatal(err)
	}
	if secondRef != ref {
		t.Fatalf("expected idempotent put to return same ref, got %#v and %#v", ref, secondRef)
	}
	if err := store.Verify(context.Background(), ref); err != nil {
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
