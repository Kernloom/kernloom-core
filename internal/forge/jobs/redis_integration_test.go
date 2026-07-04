// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

//go:build integration

package jobs

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRedisStorePersistsAndDequeuesJobs(t *testing.T) {
	addr := os.Getenv("KERNLOOM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("KERNLOOM_TEST_REDIS_ADDR is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store := NewRedisStore(addr)
	store.Prefix = "kernloom:integration:" + newID("test")
	store.Queue = store.Prefix + ":jobs"

	job, err := NewJob(TypeSimulation, "integration-test", SimulationPayload{PolicyFile: "policies/runtime/test.intent.kni"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	dequeued, err := store.Dequeue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dequeued != job.ID {
		t.Fatalf("expected dequeued job %q, got %q", job.ID, dequeued)
	}
	job.SetResult(SimulationResult{Kind: "SimulationJobResult", Status: "resolved_only"})
	if err := store.Update(ctx, job); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != StatusSucceeded || len(loaded.Result) == 0 {
		t.Fatalf("expected persisted successful job, got %#v", loaded)
	}
	if _, err := store.Dequeue(ctx); err != ErrNoJob {
		t.Fatalf("expected empty redis queue, got %v", err)
	}
}
