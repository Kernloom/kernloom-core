// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package jobs

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom-core/internal/forge/compiler"
)

func TestRunnerRunsSimulationJob(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	policyRepo := testdataPath("policy-repo")
	job, err := NewJob(TypeSimulation, "alice", SimulationPayload{
		PolicyRepo:         policyRepo,
		PolicyFile:         filepath.Join(policyRepo, "policies", "delegation", "ziti-readonly-observation.intent.kni"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		OutputDir:          t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	processed, err := (Runner{Store: store, Defaults: compiler.Options{}}).RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if processed.Status != StatusSucceeded {
		t.Fatalf("expected succeeded, got %#v", processed)
	}
	var result SimulationResult
	if err := json.Unmarshal(processed.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "resolved_only" || len(result.Policies) != 1 {
		t.Fatalf("unexpected simulation result %#v", result)
	}
}

func testdataPath(name string) string {
	return filepath.Join("..", "testdata", name)
}
