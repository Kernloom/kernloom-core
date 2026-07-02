// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom-core/internal/core/signing"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
)

func TestCompileAccessIntent(t *testing.T) {
	out := t.TempDir()
	policyRepo := testdataPath("policy-repo")
	results, err := Compile(Options{
		PolicyRepo:         policyRepo,
		PolicyFile:         filepath.Join(policyRepo, "policies", "access", "protect-production-admin-access.intent.kni"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		OutputDir:          out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one compile result, got %d", len(results))
	}
	for _, path := range []string{
		filepath.Join(out, "resolved", "access.protect-production-admin-access.resolved.json"),
		filepath.Join(out, "artifacts", "access.protect-production-admin-access.runtime_bundle.json"),
		filepath.Join(out, "artifacts", "access.protect-production-admin-access.context_route_pack.json"),
		filepath.Join(out, "artifacts", "access.protect-production-admin-access.conformance_expectation.json"),
		filepath.Join(out, "signed", "access.protect-production-admin-access.runtime_bundle.signed.json"),
		filepath.Join(out, "signed", "access.protect-production-admin-access.context_route_pack.signed.json"),
		filepath.Join(out, "signed", "access.protect-production-admin-access.conformance_expectation.signed.json"),
		filepath.Join(out, "reports", "access.protect-production-admin-access.manifest.json"),
		filepath.Join(out, "reviews", "access.protect-production-admin-access.intent.review.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated artifact %s: %v", path, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "reports", "access.protect-production-admin-access.validation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var validation ValidationResult
	if err := json.Unmarshal(data, &validation); err != nil {
		t.Fatal(err)
	}
	if validation.Status != "not_evaluated" || validation.Passed != nil {
		t.Fatalf("expected not_evaluated validation without passed field, got %#v", validation)
	}
	manifestData, err := os.ReadFile(filepath.Join(out, "reports", "access.protect-production-admin-access.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest PolicyBuildManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Spec.ArtifactRefs["runtime_bundle"].URI == "" {
		t.Fatalf("expected runtime bundle artifact ref in manifest, got %#v", manifest.Spec.ArtifactRefs)
	}
	if manifest.Spec.SignedOutputs["runtime_bundle"].ArtifactRef.URI == "" {
		t.Fatalf("expected signed runtime bundle ref in manifest, got %#v", manifest.Spec.SignedOutputs)
	}
	verifier, err := signing.LoadDevLocalVerifier(filepath.Join(out, "keys", "dev-local.ed25519.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kliqbundle.LoadSignedRuntimeBundle(context.Background(), results[0].RuntimeBundleSignedPath, verifier); err != nil {
		t.Fatal(err)
	}
}

func TestCompileSimulationReportUsesEmptyArrayAndFinding(t *testing.T) {
	policyRepo := t.TempDir()
	policyDir := filepath.Join(policyRepo, "policies", "access")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "minimal.intent.kni")
	if err := os.WriteFile(policyPath, []byte(`intent "access.minimal" {
  version = "kni/v0.5"
  owner   = "security-platform"
  type    = "access"
  target  = "ziti"
  stage   = "prod"

  profile     = "production.high_assurance_access"
  risk_recipe = "access_risk.standard"

  rule "minimal access" {
    effect   = "allow"
    subject  = "network source"
    action   = "connect"
    resource = "production application"

    only_when = [
      "device is healthy"
    ]
  }

  runtime {
    allowed   = false
    max_ttl   = "15m"
    max_scope = "application"
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	if _, err := Compile(Options{
		PolicyRepo:         policyRepo,
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		OutputDir:          out,
	}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(out, "reports", "access.minimal.simulation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report SimulationReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Simulations == nil {
		t.Fatal("expected simulations to be an empty array, got nil")
	}
	if len(report.Simulations) != 0 {
		t.Fatalf("expected no simulations, got %d", len(report.Simulations))
	}
	if len(report.Findings) != 1 || report.Findings[0] != "No simulation examples defined." {
		t.Fatalf("expected missing simulation finding, got %#v", report.Findings)
	}
}

func testdataPath(name string) string {
	return filepath.Join("..", "testdata", name)
}
