// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validation

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/forge/bindings"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
)

func TestValidateCIResolvesKLShieldTargetBindingAndCompile(t *testing.T) {
	result := ValidateCI(CIOptions{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		Tenant:             "kernloom-demo",
		Environment:        "prod",
		Provider:           "github",
		Repository:         "kernloom-demo/klshield-config",
		BasePath:           "envs/prod",
	})
	if result.Status != "passed" {
		t.Fatalf("expected passed validation, got %#v", result)
	}
	if result.Target == nil || result.Target.ID != "klshield-prod" {
		t.Fatalf("expected klshield-prod target, got %#v", result.Target)
	}
	if len(result.Bindings) != 1 {
		t.Fatalf("expected one scoped binding, got %#v", result.Bindings)
	}
	if result.Bindings[0].Capability != "enforce.runtime.rate_limit_entity" {
		t.Fatalf("expected rate-limit capability, got %#v", result.Bindings[0])
	}
	if result.Compile == nil || result.Compile.Status != "passed" || result.Compile.Policies != 1 {
		t.Fatalf("expected compile pass, got %#v", result.Compile)
	}
	if len(result.Compile.Files) != 1 || result.Compile.Files[0] != "policies/runtime/rate-limit.intent.kni" {
		t.Fatalf("expected scoped compile of rate-limit policy only, got %#v", result.Compile.Files)
	}
	if len(result.PolicySources) != 2 {
		t.Fatalf("expected config and policy source reports, got %#v", result.PolicySources)
	}
	for _, key := range []string{"repository_bindings", "canonical_actions", "policy_sources", "target_inventory", "policy_file:policies/runtime/rate-limit.intent.kni"} {
		if result.Provenance[key] == "" {
			t.Fatalf("expected provenance digest for %s, got %#v", key, result.Provenance)
		}
	}
	if len(result.PolicySources) != 2 || len(result.PolicySources[1].PolicyMeanings) != 1 {
		t.Fatalf("expected reported policy meaning, got %#v", result.PolicySources)
	}
}

func TestValidateCIFailsClosedWhenConfigSnapshotMissing(t *testing.T) {
	result := ValidateCI(CIOptions{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		Tenant:             "kernloom-demo",
		Environment:        "prod",
		Provider:           "github",
		Repository:         "kernloom-demo/klshield-config",
		BasePath:           "envs/prod",
		ChangedPaths:       []string{"envs/prod/runtime.yaml"},
	})
	if result.Status != "failed" {
		t.Fatalf("expected failed validation, got %#v", result)
	}
	if !hasFinding(result, "config_snapshot_unavailable") {
		t.Fatalf("expected config_snapshot_unavailable finding, got %#v", result.Findings)
	}
}

func TestValidateCIFailsClosedWhenRepoUnknown(t *testing.T) {
	result := ValidateCI(CIOptions{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		Tenant:             "kernloom-demo",
		Environment:        "prod",
		Provider:           "github",
		Repository:         "kernloom-demo/unknown-config",
		BasePath:           "envs/prod",
	})
	if result.Status != "failed" {
		t.Fatalf("expected failed validation, got %#v", result)
	}
	if !hasFinding(result, "repo_not_registered") {
		t.Fatalf("expected repo_not_registered finding, got %#v", result.Findings)
	}
}

func TestValidateCIPassesWithKLShieldConfigSnapshot(t *testing.T) {
	snapshot := t.TempDir()
	configPath := filepath.Join(snapshot, "envs", "prod", "runtime.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`kind: KLShieldRuntimeConfig
runtime_actions:
  - capability: enforce.runtime.rate_limit_entity
    selector:
      type: selector.klshield.entity.v1
      entity_type: entity_type.network_source
    controls:
      - runtime_action_applied
      - runtime_action_readback
    proof:
      expected_events:
        - event.runtime_action_applied
        - event.runtime_action_readback
`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := ValidateCI(CIOptions{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		Tenant:             "kernloom-demo",
		Environment:        "prod",
		Provider:           "github",
		Repository:         "kernloom-demo/klshield-config",
		BasePath:           "envs/prod",
		ChangedPaths:       []string{"envs/prod/runtime.yaml"},
		ConfigSnapshot:     snapshot,
	})
	if result.Status != "passed" {
		t.Fatalf("expected passed validation, got %#v", result)
	}
}

func TestValidateCIFailsClosedWhenAdapterVerifyTransportInvalid(t *testing.T) {
	result := ValidateCI(CIOptions{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		Tenant:             "kernloom-demo",
		Environment:        "prod",
		Provider:           "github",
		Repository:         "kernloom-demo/klshield-config",
		BasePath:           "envs/prod",
		AdapterVerify: AdapterVerifyOptions{
			Endpoint: "adapter.example:443",
			Timeout:  time.Millisecond,
		},
	})

	if result.Status != "failed" {
		t.Fatalf("expected failed validation, got %#v", result)
	}
	if result.AdapterRuntime == nil || result.AdapterRuntime.Status != "failed" {
		t.Fatalf("expected adapter runtime verify failure, got %#v", result.AdapterRuntime)
	}
	if !hasFinding(result, "adapter_runtime_verify_failed") {
		t.Fatalf("expected adapter_runtime_verify_failed finding, got %#v", result.Findings)
	}
}

func TestValidateCIFailsWhenKLShieldConfigDoesNotEnforceBindingSelector(t *testing.T) {
	snapshot := t.TempDir()
	configPath := filepath.Join(snapshot, "envs", "prod", "runtime.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`kind: KLShieldRuntimeConfig
runtime_actions:
  - capability: enforce.runtime.rate_limit_entity
    selector:
      type: selector.klshield.entity.v1
      entity_type: entity_type.other
    controls:
      - runtime_action_applied
    proof:
      expected_events:
        - event.runtime_action_applied
`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := ValidateCI(CIOptions{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
		Tenant:             "kernloom-demo",
		Environment:        "prod",
		Provider:           "github",
		Repository:         "kernloom-demo/klshield-config",
		BasePath:           "envs/prod",
		ChangedPaths:       []string{"envs/prod/runtime.yaml"},
		ConfigSnapshot:     snapshot,
	})
	if result.Status != "failed" {
		t.Fatalf("expected failed validation, got %#v", result)
	}
	if !hasFinding(result, "binding_selector_not_enforced") {
		t.Fatalf("expected binding_selector_not_enforced finding, got %#v", result.Findings)
	}
}

func TestValidateBindingReportsConfigPathFindings(t *testing.T) {
	catalog, store, resolved, manifest := validationContext(t)
	resolvedBinding := resolved.Bindings[0]
	resolvedBinding.Binding.Selector = nil
	resolvedBinding.Binding.Controls = nil
	resolvedBinding.Binding.Proof.ExpectedEvents = []string{"event.runtime_action_applied"}

	result := CIValidationResult{Findings: []Finding{}, Provenance: map[string]string{}}
	result.validateBinding(catalog, manifest, store, resolved.Target.Target, resolvedBinding)

	for _, code := range []string{"binding_selector_not_enforced", "required_control_missing"} {
		if !hasFinding(result, code) {
			t.Fatalf("expected %s finding, got %#v", code, result.Findings)
		}
	}
}

func TestValidateBindingReportsMissingCanonicalActionMapping(t *testing.T) {
	catalog, store, resolved, manifest := validationContext(t)
	resolvedBinding := resolved.Bindings[0]
	resolvedBinding.Action.CanonicalAction = ""

	result := CIValidationResult{Findings: []Finding{}, Provenance: map[string]string{}}
	result.validateBinding(catalog, manifest, store, resolved.Target.Target, resolvedBinding)

	if !hasFinding(result, "missing_canonical_action_mapping") {
		t.Fatalf("expected missing_canonical_action_mapping finding, got %#v", result.Findings)
	}
}

func TestValidatePolicyBindingMatchesReportsUnmappedSensitiveAction(t *testing.T) {
	catalog, store, resolved, _ := validationContext(t)
	for i := range resolved.PolicySources {
		resolved.PolicySources[i].Source.PolicyMeanings = nil
	}

	result := CIValidationResult{Findings: []Finding{}}
	result.validatePolicyBindingMatches(catalog, store, resolved)

	if !hasFinding(result, "unmapped_sensitive_action") {
		t.Fatalf("expected unmapped_sensitive_action finding, got %#v", result.Findings)
	}
}

func TestValidateResolvedTargetReportsBindingCapabilityNotImplemented(t *testing.T) {
	catalog, store, resolved, manifest := validationContext(t)
	for i := range manifest.Capabilities {
		if manifest.Capabilities[i].CapabilityID == "enforce.runtime.rate_limit_entity" {
			manifest.Capabilities[i].ImplementationStatus = "planned"
		}
	}

	result := CIValidationResult{Findings: []Finding{}, Provenance: map[string]string{}}
	result.validateResolvedTarget(catalog, map[string]compiler.AdapterManifest{
		resolved.Target.Target.Adapter: manifest,
	}, store, resolved)

	if !hasFinding(result, "adapter_capability_not_implemented") {
		t.Fatalf("expected adapter_capability_not_implemented finding, got %#v", result.Findings)
	}
}

func validationContext(t *testing.T) (*registry.Catalog, bindings.Store, bindings.ResolvedTarget, compiler.AdapterManifest) {
	t.Helper()
	catalog, err := registry.Load(testdataPath("core-registry"), testdataPath("enterprise-registry"))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	store, err := bindings.Load(testdataPath("policy-repo"), testdataPath("enterprise-registry"))
	if err != nil {
		t.Fatalf("load bindings: %v", err)
	}
	resolved, err := store.ResolveCIRequest(bindings.CIRequest{
		Tenant:      "kernloom-demo",
		Environment: "prod",
		Provider:    "github",
		Repository:  "kernloom-demo/klshield-config",
		BasePath:    "envs/prod",
	})
	if err != nil {
		t.Fatalf("resolve ci request: %v", err)
	}
	manifests, err := compiler.LoadAdapterManifests(compiler.Options{
		PolicyRepo:         testdataPath("policy-repo"),
		CoreRegistry:       testdataPath("core-registry"),
		EnterpriseRegistry: testdataPath("enterprise-registry"),
	})
	if err != nil {
		t.Fatalf("load adapter manifests: %v", err)
	}
	manifest, ok := manifests[resolved.Target.Target.Adapter]
	if !ok {
		t.Fatalf("missing adapter manifest for %q", resolved.Target.Target.Adapter)
	}
	return catalog, store, resolved, manifest
}

func hasFinding(result CIValidationResult, code string) bool {
	for _, finding := range result.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func testdataPath(name string) string {
	return "../testdata/" + name
}
