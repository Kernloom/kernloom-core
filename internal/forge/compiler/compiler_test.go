// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
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
		filepath.Join(out, "signed", "access.protect-production-admin-access.policy_build_manifest.signed.json"),
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
	for adapterID, adapter := range manifest.Spec.Adapters {
		if adapter.ManifestDigest == "" {
			t.Fatalf("expected real adapter digest for %s, got %#v", adapterID, adapter)
		}
	}
	verifier, err := signing.LoadDevLocalVerifier(filepath.Join(out, "keys", "dev-local.ed25519.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kliqbundle.LoadSignedRuntimeBundle(context.Background(), results[0].RuntimeBundleSignedPath, verifier); err != nil {
		t.Fatal(err)
	}
	manifestEnvelopeData, err := os.ReadFile(results[0].ManifestSignedPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifestEnvelope signing.SignedEnvelope
	if err := json.Unmarshal(manifestEnvelopeData, &manifestEnvelope); err != nil {
		t.Fatal(err)
	}
	if result, err := verifier.Verify(context.Background(), manifestEnvelope); err != nil || !result.Valid {
		t.Fatalf("expected signed policy build manifest to verify, result=%#v err=%v", result, err)
	}
}

func TestCompileRuntimeGrantResolvesThroughCatalogBindingAndManifest(t *testing.T) {
	policyRepo := t.TempDir()
	policyDir := filepath.Join(policyRepo, "policies", "runtime")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "rate-limit.intent.kni")
	if err := os.WriteFile(policyPath, []byte(`intent "runtime.rate-limit" {
  version = "kni/v0.5"
  owner   = "security-platform"
  type    = "runtime_mitigation"
  target  = "klshield"
  stage   = "prod"

  profile     = "production.runtime_mitigation"
  risk_recipe = "runtime_anomaly.standard"

  rule "rate limit abnormal source" {
    effect   = "rate_limit"
    subject  = "network source"
    action   = "connect"
    resource = "production application"

    only_when = [
      "device is healthy"
    ]
  }

  runtime {
    allowed   = true
    actions   = ["rate_limit"]
    max_ttl   = "10m"
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

	data, err := os.ReadFile(filepath.Join(out, "artifacts", "runtime.rate-limit.runtime_bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var runtimeBundle corebundle.RuntimeBundle
	if err := json.Unmarshal(data, &runtimeBundle); err != nil {
		t.Fatal(err)
	}
	if len(runtimeBundle.Spec.CapabilityGrants) != 1 {
		t.Fatalf("expected one capability grant, got %#v", runtimeBundle.Spec.CapabilityGrants)
	}
	grant := runtimeBundle.Spec.CapabilityGrants[0]
	if grant.AdapterID != "kernloom.adapter.klshield" {
		t.Fatalf("expected adapter binding to select KLShield, got %q", grant.AdapterID)
	}
	if grant.CapabilityID != "enforce.runtime.rate_limit_entity" {
		t.Fatalf("expected canonical capability grant, got %q", grant.CapabilityID)
	}
	if grant.ActionType != "runtime_action.rate_limit_source" {
		t.Fatalf("expected compatibility runtime action alias to remain explicit, got %q", grant.ActionType)
	}
	if grant.BindingID == "" || grant.BindingDigest == "" {
		t.Fatalf("expected binding provenance on grant, got %#v", grant)
	}
	if grant.AdapterManifestDigest == "" || grant.ActionDigest == "" {
		t.Fatalf("expected adapter/action digests on grant, got %#v", grant)
	}

	manifestData, err := os.ReadFile(filepath.Join(out, "reports", "runtime.rate-limit.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest PolicyBuildManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	adapter, ok := manifest.Spec.Adapters["kernloom.adapter.klshield"]
	if !ok {
		t.Fatalf("expected KLShield adapter manifest ref, got %#v", manifest.Spec.Adapters)
	}
	if adapter.ManifestDigest == "" || adapter.ManifestDigest == "sha256:unavailable" {
		t.Fatalf("expected adapter manifest digest, got %#v", adapter)
	}
	if adapter.SignedManifest.ArtifactRef.URI == "" || adapter.SignedManifest.EnvelopeSHA256 == "" {
		t.Fatalf("expected signed adapter manifest artifact ref, got %#v", adapter)
	}
	if manifest.Spec.SignedOutputs["adapter_manifest:kernloom.adapter.klshield"].ArtifactRef.URI == "" {
		t.Fatalf("expected adapter manifest signed output, got %#v", manifest.Spec.SignedOutputs)
	}
	if _, ok := manifest.Spec.Bindings[grant.BindingID]; !ok {
		t.Fatalf("expected binding ref %q in policy build manifest, got %#v", grant.BindingID, manifest.Spec.Bindings)
	}
	actionRef, ok := manifest.Spec.RuntimeActions[grant.ID]
	if !ok {
		t.Fatalf("expected runtime action ref for grant %q, got %#v", grant.ID, manifest.Spec.RuntimeActions)
	}
	if actionRef.ActionDigest != grant.ActionDigest || actionRef.BindingID != grant.BindingID {
		t.Fatalf("expected runtime action ref to mirror grant provenance, ref=%#v grant=%#v", actionRef, grant)
	}
}

func TestLoadAdapterManifestsPrefersExplicitWorkspaceRoot(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	coreRoot := filepath.Join(workspace, "kernloom-core")
	explicitRoot := filepath.Join(coreRoot, "internal", "forge", "testdata")
	for _, dir := range []string{
		coreRoot,
		filepath.Join(explicitRoot, "policy-repo"),
		filepath.Join(explicitRoot, "core-registry"),
		filepath.Join(explicitRoot, "enterprise-registry"),
		filepath.Join(explicitRoot, "kernloom-adapter-klshield"),
		filepath.Join(workspace, "kernloom-adapter-klshield"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	explicitManifest := filepath.Join(explicitRoot, "kernloom-adapter-klshield", "adapter.manifest.yaml")
	fallbackManifest := filepath.Join(workspace, "kernloom-adapter-klshield", "adapter.manifest.yaml")
	writeAdapterManifestForTest(t, explicitManifest, "0.1.0-explicit")
	writeAdapterManifestForTest(t, fallbackManifest, "0.1.0-fallback")
	if err := os.Chdir(coreRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	manifests, err := LoadAdapterManifests(Options{
		PolicyRepo:         filepath.Join("internal", "forge", "testdata", "policy-repo"),
		CoreRegistry:       filepath.Join("internal", "forge", "testdata", "core-registry"),
		EnterpriseRegistry: filepath.Join("internal", "forge", "testdata", "enterprise-registry"),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, ok := manifests["kernloom.adapter.klshield"]
	if !ok {
		t.Fatalf("expected KLShield manifest, got %#v", manifests)
	}
	if manifest.AdapterVersion != "0.1.0-explicit" {
		t.Fatalf("expected explicit workspace manifest to win, got %#v", manifest)
	}
	if manifest.Path != explicitManifest {
		t.Fatalf("expected explicit manifest path %q, got %q", explicitManifest, manifest.Path)
	}
}

func TestValidateAdapterRuntimeDescribeMatchesManifest(t *testing.T) {
	manifest := adapterRuntimeManifestForTest()
	describe := AdapterRuntimeDescribe{
		ManifestDigest: manifest.Digest,
		Descriptor:     adapterRuntimeDescriptorForTest(manifest),
	}

	if err := ValidateAdapterRuntimeDescribe(manifest, describe); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAdapterRuntimeDescribeRejectsDigestMismatch(t *testing.T) {
	manifest := adapterRuntimeManifestForTest()
	describe := AdapterRuntimeDescribe{
		ManifestDigest: "sha256:" + strings.Repeat("0", 64),
		Descriptor:     adapterRuntimeDescriptorForTest(manifest),
	}

	err := ValidateAdapterRuntimeDescribe(manifest, describe)
	if err == nil {
		t.Fatal("expected manifest digest mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Fatalf("expected manifest digest mismatch error, got %v", err)
	}
}

func TestValidateAdapterRuntimeDescribeRejectsMissingCapability(t *testing.T) {
	manifest := adapterRuntimeManifestForTest()
	desc := adapterRuntimeDescriptorForTest(manifest)
	desc.Capabilities = nil

	err := ValidateAdapterRuntimeDescribe(manifest, AdapterRuntimeDescribe{Descriptor: desc})
	if err == nil || !strings.Contains(err.Error(), "omits implemented capability") {
		t.Fatalf("expected missing capability error, got %v", err)
	}
}

func TestValidateAdapterRuntimeDescribeRejectsMissingRuntimeAction(t *testing.T) {
	manifest := adapterRuntimeManifestForTest()
	desc := adapterRuntimeDescriptorForTest(manifest)
	desc.Capabilities[0].RuntimeActions = []string{"runtime_action.rate_limit_entity"}

	err := ValidateAdapterRuntimeDescribe(manifest, AdapterRuntimeDescribe{Descriptor: desc})
	if err == nil || !strings.Contains(err.Error(), "omits manifest action") {
		t.Fatalf("expected missing runtime action error, got %v", err)
	}
}

func TestValidateAdapterRuntimeDescribeRejectsMissingPrivilege(t *testing.T) {
	manifest := adapterRuntimeManifestForTest()
	desc := adapterRuntimeDescriptorForTest(manifest)
	desc.Privileges[0].Id = "privilege.bpf.map.other"

	err := ValidateAdapterRuntimeDescribe(manifest, AdapterRuntimeDescribe{Descriptor: desc})
	if err == nil || !strings.Contains(err.Error(), "omits manifest privilege") {
		t.Fatalf("expected missing privilege error, got %v", err)
	}
}

func TestValidateAdapterRuntimeDescribeRejectsProtocolVersionMismatch(t *testing.T) {
	manifest := adapterRuntimeManifestForTest()
	desc := adapterRuntimeDescriptorForTest(manifest)
	desc.ProtocolVersion = "adapter/v0"

	err := ValidateAdapterRuntimeDescribe(manifest, AdapterRuntimeDescribe{Descriptor: desc})
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("expected protocol version mismatch error, got %v", err)
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

func writeAdapterManifestForTest(t *testing.T, path, version string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`adapter_id: kernloom.adapter.klshield
adapter_version: `+version+`
protocol_version: adapter/v1
status: stable
capabilities:
  - capability_id: enforce.runtime.rate_limit_entity
    implementation_status: implemented
`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func adapterRuntimeManifestForTest() AdapterManifest {
	manifest := AdapterManifest{
		AdapterID:       "kernloom.adapter.klshield",
		AdapterVersion:  "0.1.0",
		ProtocolVersion: adapterv1.ProtocolVersion,
		Status:          "stable",
		Capabilities: []AdapterManifestCapability{
			{
				CapabilityID:         "enforce.runtime.rate_limit_entity",
				ImplementationStatus: "implemented",
				SupportedActions: []string{
					"runtime_action.rate_limit_entity",
					"runtime_action.rate_limit_source",
				},
				RequiredPrivileges: []string{"privilege.bpf.map.write"},
			},
		},
		Privileges: []AdapterManifestPrivilege{{PrivilegeID: "privilege.bpf.map.write"}},
	}
	manifest.Digest = digestJSON(manifest)
	return manifest
}

func adapterRuntimeDescriptorForTest(manifest AdapterManifest) *adapterv1.AdapterDescriptor {
	return &adapterv1.AdapterDescriptor{
		AdapterId:       manifest.AdapterID,
		Name:            "Kernloom KLShield Adapter",
		ProtocolVersion: manifest.ProtocolVersion,
		ManifestDigest:  manifest.Digest,
		Capabilities: []*adapterv1.CapabilityDescriptor{
			{
				Id:             "enforce.runtime.rate_limit_entity",
				Kind:           "runtime_executor",
				RuntimeActions: []string{"runtime_action.rate_limit_entity", "runtime_action.rate_limit_source"},
			},
		},
		ContextRequirements: []*adapterv1.ContextRequirementDescriptor{
			{Fact: "runtime bundle is signed", Freshness: "bundle_expiry", Confidence: "verified", Sensitivity: "runtime"},
		},
		Privileges: []*adapterv1.PrivilegeDescriptor{
			{Id: "privilege.bpf.map.write", Reason: "Write approved runtime actions.", Scope: "local_node", Access: "write_bpf_map"},
		},
		Facets: []string{adapterv1.FacetDescribe, adapterv1.FacetHealth},
		FacetDescriptors: []*adapterv1.FacetDescriptor{
			{Name: adapterv1.FacetDescribe, Status: adapterv1.FacetStatusImplemented},
			{Name: adapterv1.FacetHealth, Status: adapterv1.FacetStatusImplemented},
		},
	}
}
