// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadIncludesEnterpriseAliasesAndInheritedProfiles(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")
	enterpriseRegistry := filepath.Join(root, "enterprise-kernloom-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: production application
      canonical_id: resource.production_application
      kind: resource
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "profiles.yaml"), `kind: ProfileSet
spec:
  profiles:
    - id: production.high_assurance_access
      stage: prod
      guardrails:
        - guardrail.unknown_is_not_success
      runtime_defaults:
        max_ttl: 15m
        max_scope: user
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "risk_recipes.yaml"), `kind: RiskRecipeSet
spec:
  recipes: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "guardrails.yaml"), `kind: GuardrailPack
spec:
  guardrails:
    - id: guardrail.unknown_is_not_success
      mode: block
`)
	writeRegistryFile(t, filepath.Join(enterpriseRegistry, "enterprise", "vocabulary.yaml"), `kind: EnterpriseVocabulary
spec:
  terms:
    - id: enterprise.resource.production_admin_application
      label: production admin application
      aliases:
        - prod admin app
`)
	writeRegistryFile(t, filepath.Join(enterpriseRegistry, "enterprise", "profiles.yaml"), `kind: EnterpriseProfileSet
spec:
  profiles:
    - id: production.high_assurance_access
      mode: inherited
      owner: security-platform
`)
	writeRegistryFile(t, filepath.Join(enterpriseRegistry, "bindings", "adapter_bindings.yaml"), `kind: AdapterBindingSet
spec:
  bindings: []
`)

	catalog, err := Load(coreRegistry, enterpriseRegistry)
	if err != nil {
		t.Fatal(err)
	}
	value, err := catalog.Resolve("prod admin app", "resource")
	if err != nil {
		t.Fatal(err)
	}
	if value.CanonicalID != "enterprise.resource.production_admin_application" {
		t.Fatalf("expected alias to resolve to enterprise term, got %q", value.CanonicalID)
	}
	profile, ok := catalog.Profile("production.high_assurance_access")
	if !ok {
		t.Fatal("expected inherited enterprise profile to be loaded")
	}
	if profile.Owner != "security-platform" || profile.Mode != "inherited" {
		t.Fatalf("expected enterprise profile provenance, got owner=%q mode=%q", profile.Owner, profile.Mode)
	}
	if profile.RuntimeDefaults["max_ttl"] != "15m" || profile.RuntimeDefaults["max_scope"] != "user" {
		t.Fatalf("expected core runtime defaults to survive inheritance, got %#v", profile.RuntimeDefaults)
	}
}

func TestLoadRejectsEnterpriseDuplicateLabelKind(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")
	enterpriseRegistry := filepath.Join(root, "enterprise-kernloom-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: production admin application
      canonical_id: resource.production_admin_application
      kind: resource
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "profiles.yaml"), `kind: ProfileSet
spec:
  profiles: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "risk_recipes.yaml"), `kind: RiskRecipeSet
spec:
  recipes: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "guardrails.yaml"), `kind: GuardrailPack
spec:
  guardrails: []
`)
	writeRegistryFile(t, filepath.Join(enterpriseRegistry, "enterprise", "vocabulary.yaml"), `kind: EnterpriseVocabulary
spec:
  terms:
    - id: enterprise.resource.production_admin_application
      label: production admin application
`)
	writeRegistryFile(t, filepath.Join(enterpriseRegistry, "enterprise", "profiles.yaml"), `kind: EnterpriseProfileSet
spec:
  profiles: []
`)
	writeRegistryFile(t, filepath.Join(enterpriseRegistry, "bindings", "adapter_bindings.yaml"), `kind: AdapterBindingSet
spec:
  bindings: []
`)

	_, err := Load(coreRegistry, enterpriseRegistry)
	if err == nil {
		t.Fatal("expected duplicate enterprise label/kind to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate label/kind") {
		t.Fatalf("expected duplicate label/kind error, got %v", err)
	}
}

func TestLoadRejectsUnknownProfileGuardrail(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "profiles.yaml"), `kind: ProfileSet
spec:
  profiles:
    - id: production.high_assurance_access
      stage: prod
      guardrails:
        - guardrail.missing
      runtime_defaults:
        max_ttl: 15m
        max_scope: user
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "risk_recipes.yaml"), `kind: RiskRecipeSet
spec:
  recipes: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "guardrails.yaml"), `kind: GuardrailPack
spec:
  guardrails:
    - id: guardrail.unknown_is_not_success
      mode: block
`)

	_, err := Load(coreRegistry, "")
	if err == nil {
		t.Fatal("expected unknown profile guardrail to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown guardrail") {
		t.Fatalf("expected unknown guardrail error, got %v", err)
	}
}

func TestLoadRejectsCompilerRuleUnknownRuntimeAction(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values: []
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeMinimalDefaults(t, coreRegistry)

	_, err := Load(coreRegistry, "")
	if err == nil {
		t.Fatal("expected unknown compiler-rule runtime action to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown runtime action") {
		t.Fatalf("expected unknown runtime action error, got %v", err)
	}
}

func TestLoadRejectsCompilerRuleMissingRuntimeActionBySchema(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeMinimalDefaults(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "compiler_rule_catalog.yaml"), `kind: CompilerRuleCatalog
spec:
  rules:
    - id: compiler_rule.runtime_action.rate_limit_source.compat.v1
      capability_ids:
        - enforce.runtime.rate_limit_entity
`)

	_, err := Load(coreRegistry, "")
	if err == nil {
		t.Fatal("expected missing runtime_action to be rejected by schema")
	}
	if !strings.Contains(err.Error(), "missing required property") || !strings.Contains(err.Error(), "runtime_action") {
		t.Fatalf("expected missing runtime_action schema error, got %v", err)
	}
}

func TestLoadRejectsUnknownCapabilityCatalogFieldBySchema(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeMinimalDefaults(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "capability_catalog.yaml"), `kind: CapabilityCatalog
spec:
  capabilities:
    - id: enforce.runtime.rate_limit_entity
      kind: enforce_runtime
      status: stable
      supported_actions:
        - runtime_action.rate_limit_entity
      compatibility_aliases:
        - runtime_action.rate_limit_source
      drifted_field: should_fail
`)

	_, err := Load(coreRegistry, "")
	if err == nil {
		t.Fatal("expected unknown capability catalog field to be rejected by schema")
	}
	if !strings.Contains(err.Error(), "additional property") || !strings.Contains(err.Error(), "drifted_field") {
		t.Fatalf("expected additional property schema error, got %v", err)
	}
}

func TestLoadRejectsAdapterRawSignalInCoreSignalCatalog(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeMinimalDefaults(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "signal_catalog.yaml"), `kind: SignalCatalog
spec:
  entries:
    - id: signal.klshield.raw_entity_counters
`)

	_, err := Load(coreRegistry, "")
	if err == nil {
		t.Fatal("expected adapter raw signal in core catalog to be rejected")
	}
	if !strings.Contains(err.Error(), "generic boundary") {
		t.Fatalf("expected generic boundary error, got %v", err)
	}
}

func TestLoadRejectsRequirementUnknownCapability(t *testing.T) {
	root := t.TempDir()
	coreRegistry := filepath.Join(root, "kernloom-core-registry")

	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "authoring_catalog.yaml"), `kind: AuthoringCatalog
metadata:
  version: vtest
spec:
  values:
    - label: rate_limit
      canonical_id: runtime_action.rate_limit_source
      kind: runtime_action
`)
	writeMinimalCapabilityFiles(t, coreRegistry)
	writeMinimalDefaults(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "requirement_catalog.yaml"), `kind: RequirementCatalog
spec:
  entries:
    - id: requirement.runtime_mitigation
      required_capabilities:
        - enforce.runtime.missing
`)

	_, err := Load(coreRegistry, "")
	if err == nil {
		t.Fatal("expected unknown requirement capability to be rejected")
	}
	if !strings.Contains(err.Error(), "references unknown capability") {
		t.Fatalf("expected unknown capability error, got %v", err)
	}
}

func writeMinimalCapabilityFiles(t *testing.T, coreRegistry string) {
	t.Helper()
	writeMinimalSchemas(t, coreRegistry)
	writeMinimalSupplementalCatalogs(t, coreRegistry)
	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "capability_catalog.yaml"), `kind: CapabilityCatalog
spec:
  capabilities:
    - id: enforce.runtime.rate_limit_entity
      kind: enforce_runtime
      status: stable
      supported_actions:
        - runtime_action.rate_limit_entity
      compatibility_aliases:
        - runtime_action.rate_limit_source
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "core", "compiler_rule_catalog.yaml"), `kind: CompilerRuleCatalog
spec:
  rules:
    - id: compiler_rule.runtime_action.rate_limit_source.compat.v1
      runtime_action: runtime_action.rate_limit_source
      capability_ids:
        - enforce.runtime.rate_limit_entity
`)
}

func writeMinimalSchemas(t *testing.T, coreRegistry string) {
	t.Helper()
	schemaRoot := filepath.Join("..", "..", "forge", "testdata", "core-registry", "schemas")
	for _, name := range requiredSchemaFiles {
		data, err := os.ReadFile(filepath.Join(schemaRoot, name))
		if err != nil {
			t.Fatalf("read schema fixture %s: %v", name, err)
		}
		writeRegistryFile(t, filepath.Join(coreRegistry, "schemas", name), string(data))
	}
}

func writeMinimalDefaults(t *testing.T, coreRegistry string) {
	t.Helper()
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "profiles.yaml"), `kind: ProfileSet
spec:
  profiles: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "risk_recipes.yaml"), `kind: RiskRecipeSet
spec:
  recipes: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "guardrails.yaml"), `kind: GuardrailPack
spec:
  guardrails: []
`)
}

func writeMinimalSupplementalCatalogs(t *testing.T, coreRegistry string) {
	t.Helper()
	files := map[string]string{
		"signal_catalog.yaml": `kind: SignalCatalog
spec:
  entries:
    - id: signal.runtime_action_state_summary
`,
		"metric_catalog.yaml": `kind: MetricCatalog
spec:
  entries:
    - id: metric.entity_activity
`,
		"granularity_catalog.yaml": `kind: GranularityCatalog
spec:
  entries:
    - id: granularity.entity
`,
		"entity_type_catalog.yaml": `kind: EntityTypeCatalog
spec:
  entries:
    - id: entity_type.network_source
`,
		"action_type_catalog.yaml": `kind: ActionTypeCatalog
spec:
  entries:
    - id: action_type.runtime_mitigation
`,
		"evidence_catalog.yaml": `kind: EvidenceCatalog
spec:
  entries:
    - id: evidence.runtime_action_readback
`,
		"privilege_catalog.yaml": `kind: PrivilegeCatalog
spec:
  entries:
    - id: privilege.bpf.map.write
`,
		"state_catalog.yaml": `kind: StateCatalog
spec:
  entries:
    - id: state.runtime_action
`,
		"event_catalog.yaml": `kind: EventCatalog
spec:
  entries:
    - id: event.runtime_action_applied
`,
		"context_catalog.yaml": `kind: ContextCatalog
spec:
  entries:
    - id: context.runtime_action.selector
`,
		"component_role_catalog.yaml": `kind: ComponentRoleCatalog
spec:
  entries:
    - id: component_role.adapter
`,
		"requirement_catalog.yaml": `kind: RequirementCatalog
spec:
  entries:
    - id: requirement.runtime_mitigation
`,
		"selector_schema_catalog.yaml": `kind: SelectorSchemaCatalog
spec:
  entries:
    - id: selector.klshield.entity.v1
`,
		"validation_profile_catalog.yaml": `kind: ValidationProfileCatalog
spec:
  entries:
    - id: validation.klshield.runtime_action.v1
`,
	}
	for name, contents := range files {
		writeRegistryFile(t, filepath.Join(coreRegistry, "core", name), contents)
	}
}

func writeRegistryFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
