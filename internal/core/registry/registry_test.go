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
`)
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
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "profiles.yaml"), `kind: ProfileSet
spec:
  profiles: []
`)
	writeRegistryFile(t, filepath.Join(coreRegistry, "defaults", "risk_recipes.yaml"), `kind: RiskRecipeSet
spec:
  recipes: []
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

	_, err := Load(coreRegistry, enterpriseRegistry)
	if err == nil {
		t.Fatal("expected duplicate enterprise label/kind to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate label/kind") {
		t.Fatalf("expected duplicate label/kind error, got %v", err)
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
