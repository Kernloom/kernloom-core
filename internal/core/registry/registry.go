// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Catalog struct {
	Values                 []Value
	Capabilities           map[string]CapabilitySpec
	CompilerRules          map[string]CompilerRuleSpec
	AdapterBindings        []AdapterBinding
	SupplementalCatalogs   map[string]SupplementalCatalog
	Profiles               map[string]Profile
	RiskRecipes            map[string]RiskRecipe
	Guardrails             map[string]Guardrail
	CoreVersion            string
	byLabel                map[string][]Value
	byLabelKind            map[string]Value
	bySupplementalEntryID  map[string]CatalogEntry
	bySupplementalEntryKey map[string]CatalogEntry
}

type Value struct {
	Label       string `yaml:"label" json:"label"`
	CanonicalID string `yaml:"canonical_id" json:"canonical_id"`
	Kind        string `yaml:"kind" json:"kind"`
	CEL         string `yaml:"cel,omitempty" json:"cel,omitempty"`
}

type Profile struct {
	ID              string            `yaml:"id" json:"id"`
	Mode            string            `yaml:"mode,omitempty" json:"mode,omitempty"`
	Owner           string            `yaml:"owner,omitempty" json:"owner,omitempty"`
	Stage           string            `yaml:"stage" json:"stage"`
	Guardrails      []string          `yaml:"guardrails" json:"guardrails"`
	RuntimeDefaults map[string]string `yaml:"runtime_defaults" json:"runtime_defaults"`
}

type RiskRecipe struct {
	ID         string            `yaml:"id" json:"id"`
	Output     map[string]string `yaml:"output" json:"output"`
	Scoring    map[string]string `yaml:"scoring" json:"scoring"`
	Thresholds map[string]string `yaml:"thresholds" json:"thresholds"`
	Confidence map[string]string `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Freshness  map[string]string `yaml:"freshness,omitempty" json:"freshness,omitempty"`
}

type Guardrail struct {
	ID          string `yaml:"id" json:"id"`
	Mode        string `yaml:"mode" json:"mode"`
	Description string `yaml:"description" json:"description"`
}

type CapabilitySpec struct {
	ID                     string           `yaml:"id" json:"id"`
	Kind                   string           `yaml:"kind" json:"kind"`
	Status                 string           `yaml:"status" json:"status"`
	Semantic               string           `yaml:"semantic,omitempty" json:"semantic,omitempty"`
	SupportedActions       []string         `yaml:"supported_actions,omitempty" json:"supported_actions,omitempty"`
	CompatibilityAliases   []string         `yaml:"compatibility_aliases,omitempty" json:"compatibility_aliases,omitempty"`
	SupportedGranularities []string         `yaml:"supported_granularities,omitempty" json:"supported_granularities,omitempty"`
	TargetScopes           []string         `yaml:"target_scopes,omitempty" json:"target_scopes,omitempty"`
	ContextRequirements    []string         `yaml:"context_requirements,omitempty" json:"context_requirements,omitempty"`
	PrivilegeRequirements  []string         `yaml:"privilege_requirements,omitempty" json:"privilege_requirements,omitempty"`
	EvidenceRequirements   []string         `yaml:"evidence_requirements,omitempty" json:"evidence_requirements,omitempty"`
	FailureSemantics       FailureSemantics `yaml:"failure_semantics,omitempty" json:"failure_semantics,omitempty"`
}

type FailureSemantics struct {
	UnknownIsSuccess *bool `yaml:"unknown_is_success,omitempty" json:"unknown_is_success,omitempty"`
}

type CompilerRuleSpec struct {
	ID            string   `yaml:"id" json:"id"`
	RuntimeAction string   `yaml:"runtime_action,omitempty" json:"runtime_action,omitempty"`
	RequirementID string   `yaml:"requirement_id,omitempty" json:"requirement_id,omitempty"`
	CapabilityIDs []string `yaml:"capability_ids,omitempty" json:"capability_ids,omitempty"`
}

type AdapterBinding struct {
	BindingID            string   `yaml:"binding_id,omitempty" json:"binding_id,omitempty"`
	Digest               string   `yaml:"digest,omitempty" json:"digest,omitempty"`
	CapabilityID         string   `yaml:"capability_id" json:"capability_id"`
	AdapterID            string   `yaml:"adapter_id" json:"adapter_id"`
	Environments         []string `yaml:"environments,omitempty" json:"environments,omitempty"`
	Stages               []string `yaml:"stages,omitempty" json:"stages,omitempty"`
	ImplementationStatus string   `yaml:"implementation_status,omitempty" json:"implementation_status,omitempty"`
	RequiredGrantProfile string   `yaml:"required_grant_profile,omitempty" json:"required_grant_profile,omitempty"`
}

type SupplementalCatalog struct {
	Name    string                  `json:"name"`
	Path    string                  `json:"path"`
	Kind    string                  `json:"kind"`
	Entries map[string]CatalogEntry `json:"entries"`
}

type CatalogEntry struct {
	ID                   string         `yaml:"id" json:"id"`
	Status               string         `yaml:"status,omitempty" json:"status,omitempty"`
	Kind                 string         `yaml:"kind,omitempty" json:"kind,omitempty"`
	Description          string         `yaml:"description,omitempty" json:"description,omitempty"`
	Schema               map[string]any `yaml:"schema,omitempty" json:"schema,omitempty"`
	RequiredMetrics      []string       `yaml:"required_metrics,omitempty" json:"required_metrics,omitempty"`
	RequiredSignals      []string       `yaml:"required_signals,omitempty" json:"required_signals,omitempty"`
	RequiredCapabilities []string       `yaml:"required_capabilities,omitempty" json:"required_capabilities,omitempty"`
	RequiredEvidence     []string       `yaml:"required_evidence,omitempty" json:"required_evidence,omitempty"`
	AllowedGranularities []string       `yaml:"allowed_granularities,omitempty" json:"allowed_granularities,omitempty"`
	UnknownBehavior      string         `yaml:"unknown_behavior,omitempty" json:"unknown_behavior,omitempty"`
}

type ResolveError struct {
	Code  string
	Label string
	Kinds []string
}

func (e ResolveError) Error() string {
	return fmt.Sprintf("%s: %q for kinds [%s]", e.Code, e.Label, strings.Join(e.Kinds, ", "))
}

func Load(coreRegistryPath, enterpriseRegistryPath string) (*Catalog, error) {
	if err := validateRequiredSchemas(coreRegistryPath); err != nil {
		return nil, err
	}
	if err := validateRegistryDocuments(coreRegistryPath, enterpriseRegistryPath); err != nil {
		return nil, err
	}
	catalog, err := loadCoreCatalog(filepath.Join(coreRegistryPath, "core", "authoring_catalog.yaml"))
	if err != nil {
		return nil, err
	}
	supplementalCatalogs, err := loadSupplementalCatalogs(coreRegistryPath)
	if err != nil {
		return nil, err
	}
	capabilities, err := loadCapabilities(filepath.Join(coreRegistryPath, "core", "capability_catalog.yaml"))
	if err != nil {
		return nil, err
	}
	compilerRules, err := loadCompilerRules(filepath.Join(coreRegistryPath, "core", "compiler_rule_catalog.yaml"))
	if err != nil {
		return nil, err
	}
	profiles, err := loadProfiles(filepath.Join(coreRegistryPath, "defaults", "profiles.yaml"))
	if err != nil {
		return nil, err
	}
	riskRecipes, err := loadRiskRecipes(filepath.Join(coreRegistryPath, "defaults", "risk_recipes.yaml"))
	if err != nil {
		return nil, err
	}
	guardrails, err := loadGuardrails(filepath.Join(coreRegistryPath, "defaults", "guardrails.yaml"))
	if err != nil {
		return nil, err
	}
	catalog.SupplementalCatalogs = supplementalCatalogs
	catalog.Capabilities = capabilities
	catalog.CompilerRules = compilerRules
	catalog.Profiles = profiles
	catalog.RiskRecipes = riskRecipes
	catalog.Guardrails = guardrails

	if enterpriseRegistryPath != "" {
		if err := catalog.loadEnterpriseVocabulary(filepath.Join(enterpriseRegistryPath, "enterprise", "vocabulary.yaml")); err != nil {
			return nil, err
		}
		if err := catalog.loadEnterpriseProfiles(filepath.Join(enterpriseRegistryPath, "enterprise", "profiles.yaml")); err != nil {
			return nil, err
		}
		adapterBindings, err := loadAdapterBindings(filepath.Join(enterpriseRegistryPath, "bindings", "adapter_bindings.yaml"))
		if err != nil {
			return nil, err
		}
		catalog.AdapterBindings = adapterBindings
	}
	catalog.reindex()
	if err := catalog.validateProfileGuardrails(); err != nil {
		return nil, err
	}
	if err := catalog.validateCapabilityReferences(); err != nil {
		return nil, err
	}
	return catalog, nil
}

func (c *Catalog) Resolve(label string, kinds ...string) (Value, error) {
	var candidates []Value
	allowed := map[string]bool{}
	for _, kind := range kinds {
		allowed[kind] = true
	}
	for _, value := range c.byLabel[label] {
		if len(allowed) == 0 || allowed[value.Kind] {
			candidates = append(candidates, value)
		}
	}
	switch len(candidates) {
	case 0:
		return Value{}, ResolveError{Code: "unknown_authoring_value", Label: label, Kinds: kinds}
	case 1:
		return candidates[0], nil
	default:
		return Value{}, ResolveError{Code: "ambiguous_authoring_value", Label: label, Kinds: kinds}
	}
}

func (c *Catalog) Profile(id string) (Profile, bool) {
	profile, ok := c.Profiles[id]
	return profile, ok
}

func (c *Catalog) RiskRecipe(id string) (RiskRecipe, bool) {
	recipe, ok := c.RiskRecipes[id]
	return recipe, ok
}

func (c *Catalog) RuntimeActionRule(actionType string) (CompilerRuleSpec, bool) {
	actionType = strings.TrimSpace(actionType)
	for _, rule := range c.CompilerRules {
		if strings.TrimSpace(rule.RuntimeAction) == actionType {
			return rule, true
		}
	}
	return CompilerRuleSpec{}, false
}

func (c *Catalog) Capability(id string) (CapabilitySpec, bool) {
	capability, ok := c.Capabilities[id]
	return capability, ok
}

func (c *Catalog) CatalogEntry(catalogName, id string) (CatalogEntry, bool) {
	entry, ok := c.bySupplementalEntryKey[supplementalEntryKey(catalogName, id)]
	return entry, ok
}

func (c *Catalog) HasRegistryID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	if _, ok := c.Capabilities[id]; ok {
		return true
	}
	if _, ok := c.bySupplementalEntryID[id]; ok {
		return true
	}
	for _, value := range c.Values {
		if strings.TrimSpace(value.CanonicalID) == id {
			return true
		}
	}
	for _, profile := range c.Profiles {
		if strings.TrimSpace(profile.ID) == id {
			return true
		}
	}
	for _, guardrail := range c.Guardrails {
		if strings.TrimSpace(guardrail.ID) == id {
			return true
		}
	}
	return false
}

func (c *Catalog) HasAuthoringCanonicalID(kind, id string) bool {
	kind = strings.TrimSpace(kind)
	id = strings.TrimSpace(id)
	if kind == "" || id == "" {
		return false
	}
	for _, value := range c.Values {
		if strings.TrimSpace(value.Kind) == kind && strings.TrimSpace(value.CanonicalID) == id {
			return true
		}
	}
	return false
}

func (c *Catalog) AdapterBinding(capabilityID, stage string) (AdapterBinding, bool) {
	capabilityID = strings.TrimSpace(capabilityID)
	stage = strings.TrimSpace(stage)
	for _, binding := range c.AdapterBindings {
		if strings.TrimSpace(binding.CapabilityID) != capabilityID {
			continue
		}
		if status := strings.TrimSpace(binding.ImplementationStatus); status != "" && status != "implemented" {
			continue
		}
		if len(binding.Stages) == 0 || containsString(binding.Stages, stage) {
			return binding, true
		}
	}
	return AdapterBinding{}, false
}

func (c *Catalog) reindex() {
	c.byLabel = map[string][]Value{}
	c.byLabelKind = map[string]Value{}
	c.bySupplementalEntryID = map[string]CatalogEntry{}
	c.bySupplementalEntryKey = map[string]CatalogEntry{}
	for _, value := range c.Values {
		c.byLabel[value.Label] = append(c.byLabel[value.Label], value)
		c.byLabelKind[labelKind(value.Label, value.Kind)] = value
	}
	for catalogName, catalog := range c.SupplementalCatalogs {
		for id, entry := range catalog.Entries {
			c.bySupplementalEntryID[id] = entry
			c.bySupplementalEntryKey[supplementalEntryKey(catalogName, id)] = entry
		}
	}
}

func (c *Catalog) addValue(value Value) error {
	if existing, ok := c.byLabelKind[labelKind(value.Label, value.Kind)]; ok {
		if existing.CanonicalID != value.CanonicalID {
			return fmt.Errorf("registry duplicate label/kind %q/%q maps to both %q and %q", value.Label, value.Kind, existing.CanonicalID, value.CanonicalID)
		}
		return nil
	}
	c.Values = append(c.Values, value)
	c.byLabel[value.Label] = append(c.byLabel[value.Label], value)
	c.byLabelKind[labelKind(value.Label, value.Kind)] = value
	return nil
}

func loadCoreCatalog(path string) (*Catalog, error) {
	var doc struct {
		Metadata struct {
			Version string `yaml:"version"`
		} `yaml:"metadata"`
		Spec struct {
			Values []Value `yaml:"values"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	catalog := &Catalog{Values: doc.Spec.Values, CoreVersion: doc.Metadata.Version}
	catalog.reindex()
	return catalog, nil
}

func loadCapabilities(path string) (map[string]CapabilitySpec, error) {
	var doc struct {
		Spec struct {
			Capabilities []CapabilitySpec `yaml:"capabilities"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	capabilities := map[string]CapabilitySpec{}
	for _, capability := range doc.Spec.Capabilities {
		if strings.TrimSpace(capability.ID) == "" {
			return nil, fmt.Errorf("%s: capability without id", path)
		}
		if !strings.Contains(capability.ID, ".") {
			return nil, fmt.Errorf("%s: capability %q must be a namespaced canonical id", path, capability.ID)
		}
		if !allowedCapabilityKind(capability.Kind) {
			return nil, fmt.Errorf("%s: capability %q has unsupported kind %q", path, capability.ID, capability.Kind)
		}
		if !allowedCatalogStatus(capability.Status, true) {
			return nil, fmt.Errorf("%s: capability %q has unsupported status %q", path, capability.ID, capability.Status)
		}
		if violatesCoreSemanticBoundary(capability.ID) {
			return nil, fmt.Errorf("%s: capability %q violates core generic boundary", path, capability.ID)
		}
		if capability.FailureSemantics.UnknownIsSuccess != nil && *capability.FailureSemantics.UnknownIsSuccess {
			return nil, fmt.Errorf("%s: capability %q sets unknown_is_success=true", path, capability.ID)
		}
		if _, exists := capabilities[capability.ID]; exists {
			return nil, fmt.Errorf("%s: duplicate capability %q", path, capability.ID)
		}
		capabilities[capability.ID] = capability
	}
	return capabilities, nil
}

func loadCompilerRules(path string) (map[string]CompilerRuleSpec, error) {
	var doc struct {
		Spec struct {
			Rules []CompilerRuleSpec `yaml:"rules"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	rules := map[string]CompilerRuleSpec{}
	seenRuntimeActions := map[string]string{}
	for _, rule := range doc.Spec.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return nil, fmt.Errorf("%s: compiler rule without id", path)
		}
		if !strings.HasPrefix(rule.ID, "compiler_rule.") {
			return nil, fmt.Errorf("%s: compiler rule %q must use prefix %q", path, rule.ID, "compiler_rule.")
		}
		if violatesCoreSemanticBoundary(rule.ID) {
			return nil, fmt.Errorf("%s: compiler rule %q violates core generic boundary", path, rule.ID)
		}
		if _, exists := rules[rule.ID]; exists {
			return nil, fmt.Errorf("%s: duplicate compiler rule %q", path, rule.ID)
		}
		if runtimeAction := strings.TrimSpace(rule.RuntimeAction); runtimeAction != "" {
			if existing, exists := seenRuntimeActions[runtimeAction]; exists {
				return nil, fmt.Errorf("%s: runtime action %q mapped by both %q and %q", path, runtimeAction, existing, rule.ID)
			}
			seenRuntimeActions[runtimeAction] = rule.ID
		}
		rules[rule.ID] = rule
	}
	return rules, nil
}

type supplementalCatalogDefinition struct {
	Name       string
	Path       string
	Kind       string
	IDPrefix   string
	Required   bool
	MinEntries int
}

var supplementalCatalogDefinitions = []supplementalCatalogDefinition{
	{Name: "signal", Path: filepath.Join("core", "signal_catalog.yaml"), Kind: "SignalCatalog", IDPrefix: "signal.", Required: true, MinEntries: 1},
	{Name: "metric", Path: filepath.Join("core", "metric_catalog.yaml"), Kind: "MetricCatalog", IDPrefix: "metric.", Required: true, MinEntries: 1},
	{Name: "granularity", Path: filepath.Join("core", "granularity_catalog.yaml"), Kind: "GranularityCatalog", IDPrefix: "granularity.", Required: true, MinEntries: 1},
	{Name: "entity_type", Path: filepath.Join("core", "entity_type_catalog.yaml"), Kind: "EntityTypeCatalog", IDPrefix: "entity_type.", Required: true, MinEntries: 1},
	{Name: "action_type", Path: filepath.Join("core", "action_type_catalog.yaml"), Kind: "ActionTypeCatalog", IDPrefix: "action_type.", Required: true, MinEntries: 1},
	{Name: "evidence", Path: filepath.Join("core", "evidence_catalog.yaml"), Kind: "EvidenceCatalog", IDPrefix: "evidence.", Required: true, MinEntries: 1},
	{Name: "privilege", Path: filepath.Join("core", "privilege_catalog.yaml"), Kind: "PrivilegeCatalog", IDPrefix: "privilege.", Required: true, MinEntries: 1},
	{Name: "state", Path: filepath.Join("core", "state_catalog.yaml"), Kind: "StateCatalog", IDPrefix: "state.", Required: true, MinEntries: 1},
	{Name: "event", Path: filepath.Join("core", "event_catalog.yaml"), Kind: "EventCatalog", IDPrefix: "event.", Required: true, MinEntries: 1},
	{Name: "context", Path: filepath.Join("core", "context_catalog.yaml"), Kind: "ContextCatalog", IDPrefix: "context.", Required: true, MinEntries: 1},
	{Name: "component_role", Path: filepath.Join("core", "component_role_catalog.yaml"), Kind: "ComponentRoleCatalog", IDPrefix: "component_role.", Required: true, MinEntries: 1},
	{Name: "requirement", Path: filepath.Join("core", "requirement_catalog.yaml"), Kind: "RequirementCatalog", IDPrefix: "requirement.", Required: true, MinEntries: 1},
	{Name: "selector_schema", Path: filepath.Join("core", "selector_schema_catalog.yaml"), Kind: "SelectorSchemaCatalog", IDPrefix: "selector.", Required: true, MinEntries: 1},
	{Name: "validation_profile", Path: filepath.Join("core", "validation_profile_catalog.yaml"), Kind: "ValidationProfileCatalog", IDPrefix: "validation.", Required: true, MinEntries: 1},
}

var requiredSchemaFiles = []string{
	"registry.schema.json",
	"authoring-catalog.schema.json",
	"capability-catalog.schema.json",
	"compiler-rule-catalog.schema.json",
	"supplemental-catalog.schema.json",
	"adapter-binding.schema.json",
	"repository-binding.schema.json",
	"policy-source.schema.json",
	"canonical-action.schema.json",
	"business-action.schema.json",
	"target-inventory.schema.json",
	"validation-request.schema.json",
}

func validateRequiredSchemas(coreRegistryPath string) error {
	return validateSchemaFiles(coreRegistryPath, requiredSchemaFiles)
}

func loadSupplementalCatalogs(coreRegistryPath string) (map[string]SupplementalCatalog, error) {
	catalogs := map[string]SupplementalCatalog{}
	for _, definition := range supplementalCatalogDefinitions {
		path := filepath.Join(coreRegistryPath, definition.Path)
		catalog, err := loadSupplementalCatalog(path, definition)
		if err != nil {
			if os.IsNotExist(err) && !definition.Required {
				continue
			}
			return nil, err
		}
		catalogs[definition.Name] = catalog
	}
	return catalogs, nil
}

func loadSupplementalCatalog(path string, definition supplementalCatalogDefinition) (SupplementalCatalog, error) {
	var doc struct {
		Kind string `yaml:"kind"`
		Spec struct {
			Entries []CatalogEntry `yaml:"entries"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return SupplementalCatalog{}, err
	}
	if strings.TrimSpace(doc.Kind) != definition.Kind {
		return SupplementalCatalog{}, fmt.Errorf("%s: expected kind %q, got %q", path, definition.Kind, doc.Kind)
	}
	if len(doc.Spec.Entries) < definition.MinEntries {
		return SupplementalCatalog{}, fmt.Errorf("%s: catalog %q requires at least %d entries", path, definition.Name, definition.MinEntries)
	}
	entries := map[string]CatalogEntry{}
	for i, entry := range doc.Spec.Entries {
		entry.ID = strings.TrimSpace(entry.ID)
		if entry.ID == "" {
			return SupplementalCatalog{}, fmt.Errorf("%s: %s entry %d missing id", path, definition.Name, i)
		}
		if definition.IDPrefix != "" && !strings.HasPrefix(entry.ID, definition.IDPrefix) {
			return SupplementalCatalog{}, fmt.Errorf("%s: %s entry %q must use prefix %q", path, definition.Name, entry.ID, definition.IDPrefix)
		}
		if !allowedCatalogStatus(entry.Status, false) {
			return SupplementalCatalog{}, fmt.Errorf("%s: %s entry %q has unsupported status %q", path, definition.Name, entry.ID, entry.Status)
		}
		if coreSemanticBoundaryApplies(definition.Name) && violatesCoreSemanticBoundary(entry.ID) {
			return SupplementalCatalog{}, fmt.Errorf("%s: %s entry %q violates core generic boundary", path, definition.Name, entry.ID)
		}
		if _, exists := entries[entry.ID]; exists {
			return SupplementalCatalog{}, fmt.Errorf("%s: duplicate %s entry %q", path, definition.Name, entry.ID)
		}
		entries[entry.ID] = entry
	}
	return SupplementalCatalog{Name: definition.Name, Path: path, Kind: definition.Kind, Entries: entries}, nil
}

func loadAdapterBindings(path string) ([]AdapterBinding, error) {
	var doc struct {
		Spec struct {
			Bindings []AdapterBinding `yaml:"bindings"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	for i, binding := range doc.Spec.Bindings {
		if strings.TrimSpace(binding.CapabilityID) == "" {
			return nil, fmt.Errorf("%s: adapter binding %d missing capability_id", path, i)
		}
		if strings.TrimSpace(binding.AdapterID) == "" {
			return nil, fmt.Errorf("%s: adapter binding %d missing adapter_id", path, i)
		}
		if status := strings.TrimSpace(binding.ImplementationStatus); status != "" && !containsString([]string{"implemented", "planned", "experimental"}, status) {
			return nil, fmt.Errorf("%s: adapter binding for %q has unsupported implementation_status %q", path, binding.CapabilityID, binding.ImplementationStatus)
		}
		if strings.TrimSpace(binding.BindingID) == "" {
			binding.BindingID = adapterBindingID(binding)
		}
		binding.Digest = adapterBindingDigest(binding)
		doc.Spec.Bindings[i] = binding
	}
	return doc.Spec.Bindings, nil
}

func loadProfiles(path string) (map[string]Profile, error) {
	var doc struct {
		Spec struct {
			Profiles []Profile `yaml:"profiles"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	profiles := map[string]Profile{}
	for _, profile := range doc.Spec.Profiles {
		profiles[profile.ID] = profile
	}
	return profiles, nil
}

func loadRiskRecipes(path string) (map[string]RiskRecipe, error) {
	var doc struct {
		Spec struct {
			Recipes []RiskRecipe `yaml:"recipes"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	recipes := map[string]RiskRecipe{}
	for _, recipe := range doc.Spec.Recipes {
		recipes[recipe.ID] = recipe
	}
	return recipes, nil
}

func loadGuardrails(path string) (map[string]Guardrail, error) {
	var doc struct {
		Spec struct {
			Guardrails []Guardrail `yaml:"guardrails"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, err
	}
	guardrails := map[string]Guardrail{}
	for _, guardrail := range doc.Spec.Guardrails {
		if guardrail.ID == "" {
			return nil, fmt.Errorf("%s: guardrail without id", path)
		}
		if _, exists := guardrails[guardrail.ID]; exists {
			return nil, fmt.Errorf("%s: duplicate guardrail %q", path, guardrail.ID)
		}
		guardrails[guardrail.ID] = guardrail
	}
	return guardrails, nil
}

func (c *Catalog) validateProfileGuardrails() error {
	for _, profile := range c.Profiles {
		for _, guardrailID := range profile.Guardrails {
			if _, ok := c.Guardrails[guardrailID]; !ok {
				return fmt.Errorf("profile %q references unknown guardrail %q", profile.ID, guardrailID)
			}
		}
	}
	return nil
}

func (c *Catalog) validateCapabilityReferences() error {
	for _, rule := range c.CompilerRules {
		if strings.TrimSpace(rule.RuntimeAction) == "" {
			continue
		}
		if !c.HasAuthoringCanonicalID("runtime_action", rule.RuntimeAction) {
			return fmt.Errorf("compiler rule %q references unknown runtime action %q", rule.ID, rule.RuntimeAction)
		}
		if requirementID := strings.TrimSpace(rule.RequirementID); requirementID != "" {
			if _, ok := c.CatalogEntry("requirement", requirementID); !ok {
				return fmt.Errorf("compiler rule %q references unknown requirement %q", rule.ID, requirementID)
			}
		}
		if len(rule.CapabilityIDs) == 0 {
			return fmt.Errorf("compiler rule %q maps runtime action %q without capabilities", rule.ID, rule.RuntimeAction)
		}
		for _, capabilityID := range rule.CapabilityIDs {
			capability, ok := c.Capabilities[capabilityID]
			if !ok {
				return fmt.Errorf("compiler rule %q references unknown capability %q", rule.ID, capabilityID)
			}
			if !capabilitySupportsRuntimeAction(capability, rule.RuntimeAction) {
				return fmt.Errorf("compiler rule %q maps runtime action %q to capability %q, but the capability does not support that action or alias", rule.ID, rule.RuntimeAction, capabilityID)
			}
		}
	}
	for _, capability := range c.Capabilities {
		for _, granularity := range capability.SupportedGranularities {
			if _, ok := c.CatalogEntry("granularity", granularity); !ok {
				return fmt.Errorf("capability %q references unknown granularity %q", capability.ID, granularity)
			}
		}
		for _, privilege := range capability.PrivilegeRequirements {
			if _, ok := c.CatalogEntry("privilege", privilege); !ok {
				return fmt.Errorf("capability %q references unknown privilege %q", capability.ID, privilege)
			}
		}
		for _, evidence := range capability.EvidenceRequirements {
			if _, ok := c.CatalogEntry("evidence", evidence); !ok {
				return fmt.Errorf("capability %q references unknown evidence %q", capability.ID, evidence)
			}
		}
		for _, contextRequirement := range capability.ContextRequirements {
			if !c.HasRegistryID(contextRequirement) {
				return fmt.Errorf("capability %q references unknown context requirement %q", capability.ID, contextRequirement)
			}
		}
	}
	if err := c.validateRequirementReferences(); err != nil {
		return err
	}
	for _, binding := range c.AdapterBindings {
		if _, ok := c.Capabilities[binding.CapabilityID]; !ok {
			return fmt.Errorf("adapter binding for %q references unknown capability", binding.CapabilityID)
		}
		if status := strings.TrimSpace(binding.ImplementationStatus); status == "implemented" {
			capability := c.Capabilities[binding.CapabilityID]
			if strings.TrimSpace(capability.Status) == "planned" {
				return fmt.Errorf("adapter binding for %q claims implemented planned capability", binding.CapabilityID)
			}
		}
	}
	return nil
}

func (c *Catalog) validateRequirementReferences() error {
	requirements, ok := c.SupplementalCatalogs["requirement"]
	if !ok {
		return fmt.Errorf("requirement catalog is required")
	}
	for _, requirement := range requirements.Entries {
		for _, metric := range requirement.RequiredMetrics {
			if _, ok := c.CatalogEntry("metric", metric); !ok {
				return fmt.Errorf("requirement %q references unknown metric %q", requirement.ID, metric)
			}
		}
		for _, signal := range requirement.RequiredSignals {
			if _, ok := c.CatalogEntry("signal", signal); !ok {
				return fmt.Errorf("requirement %q references unknown signal %q", requirement.ID, signal)
			}
		}
		for _, capability := range requirement.RequiredCapabilities {
			if _, ok := c.Capabilities[capability]; !ok {
				return fmt.Errorf("requirement %q references unknown capability %q", requirement.ID, capability)
			}
		}
		for _, evidence := range requirement.RequiredEvidence {
			if _, ok := c.CatalogEntry("evidence", evidence); !ok {
				return fmt.Errorf("requirement %q references unknown evidence %q", requirement.ID, evidence)
			}
		}
		for _, granularity := range requirement.AllowedGranularities {
			if _, ok := c.CatalogEntry("granularity", granularity); !ok {
				return fmt.Errorf("requirement %q references unknown granularity %q", requirement.ID, granularity)
			}
		}
		if behavior := strings.TrimSpace(requirement.UnknownBehavior); behavior != "" && !containsString([]string{"risk_unknown", "fail_closed", "unsupported", "observe_only"}, behavior) {
			return fmt.Errorf("requirement %q has unsupported unknown_behavior %q", requirement.ID, behavior)
		}
	}
	return nil
}

func (c *Catalog) loadEnterpriseVocabulary(path string) error {
	var doc struct {
		Spec struct {
			Terms []struct {
				ID      string   `yaml:"id"`
				Label   string   `yaml:"label"`
				Aliases []string `yaml:"aliases"`
			} `yaml:"terms"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return err
	}
	for _, term := range doc.Spec.Terms {
		value := Value{Label: term.Label, CanonicalID: term.ID, Kind: inferKind(term.ID)}
		if err := c.addValue(value); err != nil {
			return err
		}
		for _, alias := range term.Aliases {
			if err := c.addValue(Value{Label: alias, CanonicalID: term.ID, Kind: value.Kind}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Catalog) loadEnterpriseProfiles(path string) error {
	profiles, err := loadProfiles(path)
	if err != nil {
		return err
	}
	for _, enterprise := range profiles {
		existing, ok := c.Profiles[enterprise.ID]
		switch enterprise.Mode {
		case "inherited":
			if !ok {
				return fmt.Errorf("enterprise profile %q uses inherited mode but no core profile exists", enterprise.ID)
			}
			c.Profiles[enterprise.ID] = mergeProfile(existing, enterprise)
		case "override":
			if !ok {
				return fmt.Errorf("enterprise profile %q uses override mode but no core profile exists", enterprise.ID)
			}
			c.Profiles[enterprise.ID] = mergeProfile(existing, enterprise)
		case "":
			if ok {
				return fmt.Errorf("enterprise profile %q duplicates a core profile without mode", enterprise.ID)
			}
			c.Profiles[enterprise.ID] = enterprise
		default:
			return fmt.Errorf("enterprise profile %q has unsupported mode %q", enterprise.ID, enterprise.Mode)
		}
	}
	return nil
}

func mergeProfile(base, overlay Profile) Profile {
	merged := base
	merged.Mode = overlay.Mode
	merged.Owner = overlay.Owner
	if overlay.Stage != "" {
		merged.Stage = overlay.Stage
	}
	if overlay.Guardrails != nil {
		merged.Guardrails = overlay.Guardrails
	}
	if overlay.RuntimeDefaults != nil {
		merged.RuntimeDefaults = map[string]string{}
		for key, value := range base.RuntimeDefaults {
			merged.RuntimeDefaults[key] = value
		}
		for key, value := range overlay.RuntimeDefaults {
			merged.RuntimeDefaults[key] = value
		}
	}
	return merged
}

func labelKind(label, kind string) string {
	return label + "\x00" + kind
}

func supplementalEntryKey(catalogName, id string) string {
	return catalogName + "\x00" + id
}

func inferKind(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) >= 2 && parts[0] == "enterprise" {
		return parts[1]
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

func capabilitySupportsRuntimeAction(capability CapabilitySpec, action string) bool {
	return containsString(capability.SupportedActions, action) || containsString(capability.CompatibilityAliases, action)
}

func adapterBindingID(binding AdapterBinding) string {
	return "adapter_binding." + strings.TrimPrefix(adapterBindingDigest(binding), "sha256:")[:16]
}

func adapterBindingDigest(binding AdapterBinding) string {
	normalized := struct {
		CapabilityID         string   `json:"capability_id"`
		AdapterID            string   `json:"adapter_id"`
		Environments         []string `json:"environments,omitempty"`
		Stages               []string `json:"stages,omitempty"`
		ImplementationStatus string   `json:"implementation_status,omitempty"`
		RequiredGrantProfile string   `json:"required_grant_profile,omitempty"`
	}{
		CapabilityID:         strings.TrimSpace(binding.CapabilityID),
		AdapterID:            strings.TrimSpace(binding.AdapterID),
		Environments:         append([]string(nil), binding.Environments...),
		Stages:               append([]string(nil), binding.Stages...),
		ImplementationStatus: strings.TrimSpace(binding.ImplementationStatus),
		RequiredGrantProfile: strings.TrimSpace(binding.RequiredGrantProfile),
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return "sha256:unavailable"
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func allowedCapabilityKind(kind string) bool {
	return containsString([]string{
		"observe",
		"enforce_runtime",
		"plan_config",
		"validate_config",
		"read_state",
		"provide_evidence",
		"provide_relationship",
		"provide_attestation",
		"compute",
		"evaluate",
	}, kind)
}

func allowedCatalogStatus(status string, required bool) bool {
	status = strings.TrimSpace(status)
	if status == "" {
		return !required
	}
	return containsString([]string{"experimental", "stable", "deprecated", "planned"}, status)
}

func coreSemanticBoundaryApplies(catalogName string) bool {
	return containsString([]string{
		"signal",
		"metric",
		"evidence",
		"requirement",
	}, catalogName)
}

func violatesCoreSemanticBoundary(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, forbidden := range []string{
		"source_ip",
		"bpf_map",
		"openziti",
		"zscaler",
		"klshield",
		".ziti.",
		".raw_",
	} {
		if strings.Contains(id, forbidden) {
			return true
		}
	}
	return false
}

func containsString(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, value := range values {
		if strings.TrimSpace(value) == needle {
			return true
		}
	}
	return false
}

func readYAML(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
