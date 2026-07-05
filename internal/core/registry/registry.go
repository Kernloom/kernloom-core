// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Catalog struct {
	Values      []Value
	Profiles    map[string]Profile
	RiskRecipes map[string]RiskRecipe
	Guardrails  map[string]Guardrail
	CoreVersion string
	byLabel     map[string][]Value
	byLabelKind map[string]Value
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

type ResolveError struct {
	Code  string
	Label string
	Kinds []string
}

func (e ResolveError) Error() string {
	return fmt.Sprintf("%s: %q for kinds [%s]", e.Code, e.Label, strings.Join(e.Kinds, ", "))
}

func Load(coreRegistryPath, enterpriseRegistryPath string) (*Catalog, error) {
	catalog, err := loadCoreCatalog(filepath.Join(coreRegistryPath, "core", "authoring_catalog.yaml"))
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
	}
	if err := catalog.validateProfileGuardrails(); err != nil {
		return nil, err
	}
	catalog.reindex()
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

func (c *Catalog) reindex() {
	c.byLabel = map[string][]Value{}
	c.byLabelKind = map[string]Value{}
	for _, value := range c.Values {
		c.byLabel[value.Label] = append(c.byLabel[value.Label], value)
		c.byLabelKind[labelKind(value.Label, value.Kind)] = value
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
