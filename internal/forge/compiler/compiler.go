// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kernloom/kernloom-core/internal/core/expression"
	"github.com/kernloom/kernloom-core/internal/core/intent"
	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/core/version"
)

func Compile(opts Options) ([]Result, error) {
	if opts.PolicyRepo == "" {
		opts.PolicyRepo = "../enterprise-kernloom-policies"
	}
	if opts.CoreRegistry == "" {
		opts.CoreRegistry = "../kernloom-core-registry"
	}
	if opts.EnterpriseRegistry == "" {
		opts.EnterpriseRegistry = "../enterprise-kernloom-registry"
	}
	if opts.OutputDir == "" {
		opts.OutputDir = filepath.Join(opts.PolicyRepo, "generated")
	}

	catalog, err := registry.Load(opts.CoreRegistry, opts.EnterpriseRegistry)
	if err != nil {
		return nil, err
	}
	celValidator, err := expression.NewCELValidator()
	if err != nil {
		return nil, err
	}
	if err := validateCatalogCEL(catalog, celValidator); err != nil {
		return nil, err
	}

	files, err := intentFiles(opts)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(files))
	for _, file := range files {
		card, err := intent.ParseFile(file)
		if err != nil {
			return nil, err
		}
		result, err := compileOne(card, catalog, celValidator, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func compileOne(card *intent.Card, catalog *registry.Catalog, celValidator *expression.CELValidator, opts Options) (Result, error) {
	if err := validateMetadata(card, catalog); err != nil {
		return Result{}, err
	}
	profile, _ := catalog.Profile(card.Profile)
	sourceCommit := gitCommit(opts.PolicyRepo)

	resolved := ResolvedPolicy{
		Kind: "ResolvedPolicy",
		Metadata: ResolvedMetadata{
			ID:           "resolved." + card.ID,
			PolicyID:     card.ID,
			SourcePath:   relativeOrSame(opts.PolicyRepo, card.SourcePath),
			SourceCommit: sourceCommit,
		},
		Spec: ResolvedPolicySpec{
			Version:    card.Version,
			Owner:      card.Owner,
			Type:       card.Type,
			Target:     card.Target,
			Stage:      card.Stage,
			Profile:    card.Profile,
			RiskRecipe: card.RiskRecipe,
			Guardrails: profile.Guardrails,
		},
	}

	for _, rule := range card.Rules {
		resolvedRule, err := resolveRule(rule, catalog, celValidator)
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", card.ID, err)
		}
		resolved.Spec.Rules = append(resolved.Spec.Rules, resolvedRule)
	}
	for _, behavior := range card.Risk {
		riskType, err := catalog.Resolve(behavior.RiskType, "risk_type")
		if err != nil {
			return Result{}, err
		}
		tier, err := catalog.Resolve(behavior.Tier, "risk_tier")
		if err != nil {
			return Result{}, err
		}
		effect, err := catalog.Resolve(behavior.Effect, "effect")
		if err != nil {
			return Result{}, err
		}
		resolved.Spec.RiskBehavior = append(resolved.Spec.RiskBehavior, ResolvedRiskBehavior{
			RiskType: resolvedValue(riskType),
			Tier:     resolvedValue(tier),
			Effect:   resolvedValue(effect),
		})
	}
	for _, label := range card.Prohibit {
		value, err := catalog.Resolve(label, "prohibited_outcome")
		if err != nil {
			return Result{}, err
		}
		resolved.Spec.Prohibit = append(resolved.Spec.Prohibit, resolvedValue(value))
	}
	runtime, err := resolveRuntime(card.Runtime, catalog, profile)
	if err != nil {
		return Result{}, err
	}
	resolved.Spec.Runtime = runtime
	for _, simulation := range card.Simulations {
		resolvedSimulation, err := resolveSimulation(simulation, catalog, celValidator)
		if err != nil {
			return Result{}, err
		}
		resolved.Spec.Simulations = append(resolved.Spec.Simulations, resolvedSimulation)
	}

	resolvedPath, resolvedHash, err := writeJSON(filepath.Join(opts.OutputDir, "resolved", card.ID+".resolved.json"), resolved)
	if err != nil {
		return Result{}, err
	}
	coverage := MeaningCoverageReport{
		Kind:     "MeaningCoverageReport",
		PolicyID: card.ID,
		Status:   "resolved_only",
		Message:  "Slice 1 compiler resolved normative authoring values; multi-system meaning coverage has not been evaluated.",
	}
	coveragePath, coverageHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".coverage.json"), coverage)
	if err != nil {
		return Result{}, err
	}
	simulationReport := SimulationReport{Kind: "SimulationReport", PolicyID: card.ID}
	for _, simulation := range resolved.Spec.Simulations {
		simulationReport.Simulations = append(simulationReport.Simulations, SimulationStatus{Name: simulation.Name, Status: "resolved_only"})
	}
	simulationPath, simulationHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".simulation.json"), simulationReport)
	if err != nil {
		return Result{}, err
	}
	validation := ValidationResult{
		Kind:     "ValidationResult",
		PolicyID: card.ID,
		Status:   "not_evaluated",
		Passed:   false,
		Findings: []string{
			"Slice 1 performed parser, catalog resolution and CEL validation only; full policy validation is not implemented.",
			"Risk recipes are loaded and CEL-checked only; scoring, freshness, confidence and runtime simulation are not evaluated.",
		},
	}
	validationPath, validationHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".validation.json"), validation)
	if err != nil {
		return Result{}, err
	}

	manifest := PolicyBuildManifest{
		Kind:     "PolicyBuildManifest",
		Metadata: ManifestMetadata{ID: "build." + card.ID},
		Spec: ManifestSpec{
			PolicyRepo:         RepoRef{Repo: filepath.Base(opts.PolicyRepo), Commit: sourceCommit},
			EnterpriseRegistry: RepoRef{Repo: filepath.Base(opts.EnterpriseRegistry), Commit: gitCommit(opts.EnterpriseRegistry)},
			CoreRegistry:       CoreRegistryRef{Repo: filepath.Base(opts.CoreRegistry), Version: catalog.CoreVersion},
			Compiler:           CompilerRef{Name: "forge", Version: version.Version, Digest: sha256String("forge:" + version.Version)},
			Adapters: map[string]AdapterRef{
				"ziti":     {ManifestDigest: "sha256:pending-slice-3", ProtocolVersion: "adapter/v1"},
				"klshield": {ManifestDigest: "sha256:pending-slice-3", ProtocolVersion: "adapter/v1"},
			},
			Outputs: map[string]string{
				"resolved_policy":         resolvedHash,
				"meaning_coverage_report": coverageHash,
				"simulation_report":       simulationHash,
				"validation_result":       validationHash,
			},
		},
	}
	manifestPath, manifestHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".manifest.json"), manifest)
	if err != nil {
		return Result{}, err
	}
	reviewPath, err := writeReview(filepath.Join(opts.OutputDir, "reviews", card.ID+".intent.review.md"), card, resolved)
	if err != nil {
		return Result{}, err
	}

	return Result{
		PolicyID:       card.ID,
		ReviewPath:     reviewPath,
		ResolvedPath:   resolvedPath,
		ManifestPath:   manifestPath,
		CoveragePath:   coveragePath,
		SimulationPath: simulationPath,
		ValidationPath: validationPath,
		ResolvedSHA256: resolvedHash,
		ManifestSHA256: manifestHash,
	}, nil
}

func validateMetadata(card *intent.Card, catalog *registry.Catalog) error {
	if card.Version != "kni/v0.5" {
		return fmt.Errorf("%s: unsupported KNI version %q", card.ID, card.Version)
	}
	if card.ID == "" || card.Owner == "" || card.Type == "" || card.Target == "" || card.Stage == "" {
		return fmt.Errorf("%s: missing required intent metadata", card.ID)
	}
	if _, err := catalog.Resolve(card.Type, "policy_type"); err != nil {
		return fmt.Errorf("%s: invalid policy type: %w", card.ID, err)
	}
	if _, err := catalog.Resolve(card.Target, "target_system"); err != nil {
		return fmt.Errorf("%s: invalid target: %w", card.ID, err)
	}
	if _, err := catalog.Resolve(card.Stage, "stage"); err != nil {
		return fmt.Errorf("%s: invalid stage: %w", card.ID, err)
	}
	if len(card.Rules) == 0 {
		return fmt.Errorf("%s: intent requires at least one rule", card.ID)
	}
	if _, ok := catalog.Profile(card.Profile); !ok {
		return fmt.Errorf("%s: unknown profile %q", card.ID, card.Profile)
	}
	if _, ok := catalog.RiskRecipe(card.RiskRecipe); !ok {
		return fmt.Errorf("%s: unknown risk recipe %q", card.ID, card.RiskRecipe)
	}
	return nil
}

func resolveRule(rule intent.Rule, catalog *registry.Catalog, celValidator *expression.CELValidator) (ResolvedRule, error) {
	effect, err := catalog.Resolve(rule.Effect, "effect")
	if err != nil {
		return ResolvedRule{}, err
	}
	subject, err := catalog.Resolve(rule.Subject, "subject")
	if err != nil {
		return ResolvedRule{}, err
	}
	action, err := catalog.Resolve(rule.Action, "action")
	if err != nil {
		return ResolvedRule{}, err
	}
	resource, err := catalog.Resolve(rule.Resource, "resource")
	if err != nil {
		return ResolvedRule{}, err
	}
	resolved := ResolvedRule{
		Name:     rule.Name,
		Effect:   resolvedValue(effect),
		Subject:  resolvedValue(subject),
		Action:   resolvedValue(action),
		Resource: resolvedValue(resource),
	}
	var expressions []string
	for _, label := range rule.OnlyWhen {
		value, err := catalog.Resolve(label, "fact")
		if err != nil {
			return ResolvedRule{}, err
		}
		if err := celValidator.Validate(value.CEL); err != nil {
			return ResolvedRule{}, err
		}
		resolved.Conditions = append(resolved.Conditions, resolvedValue(value))
		if value.CEL != "" {
			expressions = append(expressions, "("+value.CEL+")")
		}
	}
	if len(expressions) == 0 {
		resolved.CEL = "true"
	} else {
		resolved.CEL = strings.Join(expressions, " && ")
	}
	if err := celValidator.Validate(resolved.CEL); err != nil {
		return ResolvedRule{}, err
	}
	return resolved, nil
}

func resolveRuntime(runtime intent.Runtime, catalog *registry.Catalog, profile registry.Profile) (ResolvedRuntime, error) {
	maxTTL := runtime.MaxTTL
	maxTTLSource := "policy"
	if maxTTL == "" {
		maxTTL = profile.RuntimeDefaults["max_ttl"]
		maxTTLSource = "profile_default"
	}
	maxScope := runtime.MaxScope
	maxScopeSource := "policy"
	if maxScope == "" {
		maxScope = profile.RuntimeDefaults["max_scope"]
		maxScopeSource = "profile_default"
	}
	if maxTTL == "" {
		return ResolvedRuntime{}, fmt.Errorf("runtime max_ttl is missing and profile %q has no default", profile.ID)
	}
	if maxScope == "" {
		return ResolvedRuntime{}, fmt.Errorf("runtime max_scope is missing and profile %q has no default", profile.ID)
	}
	scope, err := catalog.Resolve(maxScope, "scope")
	if err != nil {
		return ResolvedRuntime{}, err
	}
	resolved := ResolvedRuntime{
		Allowed:        runtime.Allowed,
		MaxTTL:         maxTTL,
		MaxTTLSource:   maxTTLSource,
		MaxScope:       resolvedValue(scope),
		MaxScopeSource: maxScopeSource,
	}
	for _, label := range runtime.Actions {
		value, err := catalog.Resolve(label, "runtime_action")
		if err != nil {
			return ResolvedRuntime{}, err
		}
		resolved.Actions = append(resolved.Actions, resolvedValue(value))
	}
	return resolved, nil
}

func resolveSimulation(simulation intent.Simulation, catalog *registry.Catalog, celValidator *expression.CELValidator) (ResolvedSimulation, error) {
	resolved := ResolvedSimulation{Name: simulation.Name}
	for _, label := range simulation.Given {
		value, err := catalog.Resolve(label, "fact", "subject")
		if err != nil {
			return ResolvedSimulation{}, err
		}
		if err := celValidator.Validate(value.CEL); err != nil {
			return ResolvedSimulation{}, err
		}
		resolved.Given = append(resolved.Given, resolvedValue(value))
	}
	effect, err := catalog.Resolve(simulation.ExpectEffect, "effect")
	if err != nil {
		return ResolvedSimulation{}, err
	}
	resolved.ExpectEffect = resolvedValue(effect)
	return resolved, nil
}

func validateCatalogCEL(catalog *registry.Catalog, celValidator *expression.CELValidator) error {
	for _, value := range catalog.Values {
		if err := celValidator.Validate(value.CEL); err != nil {
			return fmt.Errorf("%s: %w", value.Label, err)
		}
	}
	for _, recipe := range catalog.RiskRecipes {
		for tier, expr := range recipe.Thresholds {
			if err := celValidator.Validate(expr); err != nil {
				return fmt.Errorf("%s threshold %s: %w", recipe.ID, tier, err)
			}
		}
	}
	return nil
}

func intentFiles(opts Options) ([]string, error) {
	if opts.PolicyFile != "" {
		return []string{opts.PolicyFile}, nil
	}
	var files []string
	root := filepath.Join(opts.PolicyRepo, "policies")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".intent.kni") {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func writeJSON(path string, value any) (string, string, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", "", err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", "", err
	}
	return path, sha256Bytes(data), nil
}

func writeReview(path string, card *intent.Card, resolved ResolvedPolicy) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Natural Intent Review: %s\n\n", card.ID)
	fmt.Fprintf(&b, "Forge understood this intent as `%s` policy for `%s` in `%s`.\n\n", card.Type, card.Target, card.Stage)
	fmt.Fprintf(&b, "Profile: `%s`\n\n", card.Profile)
	fmt.Fprintf(&b, "## Metadata\n\n")
	fmt.Fprintf(&b, "- Owner: `%s`\n", resolved.Spec.Owner)
	fmt.Fprintf(&b, "- Type: `%s`\n", resolved.Spec.Type)
	fmt.Fprintf(&b, "- Target: `%s`\n", resolved.Spec.Target)
	fmt.Fprintf(&b, "- Stage: `%s`\n", resolved.Spec.Stage)
	fmt.Fprintf(&b, "- Risk Recipe: `%s`\n\n", resolved.Spec.RiskRecipe)
	fmt.Fprintf(&b, "## Applied Guardrails\n\n")
	for _, guardrail := range resolved.Spec.Guardrails {
		fmt.Fprintf(&b, "- `%s`\n", guardrail)
	}
	fmt.Fprintf(&b, "\n")
	for _, rule := range resolved.Spec.Rules {
		fmt.Fprintf(&b, "## Rule: %s\n\n", rule.Name)
		fmt.Fprintf(&b, "Subject: `%s` -> `%s`\n\n", rule.Subject.Label, rule.Subject.CanonicalID)
		fmt.Fprintf(&b, "Action: `%s` -> `%s`\n\n", rule.Action.Label, rule.Action.CanonicalID)
		fmt.Fprintf(&b, "Resource: `%s` -> `%s`\n\n", rule.Resource.Label, rule.Resource.CanonicalID)
		fmt.Fprintf(&b, "Effect: `%s` -> `%s`\n\n", rule.Effect.Label, rule.Effect.CanonicalID)
		fmt.Fprintf(&b, "CEL:\n\n```cel\n%s\n```\n\n", rule.CEL)
	}
	if len(resolved.Spec.RiskBehavior) > 0 {
		fmt.Fprintf(&b, "## Risk Behavior\n\n")
		for _, behavior := range resolved.Spec.RiskBehavior {
			fmt.Fprintf(&b, "- `%s` `%s` -> `%s`\n", behavior.RiskType.Label, behavior.Tier.Label, behavior.Effect.Label)
		}
		fmt.Fprintf(&b, "\n")
	}
	if len(resolved.Spec.Prohibit) > 0 {
		fmt.Fprintf(&b, "## Prohibited Outcomes\n\n")
		for _, outcome := range resolved.Spec.Prohibit {
			fmt.Fprintf(&b, "- `%s` -> `%s`\n", outcome.Label, outcome.CanonicalID)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Runtime\n\n")
	fmt.Fprintf(&b, "- Allowed: `%t`\n", resolved.Spec.Runtime.Allowed)
	fmt.Fprintf(&b, "- Max TTL: `%s` (%s)\n", resolved.Spec.Runtime.MaxTTL, resolved.Spec.Runtime.MaxTTLSource)
	fmt.Fprintf(&b, "- Max Scope: `%s` -> `%s` (%s)\n", resolved.Spec.Runtime.MaxScope.Label, resolved.Spec.Runtime.MaxScope.CanonicalID, resolved.Spec.Runtime.MaxScopeSource)
	for _, action := range resolved.Spec.Runtime.Actions {
		fmt.Fprintf(&b, "- Action: `%s` -> `%s`\n", action.Label, action.CanonicalID)
	}
	fmt.Fprintf(&b, "\n")
	if len(resolved.Spec.Simulations) > 0 {
		fmt.Fprintf(&b, "## Simulation Examples\n\n")
		for _, simulation := range resolved.Spec.Simulations {
			fmt.Fprintf(&b, "- `%s`: resolved only, expected `%s`\n", simulation.Name, simulation.ExpectEffect.Label)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Reports\n\n")
	fmt.Fprintf(&b, "- Meaning coverage: `resolved_only`\n")
	fmt.Fprintf(&b, "- Simulation: `resolved_only`\n")
	fmt.Fprintf(&b, "- Risk recipe evaluation: `not_evaluated`\n")
	fmt.Fprintf(&b, "- Validation: `not_evaluated`\n\n")
	fmt.Fprintf(&b, "## Findings\n\nnone blocking during Slice 1 resolution\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func relativeOrSame(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}

func gitCommit(repo string) string {
	cmd := exec.Command("git", "-C", repo, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "uncommitted"
	}
	return strings.TrimSpace(string(out))
}

func sha256String(value string) string {
	return sha256Bytes([]byte(value))
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
