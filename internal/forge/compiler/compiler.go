// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/artifact"
	"github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/conformance"
	corecontext "github.com/kernloom/kernloom-core/internal/core/context"
	"github.com/kernloom/kernloom-core/internal/core/expression"
	"github.com/kernloom/kernloom-core/internal/core/intent"
	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/core/version"
	"github.com/kernloom/kernloom-core/internal/storage/artifactstore"
)

const (
	SigningModeNone     = "none"
	SigningModeDevLocal = "dev-local"
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
	services, err := compileServices(opts)
	if err != nil {
		return nil, err
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
		result, err := compileOne(context.Background(), card, catalog, celValidator, opts, services)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

type compileRuntime struct {
	ArtifactStore artifactstore.ArtifactStore
	Signer        signing.Signer
	ExpiresAt     *time.Time
}

func compileServices(opts Options) (compileRuntime, error) {
	store := opts.ArtifactStore
	if store == nil {
		root := opts.ArtifactStoreRoot
		if root == "" {
			root = filepath.Join(opts.OutputDir, "artifact-store")
		}
		store = artifactstore.NewFSStore(root, valueOrDefault(opts.ArtifactStoreOrg, "kernloom"), valueOrDefault(opts.ArtifactStoreEnvironment, "dev"))
	}

	mode := opts.SigningMode
	if mode == "" {
		mode = SigningModeDevLocal
	}
	mode = strings.ToLower(mode)
	if mode == SigningModeNone {
		return compileRuntime{ArtifactStore: store}, nil
	}
	ttl := opts.SignatureTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	expiresAt := now.Add(ttl)
	signer := opts.Signer
	switch mode {
	case SigningModeDevLocal:
		if signer == nil {
			keyPath := opts.SigningKeyPath
			if keyPath == "" {
				keyPath = filepath.Join(opts.OutputDir, "keys", "dev-local.ed25519.json")
			}
			devSigner, err := signing.LoadOrCreateDevLocalSigner(keyPath, valueOrDefault(opts.SigningKeyID, "dev-local"))
			if err != nil {
				return compileRuntime{}, err
			}
			signer = devSigner
		}
	default:
		return compileRuntime{}, fmt.Errorf("unsupported signing mode %q", opts.SigningMode)
	}
	return compileRuntime{ArtifactStore: store, Signer: signer, ExpiresAt: &expiresAt}, nil
}

func compileOne(ctx context.Context, card *intent.Card, catalog *registry.Catalog, celValidator *expression.CELValidator, opts Options, services compileRuntime) (Result, error) {
	if err := validateMetadata(card, catalog); err != nil {
		return Result{}, err
	}
	profile, _ := catalog.Profile(card.Profile)
	riskRecipe, _ := catalog.RiskRecipe(card.RiskRecipe)
	sourceCommit := gitCommit(opts.PolicyRepo)
	policyFileHash := fileSHA256(card.SourcePath)
	correlationID := strings.TrimSpace(opts.CorrelationID)
	if correlationID == "" {
		correlationID = "correlation." + strings.TrimPrefix(sha256String(card.ID+"\x00"+sourceCommit+"\x00"+policyFileHash), "sha256:")[:16]
	}
	coreRegistryDigest := pathSHA256(opts.CoreRegistry)
	enterpriseRegistryDigest := pathSHA256(opts.EnterpriseRegistry)
	compilerSourceCommit := gitCommit(".")
	compilerBinaryDigest := executableSHA256()

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

	artifactMetadata := artifact.Metadata{
		PolicyID:      card.ID,
		KNI:           card.Version,
		SourcePath:    relativeOrSame(opts.PolicyRepo, card.SourcePath),
		SourceCommit:  sourceCommit,
		CorrelationID: correlationID,
		CreatedAt:     time.Now().UTC(),
		Digests: map[string]string{
			"policy_file":         policyFileHash,
			"core_registry":       coreRegistryDigest,
			"enterprise_registry": enterpriseRegistryDigest,
			"catalog":             digestJSON(catalog),
			"profile":             digestJSON(profile),
			"risk_recipe":         digestJSON(riskRecipe),
		},
	}

	resolvedMetadata := artifactMetadata
	resolvedMetadata.ID = resolved.Metadata.ID
	resolvedMetadata.ArtifactType = "resolved_policy"
	resolvedOutput, err := emitJSONArtifact(ctx, filepath.Join(opts.OutputDir, "resolved", card.ID+".resolved.json"), resolved, resolvedMetadata, services, opts)
	if err != nil {
		return Result{}, err
	}
	runtimeBundle := runtimeBundleArtifact(card, resolved, artifactMetadata)
	runtimeBundleOutput, err := emitJSONArtifact(ctx, filepath.Join(opts.OutputDir, "artifacts", card.ID+".runtime_bundle.json"), runtimeBundle, runtimeBundle.Metadata, services, opts)
	if err != nil {
		return Result{}, err
	}
	contextRoutePack := contextRoutePackArtifact(card, resolved, artifactMetadata)
	contextRoutePackOutput, err := emitJSONArtifact(ctx, filepath.Join(opts.OutputDir, "artifacts", card.ID+".context_route_pack.json"), contextRoutePack, contextRoutePack.Metadata, services, opts)
	if err != nil {
		return Result{}, err
	}
	conformanceExpectation := conformanceExpectationArtifact(card, resolved, artifactMetadata)
	conformanceExpectationOutput, err := emitJSONArtifact(ctx, filepath.Join(opts.OutputDir, "artifacts", card.ID+".conformance_expectation.json"), conformanceExpectation, conformanceExpectation.Metadata, services, opts)
	if err != nil {
		return Result{}, err
	}
	coverage := MeaningCoverageReport{
		Kind:     "MeaningCoverageReport",
		PolicyID: card.ID,
		Status:   "resolved_only",
		Message:  "Compile phase completed catalog resolution and artifact planning; multi-system meaning coverage has not been evaluated.",
	}
	coveragePath, coverageHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".coverage.json"), coverage)
	if err != nil {
		return Result{}, err
	}
	simulationReport := SimulationReport{
		Kind:        "SimulationReport",
		PolicyID:    card.ID,
		Status:      "resolved_only",
		Simulations: []SimulationStatus{},
		Findings:    []string{},
	}
	for _, simulation := range resolved.Spec.Simulations {
		simulationReport.Simulations = append(simulationReport.Simulations, SimulationStatus{Name: simulation.Name, Status: "resolved_only"})
	}
	if len(simulationReport.Simulations) == 0 {
		simulationReport.Findings = append(simulationReport.Findings, "No simulation examples defined.")
	}
	simulationPath, simulationHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".simulation.json"), simulationReport)
	if err != nil {
		return Result{}, err
	}
	validation := ValidationResult{
		Kind:     "ValidationResult",
		PolicyID: card.ID,
		Status:   "not_evaluated",
		Findings: []string{
			"Compile phase performed parser, catalog resolution, artifact planning and CEL validation only; full policy validation is not implemented.",
			"Risk recipes are loaded and CEL-checked only; scoring, freshness, confidence and runtime simulation are not evaluated.",
		},
	}
	validationPath, validationHash, err := writeJSON(filepath.Join(opts.OutputDir, "reports", card.ID+".validation.json"), validation)
	if err != nil {
		return Result{}, err
	}

	manifest := PolicyBuildManifest{
		Kind:     "PolicyBuildManifest",
		Metadata: ManifestMetadata{ID: "build." + card.ID, CorrelationID: correlationID},
		Approval: ManifestApproval{
			Status: "pending_review",
		},
		Spec: ManifestSpec{
			KNI:      KNIRef{Version: card.Version},
			Protocol: ProtocolRef{Version: "adapter/v1"},
			PolicyRepo: PolicyRepoRef{
				Repo:           filepath.Base(opts.PolicyRepo),
				Commit:         sourceCommit,
				PolicyFile:     relativeOrSame(opts.PolicyRepo, card.SourcePath),
				PolicyFileHash: policyFileHash,
				ContentDigest:  pathSHA256(opts.PolicyRepo),
			},
			EnterpriseRegistry: RegistryRef{
				Repo:          filepath.Base(opts.EnterpriseRegistry),
				Commit:        gitCommit(opts.EnterpriseRegistry),
				ContentDigest: enterpriseRegistryDigest,
			},
			CoreRegistry: RegistryRef{
				Repo:          filepath.Base(opts.CoreRegistry),
				Commit:        gitCommit(opts.CoreRegistry),
				Version:       catalog.CoreVersion,
				ContentDigest: coreRegistryDigest,
			},
			Compiler: CompilerRef{
				Name:         "forge",
				Version:      version.Version,
				SourceCommit: compilerSourceCommit,
				BinaryDigest: compilerBinaryDigest,
				Digest:       digestJSON(map[string]string{"name": "forge", "version": version.Version, "source_commit": compilerSourceCommit, "binary_digest": compilerBinaryDigest}),
			},
			Profile:       DigestRef{ID: profile.ID, Digest: digestJSON(profile)},
			RiskRecipe:    DigestRef{ID: riskRecipe.ID, Digest: digestJSON(riskRecipe)},
			CatalogDigest: digestJSON(catalog),
			Adapters:      adapterManifestRefs(opts),
			Outputs: map[string]string{
				"resolved_policy":         resolvedOutput.SHA256,
				"runtime_bundle":          runtimeBundleOutput.SHA256,
				"context_route_pack":      contextRoutePackOutput.SHA256,
				"conformance_expectation": conformanceExpectationOutput.SHA256,
				"meaning_coverage_report": coverageHash,
				"simulation_report":       simulationHash,
				"validation_result":       validationHash,
			},
			ArtifactRefs: map[string]artifact.Ref{
				"resolved_policy":         resolvedOutput.Ref,
				"runtime_bundle":          runtimeBundleOutput.Ref,
				"context_route_pack":      contextRoutePackOutput.Ref,
				"conformance_expectation": conformanceExpectationOutput.Ref,
			},
			SignedOutputs: signedOutputs(map[string]emittedArtifact{
				"resolved_policy":         resolvedOutput,
				"runtime_bundle":          runtimeBundleOutput,
				"context_route_pack":      contextRoutePackOutput,
				"conformance_expectation": conformanceExpectationOutput,
			}),
		},
	}
	manifestMetadata := artifactMetadata
	manifestMetadata.ID = manifest.Metadata.ID
	manifestMetadata.ArtifactType = "policy_build_manifest"
	manifestOutput, err := emitJSONArtifact(ctx, filepath.Join(opts.OutputDir, "reports", card.ID+".manifest.json"), manifest, manifestMetadata, services, opts)
	if err != nil {
		return Result{}, err
	}
	reviewPath, err := writeReview(filepath.Join(opts.OutputDir, "reviews", card.ID+".intent.review.md"), card, resolved)
	if err != nil {
		return Result{}, err
	}

	return Result{
		PolicyID:                                card.ID,
		ReviewPath:                              reviewPath,
		ResolvedPath:                            resolvedOutput.Path,
		RuntimeBundlePath:                       runtimeBundleOutput.Path,
		ContextRoutePackPath:                    contextRoutePackOutput.Path,
		ConformanceExpectationPath:              conformanceExpectationOutput.Path,
		ManifestPath:                            manifestOutput.Path,
		ManifestSignedPath:                      manifestOutput.SignedPath,
		CoveragePath:                            coveragePath,
		SimulationPath:                          simulationPath,
		ValidationPath:                          validationPath,
		ResolvedSignedPath:                      resolvedOutput.SignedPath,
		RuntimeBundleSignedPath:                 runtimeBundleOutput.SignedPath,
		ContextRoutePackSignedPath:              contextRoutePackOutput.SignedPath,
		ConformanceExpectationSignedPath:        conformanceExpectationOutput.SignedPath,
		ResolvedSHA256:                          resolvedOutput.SHA256,
		RuntimeBundleSHA256:                     runtimeBundleOutput.SHA256,
		ContextRoutePackSHA256:                  contextRoutePackOutput.SHA256,
		ConformanceExpectationSHA256:            conformanceExpectationOutput.SHA256,
		ManifestSHA256:                          manifestOutput.SHA256,
		ManifestSignedSHA256:                    manifestOutput.SignedSHA256,
		ResolvedSignedSHA256:                    resolvedOutput.SignedSHA256,
		RuntimeBundleSignedSHA256:               runtimeBundleOutput.SignedSHA256,
		ContextRoutePackSignedSHA256:            contextRoutePackOutput.SignedSHA256,
		ConformanceExpectationSignedSHA256:      conformanceExpectationOutput.SignedSHA256,
		ResolvedArtifactRef:                     resolvedOutput.Ref,
		RuntimeBundleArtifactRef:                runtimeBundleOutput.Ref,
		ContextRoutePackArtifactRef:             contextRoutePackOutput.Ref,
		ConformanceExpectationArtifactRef:       conformanceExpectationOutput.Ref,
		ManifestArtifactRef:                     manifestOutput.Ref,
		ResolvedSignedArtifactRef:               resolvedOutput.SignedRef,
		RuntimeBundleSignedArtifactRef:          runtimeBundleOutput.SignedRef,
		ContextRoutePackSignedArtifactRef:       contextRoutePackOutput.SignedRef,
		ConformanceExpectationSignedArtifactRef: conformanceExpectationOutput.SignedRef,
		ManifestSignedArtifactRef:               manifestOutput.SignedRef,
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

func runtimeBundleArtifact(card *intent.Card, resolved ResolvedPolicy, metadata artifact.Metadata) bundle.RuntimeBundle {
	metadata.ID = "runtime_bundle." + card.ID
	metadata.ArtifactType = "runtime_bundle"
	actions := make([]bundle.RuntimeAction, 0, len(resolved.Spec.Runtime.Actions))
	grants := make([]bundle.CapabilityGrant, 0, len(resolved.Spec.Runtime.Actions))
	for _, action := range resolved.Spec.Runtime.Actions {
		actions = append(actions, bundle.RuntimeAction{Label: action.Label, CanonicalID: action.CanonicalID})
		if grant, ok := runtimeCapabilityGrant(card, resolved, action.CanonicalID); ok {
			grants = append(grants, grant)
		}
	}
	return bundle.RuntimeBundle{
		Kind:     "RuntimeBundle",
		Metadata: metadata,
		Spec: bundle.RuntimeBundleSpec{
			PolicyID:         card.ID,
			RuntimeAllowed:   resolved.Spec.Runtime.Allowed,
			RuntimeActions:   actions,
			CapabilityGrants: grants,
			MaxTTL:           resolved.Spec.Runtime.MaxTTL,
			MaxTTLSource:     resolved.Spec.Runtime.MaxTTLSource,
			MaxScope:         resolved.Spec.Runtime.MaxScope.Label,
			MaxScopeSource:   resolved.Spec.Runtime.MaxScopeSource,
		},
		Status: artifact.PlannedStatus("Runtime bundle is planned and locally verifiable. Real adapter execution is not implemented yet."),
	}
}

func runtimeCapabilityGrant(card *intent.Card, resolved ResolvedPolicy, actionType string) (bundle.CapabilityGrant, bool) {
	adapterID, capabilityID, ok := runtimeCapabilityForAction(actionType)
	if !ok {
		return bundle.CapabilityGrant{}, false
	}
	scope := resolved.Spec.Runtime.MaxScope.Label
	return bundle.CapabilityGrant{
		ID:                  capabilityGrantID(card.ID, adapterID, capabilityID, actionType, scope),
		AdapterID:           adapterID,
		CapabilityID:        capabilityID,
		ActionType:          actionType,
		AllowedTargetScopes: []string{scope},
		MaxTTL:              resolved.Spec.Runtime.MaxTTL,
		Stage:               card.Stage,
		Owner:               card.Owner,
		ApprovalRef:         "build." + card.ID,
	}, true
}

func runtimeCapabilityForAction(actionType string) (string, string, bool) {
	switch actionType {
	case "runtime_action.rate_limit_source", "runtime_action.deny_temporarily_source":
		return "kernloom.adapter.klshield", "klshield.runtime.source_mitigation", true
	default:
		return "", "", false
	}
}

func capabilityGrantID(policyID, adapterID, capabilityID, actionType, scope string) string {
	return "grant." + strings.TrimPrefix(sha256String(strings.Join([]string{policyID, adapterID, capabilityID, actionType, scope}, "\x00")), "sha256:")[:16]
}

func contextRoutePackArtifact(card *intent.Card, resolved ResolvedPolicy, metadata artifact.Metadata) corecontext.ContextRoutePack {
	metadata.ID = "context_route_pack." + card.ID
	metadata.ArtifactType = "context_route_pack"
	routes := make([]corecontext.ContextRoute, 0, len(resolved.Spec.Rules))
	for _, rule := range resolved.Spec.Rules {
		facts := make([]string, 0, len(rule.Conditions))
		for _, condition := range rule.Conditions {
			facts = append(facts, condition.CanonicalID)
		}
		routes = append(routes, corecontext.ContextRoute{
			Name:        rule.Name,
			Consumers:   []string{resolved.Spec.Target, "forge-simulation"},
			Facts:       facts,
			Sensitivity: "planned",
		})
	}
	return corecontext.ContextRoutePack{
		Kind:     "ContextRoutePack",
		Metadata: metadata,
		Spec: corecontext.ContextRoutePackSpec{
			PolicyID: card.ID,
			Target:   resolved.Spec.Target,
			Stage:    resolved.Spec.Stage,
			Routes:   routes,
		},
		Status: artifact.PlannedStatus("Context projection routing is planned; runtime enforcement is not active yet."),
	}
}

func conformanceExpectationArtifact(card *intent.Card, resolved ResolvedPolicy, metadata artifact.Metadata) conformance.ConformanceExpectation {
	metadata.ID = "conformance_expectation." + card.ID
	metadata.ArtifactType = "conformance_expectation"
	expectations := make([]conformance.Expectation, 0, len(resolved.Spec.Rules))
	for _, rule := range resolved.Spec.Rules {
		expectations = append(expectations, conformance.Expectation{
			Name:        rule.Name,
			Description: fmt.Sprintf("Expected effect %q for %q on %q remains unresolved-only until conformance execution exists.", rule.Effect.Label, rule.Action.Label, rule.Resource.Label),
		})
	}
	prohibit := make([]conformance.ProhibitedOutcome, 0, len(resolved.Spec.Prohibit))
	for _, outcome := range resolved.Spec.Prohibit {
		prohibit = append(prohibit, conformance.ProhibitedOutcome{Label: outcome.Label, CanonicalID: outcome.CanonicalID})
	}
	return conformance.ConformanceExpectation{
		Kind:     "ConformanceExpectation",
		Metadata: metadata,
		Spec: conformance.ConformanceExpectationSpec{
			PolicyID:     card.ID,
			Target:       resolved.Spec.Target,
			Stage:        resolved.Spec.Stage,
			Expectations: expectations,
			Prohibit:     prohibit,
		},
		Status: artifact.PlannedStatus("Conformance expectation is planned; evaluator is not implemented yet."),
	}
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

func adapterManifestRefs(opts Options) map[string]AdapterRef {
	return map[string]AdapterRef{
		"ziti": {
			ManifestDigest:  adapterRepoDigest(opts, "kernloom-adapter-ziti"),
			ProtocolVersion: "adapter/v1",
		},
		"klshield": {
			ManifestDigest:  adapterRepoDigest(opts, "kernloom-adapter-klshield"),
			ProtocolVersion: "adapter/v1",
		},
	}
}

func adapterRepoDigest(opts Options, repo string) string {
	for _, root := range workspaceRootCandidates(opts) {
		path := filepath.Join(root, repo)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return pathSHA256(path)
		}
	}
	return "sha256:unavailable"
}

func workspaceRootCandidates(opts Options) []string {
	seen := map[string]bool{}
	var roots []string
	add := func(path string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		if !seen[abs] {
			seen[abs] = true
			roots = append(roots, abs)
		}
	}
	for _, path := range []string{opts.PolicyRepo, opts.CoreRegistry, opts.EnterpriseRegistry} {
		if path == "" {
			continue
		}
		add(filepath.Dir(path))
	}
	add("..")
	add(".")
	return roots
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

type emittedArtifact struct {
	Path         string
	SHA256       string
	Ref          artifact.Ref
	SignedPath   string
	SignedSHA256 string
	SignedRef    artifact.Ref
	Envelope     signing.SignedEnvelope
}

func emitJSONArtifact(ctx context.Context, path string, value any, metadata artifact.Metadata, services compileRuntime, opts Options) (emittedArtifact, error) {
	writtenPath, hash, payload, err := writeJSONPayload(path, value)
	if err != nil {
		return emittedArtifact{}, err
	}
	ref, err := services.ArtifactStore.Put(ctx, artifact.Artifact{Metadata: metadata, Payload: payload})
	if err != nil {
		return emittedArtifact{}, err
	}
	output := emittedArtifact{Path: writtenPath, SHA256: hash, Ref: ref}
	if services.Signer == nil {
		return output, nil
	}
	envelope, err := services.Signer.Sign(ctx, payload, signing.Metadata{
		KeyID:        opts.SigningKeyID,
		PolicyID:     metadata.PolicyID,
		SourceCommit: metadata.SourceCommit,
		ExpiresAt:    services.ExpiresAt,
	})
	if err != nil {
		return emittedArtifact{}, err
	}
	signedPath := filepath.Join(opts.OutputDir, "signed", metadata.PolicyID+"."+metadata.ArtifactType+".signed.json")
	writtenSignedPath, signedHash, signedPayload, err := writeJSONPayload(signedPath, envelope)
	if err != nil {
		return emittedArtifact{}, err
	}
	signedMetadata := metadata
	signedMetadata.ID = "signed." + metadata.ID
	signedMetadata.ArtifactType = metadata.ArtifactType + "_signed_envelope"
	signedRef, err := services.ArtifactStore.Put(ctx, artifact.Artifact{Metadata: signedMetadata, Payload: signedPayload})
	if err != nil {
		return emittedArtifact{}, err
	}
	output.SignedPath = writtenSignedPath
	output.SignedSHA256 = signedHash
	output.SignedRef = signedRef
	output.Envelope = envelope
	return output, nil
}

func signedOutputs(outputs map[string]emittedArtifact) map[string]SignedOutputRef {
	signed := map[string]SignedOutputRef{}
	for name, output := range outputs {
		if output.SignedPath == "" {
			continue
		}
		signed[name] = SignedOutputRef{
			Path:           output.SignedPath,
			ArtifactRef:    output.SignedRef,
			EnvelopeSHA256: output.SignedSHA256,
			PayloadSHA256:  output.Envelope.PayloadSHA256,
			KeyID:          output.Envelope.KeyID,
		}
	}
	if len(signed) == 0 {
		return nil
	}
	return signed
}

func writeJSON(path string, value any) (string, string, error) {
	path, hash, _, err := writeJSONPayload(path, value)
	return path, hash, err
}

func writeJSONPayload(path string, value any) (string, string, []byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", "", nil, err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", "", nil, err
	}
	return path, sha256Bytes(data), data, nil
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
	} else {
		fmt.Fprintf(&b, "## Simulation Examples\n\n")
		fmt.Fprintf(&b, "- No simulation examples defined.\n\n")
	}
	fmt.Fprintf(&b, "## Reports\n\n")
	fmt.Fprintf(&b, "- Catalog resolution: `complete`\n")
	fmt.Fprintf(&b, "- Artifact storage: `complete`\n")
	fmt.Fprintf(&b, "- Artifact signing: `configured`\n")
	fmt.Fprintf(&b, "- Meaning coverage: `resolved_only`\n")
	fmt.Fprintf(&b, "- Simulation: `resolved_only`\n")
	fmt.Fprintf(&b, "- Risk recipe evaluation: `not_evaluated`\n")
	fmt.Fprintf(&b, "- Runtime execution: `not_evaluated`\n")
	fmt.Fprintf(&b, "- Validation: `not_evaluated`\n\n")
	fmt.Fprintf(&b, "## Findings\n\nnone blocking during Slice 3 artifact storage and signing\n")
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

func executableSHA256() string {
	path, err := os.Executable()
	if err != nil {
		return sha256String("forge:" + version.Version)
	}
	return fileSHA256(path)
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "sha256:unavailable"
	}
	return sha256Bytes(data)
}

func pathSHA256(path string) string {
	var parts []string
	info, err := os.Stat(path)
	if err != nil {
		return "sha256:unavailable"
	}
	if !info.IsDir() {
		return fileSHA256(path)
	}
	err = filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "generated" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		parts = append(parts, rel+"\x00"+sha256Bytes(data))
		return nil
	})
	if err != nil {
		return "sha256:unavailable"
	}
	sort.Strings(parts)
	return sha256String(strings.Join(parts, "\n"))
}

func digestJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "sha256:unavailable"
	}
	return sha256Bytes(data)
}

func sha256String(value string) string {
	return sha256Bytes([]byte(value))
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
