// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/forge/adapterverify"
	"github.com/kernloom/kernloom-core/internal/forge/bindings"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"gopkg.in/yaml.v3"
)

type CIOptions struct {
	PolicyRepo         string
	CoreRegistry       string
	EnterpriseRegistry string
	Tenant             string
	Environment        string
	Provider           string
	Repository         string
	Commit             string
	PullRequest        string
	BasePath           string
	TargetID           string
	ChangedPaths       []string
	ConfigSnapshot     string
	OutputDir          string
	AdapterVerify      AdapterVerifyOptions
}

type AdapterVerifyOptions struct {
	Endpoint                string
	Manifest                string
	DevInsecureTransport    bool
	CAPath                  string
	ClientCertPath          string
	ClientKeyPath           string
	TLSServerName           string
	ServerCertificateSHA256 string
	Timeout                 time.Duration
}

type CIValidationResult struct {
	Kind           string                `json:"kind"`
	Status         string                `json:"status"`
	Request        CIRequestReport       `json:"request"`
	Target         *TargetReport         `json:"target,omitempty"`
	AdapterRuntime *adapterverify.Result `json:"adapter_runtime,omitempty"`
	PolicySources  []SourceReport        `json:"policy_sources,omitempty"`
	Bindings       []BindingReport       `json:"bindings,omitempty"`
	Compile        *CompileReport        `json:"compile,omitempty"`
	Provenance     map[string]string     `json:"provenance,omitempty"`
	Findings       []Finding             `json:"findings"`
}

type CIRequestReport struct {
	Tenant         string   `json:"tenant"`
	Environment    string   `json:"environment"`
	Provider       string   `json:"provider,omitempty"`
	Repository     string   `json:"repository"`
	Commit         string   `json:"commit,omitempty"`
	PullRequest    string   `json:"pull_request,omitempty"`
	BasePath       string   `json:"base_path,omitempty"`
	TargetID       string   `json:"target_id,omitempty"`
	ChangedPaths   []string `json:"changed_paths,omitempty"`
	ConfigSnapshot string   `json:"config_snapshot,omitempty"`
}

type TargetReport struct {
	ID                 string   `json:"id"`
	URN                string   `json:"urn"`
	Tenant             string   `json:"tenant"`
	Environment        string   `json:"environment"`
	Adapter            string   `json:"adapter"`
	AdapterVersion     string   `json:"adapter_version,omitempty"`
	ValidationProfiles []string `json:"validation_profiles,omitempty"`
	RepoRef            string   `json:"repo_ref"`
	BasePath           string   `json:"base_path"`
	Digest             string   `json:"digest"`
}

type SourceReport struct {
	ID             string                `json:"id"`
	Type           string                `json:"type"`
	RepoRef        string                `json:"repo_ref"`
	Visibility     string                `json:"visibility,omitempty"`
	Owner          string                `json:"owner,omitempty"`
	PolicyFiles    []string              `json:"policy_files,omitempty"`
	PolicyMeanings []PolicyMeaningReport `json:"policy_meanings,omitempty"`
}

type PolicyMeaningReport struct {
	PolicyPath       string   `json:"policy_path"`
	CanonicalActions []string `json:"canonical_actions,omitempty"`
	ActionTypes      []string `json:"action_types,omitempty"`
}

type BindingReport struct {
	ActionID        string `json:"action_id"`
	ActionURN       string `json:"action_urn,omitempty"`
	ResourceRef     string `json:"resource_ref,omitempty"`
	CanonicalAction string `json:"canonical_action"`
	ActionType      string `json:"action_type"`
	Sensitivity     string `json:"sensitivity"`
	BindingID       string `json:"binding_id"`
	Capability      string `json:"capability"`
	SelectorType    string `json:"selector_type"`
	BindingDigest   string `json:"binding_digest"`
}

type CompileReport struct {
	Status    string   `json:"status"`
	Policies  int      `json:"policies"`
	OutputDir string   `json:"output_dir,omitempty"`
	PolicyIDs []string `json:"policy_ids,omitempty"`
	Files     []string `json:"files,omitempty"`
}

type Finding struct {
	Code      string `json:"code"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	TargetID  string `json:"target_id,omitempty"`
	BindingID string `json:"binding_id,omitempty"`
	Path      string `json:"path,omitempty"`
}

func ValidateCI(opts CIOptions) CIValidationResult {
	applyDefaults(&opts)
	result := CIValidationResult{
		Kind:   "CIValidationResult",
		Status: "passed",
		Request: CIRequestReport{
			Tenant:         opts.Tenant,
			Environment:    opts.Environment,
			Provider:       opts.Provider,
			Repository:     opts.Repository,
			Commit:         opts.Commit,
			PullRequest:    opts.PullRequest,
			BasePath:       opts.BasePath,
			TargetID:       opts.TargetID,
			ChangedPaths:   append([]string(nil), opts.ChangedPaths...),
			ConfigSnapshot: opts.ConfigSnapshot,
		},
		Findings: []Finding{},
	}

	if opts.Tenant == "" {
		result.add("validation_request_invalid", "error", "tenant is required", "", "", "")
	}
	if opts.Environment == "" {
		result.add("validation_request_invalid", "error", "environment is required", "", "", "")
	}
	if opts.Repository == "" {
		result.add("validation_request_invalid", "error", "repo is required", "", "", "")
	}
	if result.failed() {
		result.finalize()
		return result
	}

	catalog, err := registry.Load(opts.CoreRegistry, opts.EnterpriseRegistry)
	if err != nil {
		result.add("registry_invalid", "error", err.Error(), "", "", "")
		result.finalize()
		return result
	}
	adapterManifests, err := compiler.LoadAdapterManifests(compiler.Options{
		PolicyRepo:         opts.PolicyRepo,
		CoreRegistry:       opts.CoreRegistry,
		EnterpriseRegistry: opts.EnterpriseRegistry,
	})
	if err != nil {
		result.add("adapter_manifest_invalid", "error", err.Error(), "", "", "")
		result.finalize()
		return result
	}
	if err := compiler.ValidateAdapterManifests(catalog, adapterManifests); err != nil {
		result.add("adapter_manifest_invalid", "error", err.Error(), "", "", "")
		result.finalize()
		return result
	}

	store, err := bindings.Load(opts.PolicyRepo, opts.EnterpriseRegistry)
	if err != nil {
		result.add(bindingErrorCode(err, "policy_source_unavailable"), "error", err.Error(), "", "", "")
		result.finalize()
		return result
	}
	resolved, err := store.ResolveCIRequest(bindings.CIRequest{
		Tenant:       opts.Tenant,
		Environment:  opts.Environment,
		Provider:     opts.Provider,
		Repository:   opts.Repository,
		BasePath:     opts.BasePath,
		TargetID:     opts.TargetID,
		ChangedPaths: opts.ChangedPaths,
	})
	if err != nil {
		result.add(bindingErrorCode(err, "validation_target_not_found"), "error", err.Error(), "", "", "")
		result.finalize()
		return result
	}
	result.Target = targetReport(resolved.Target)
	result.Provenance = map[string]string{
		"repository_bindings": store.RepositoryBindingsDigest,
		"canonical_actions":   store.CanonicalActionsDigest,
		"policy_sources":      store.PolicySourcesDigest,
		"target_inventory":    resolved.Target.Digest,
	}
	result.PolicySources = sourceReports(resolved.PolicySources)
	result.validateCanonicalActions(catalog, store)
	result.validateResolvedTarget(catalog, adapterManifests, store, resolved)
	result.validatePolicyBindingMatches(catalog, store, resolved)
	result.verifyAdapterRuntime(opts, adapterManifests, resolved)
	result.validateConfigSnapshot(opts, resolved)
	result.compilePolicyMeaning(opts, store, resolved)
	result.finalize()
	return result
}

func (r *CIValidationResult) verifyAdapterRuntime(opts CIOptions, manifests map[string]compiler.AdapterManifest, resolved bindings.ResolvedTarget) {
	if strings.TrimSpace(opts.AdapterVerify.Endpoint) == "" {
		return
	}
	target := resolved.Target.Target
	manifest, ok := manifests[target.Adapter]
	if !ok {
		r.add("adapter_runtime_verify_failed", "error", fmt.Sprintf("target %q references adapter %q without adapter manifest", target.ID, target.Adapter), target.ID, "", resolved.Target.Path)
		return
	}
	if strings.TrimSpace(opts.AdapterVerify.Manifest) != "" {
		loaded, err := compiler.LoadAdapterManifestFile(opts.AdapterVerify.Manifest)
		if err != nil {
			r.add("adapter_runtime_verify_failed", "error", err.Error(), target.ID, "", opts.AdapterVerify.Manifest)
			return
		}
		manifest = loaded
	}
	verify := adapterverify.Verify(context.Background(), adapterverify.Options{
		AdapterID:               target.Adapter,
		Endpoint:                opts.AdapterVerify.Endpoint,
		Manifest:                manifest,
		DevInsecureTransport:    opts.AdapterVerify.DevInsecureTransport,
		CAPath:                  opts.AdapterVerify.CAPath,
		ClientCertPath:          opts.AdapterVerify.ClientCertPath,
		ClientKeyPath:           opts.AdapterVerify.ClientKeyPath,
		TLSServerName:           opts.AdapterVerify.TLSServerName,
		ServerCertificateSHA256: opts.AdapterVerify.ServerCertificateSHA256,
		Timeout:                 opts.AdapterVerify.Timeout,
	})
	r.AdapterRuntime = &verify
	if r.Provenance != nil && verify.ManifestDigest != "" {
		r.Provenance["adapter_runtime:"+target.Adapter] = verify.ManifestDigest
	}
	if verify.Status != "passed" {
		message := "adapter runtime verify failed"
		if len(verify.Findings) > 0 {
			message = verify.Findings[0].Message
		}
		r.add("adapter_runtime_verify_failed", "error", message, target.ID, "", manifest.Path)
	}
}

func (r *CIValidationResult) validateCanonicalActions(catalog *registry.Catalog, store bindings.Store) {
	for _, action := range store.CanonicalActions {
		if _, ok := catalog.CatalogEntry("action_type", action.Type); !ok {
			r.add("unknown_action_type", "error", fmt.Sprintf("canonical action %q references unknown action type %q", action.ID, action.Type), "", "", store.CanonicalActionsPath)
		}
		for _, eventID := range action.RequiredEvents {
			if _, ok := catalog.CatalogEntry("event", eventID); !ok {
				r.add("event_not_found", "error", fmt.Sprintf("canonical action %q requires unknown event %q", action.ID, eventID), "", "", store.CanonicalActionsPath)
			}
		}
	}
}

func (r *CIValidationResult) validateResolvedTarget(catalog *registry.Catalog, manifests map[string]compiler.AdapterManifest, store bindings.Store, resolved bindings.ResolvedTarget) {
	target := resolved.Target.Target
	manifest, ok := manifests[target.Adapter]
	if !ok {
		r.add("adapter_manifest_missing", "error", fmt.Sprintf("target %q references adapter %q without adapter manifest", target.ID, target.Adapter), target.ID, "", resolved.Target.Path)
		return
	}
	if target.AdapterVersion != "" && manifest.AdapterVersion != "" && target.AdapterVersion != manifest.AdapterVersion {
		r.add("adapter_manifest_version_mismatch", "error", fmt.Sprintf("target %q expects adapter %q version %q but manifest declares %q", target.ID, target.Adapter, target.AdapterVersion, manifest.AdapterVersion), target.ID, "", resolved.Target.Path)
	}
	for _, capabilityID := range target.Capabilities {
		capability, ok := catalog.Capability(capabilityID)
		if !ok {
			r.add("capability_not_found", "error", fmt.Sprintf("target %q references unknown capability %q", target.ID, capabilityID), target.ID, "", resolved.Target.Path)
			continue
		}
		if capability.Status == "planned" {
			r.add("capability_not_ready", "error", fmt.Sprintf("target %q references planned capability %q", target.ID, capabilityID), target.ID, "", resolved.Target.Path)
		}
		if !manifestHasCapability(manifest, capabilityID, true) {
			r.add("adapter_capability_not_implemented", "error", fmt.Sprintf("adapter %q does not implement target capability %q", target.Adapter, capabilityID), target.ID, "", manifest.Path)
		}
	}
	for _, profileID := range target.ValidationProfiles {
		entry, ok := catalog.CatalogEntry("validation_profile", profileID)
		if !ok {
			r.add("validation_profile_not_found", "error", fmt.Sprintf("target %q references unknown validation profile %q", target.ID, profileID), target.ID, "", resolved.Target.Path)
			continue
		}
		if entry.Status == "planned" {
			r.add("validation_profile_not_ready", "error", fmt.Sprintf("target %q references planned validation profile %q", target.ID, profileID), target.ID, "", resolved.Target.Path)
		}
	}
	for _, resolvedBinding := range resolved.Bindings {
		report := bindingReport(resolvedBinding)
		r.Bindings = append(r.Bindings, report)
		r.Provenance["action_binding:"+resolvedBinding.Binding.ID] = resolvedBinding.File.Digest
		if resolvedBinding.Resource != nil {
			r.Provenance["resource:"+resolvedBinding.File.Application.ID] = resolvedBinding.Resource.Digest
		}
		if resolvedBinding.ProofRequirements != nil {
			r.Provenance["proof_requirements:"+resolvedBinding.File.Application.ID] = resolvedBinding.ProofRequirements.Digest
		}
		r.validateBinding(catalog, manifest, store, target, resolvedBinding)
	}
	sort.Slice(r.Bindings, func(i, j int) bool {
		if r.Bindings[i].ActionID == r.Bindings[j].ActionID {
			return r.Bindings[i].BindingID < r.Bindings[j].BindingID
		}
		return r.Bindings[i].ActionID < r.Bindings[j].ActionID
	})
}

func (r *CIValidationResult) validateBinding(catalog *registry.Catalog, manifest compiler.AdapterManifest, store bindings.Store, target bindings.Target, resolved bindings.ResolvedBinding) {
	action := resolved.Action
	binding := resolved.Binding
	canonicalAction, hasCanonicalAction := bindings.CanonicalAction{}, false
	if strings.TrimSpace(action.CanonicalAction) == "" {
		if isSensitive(action.Sensitivity) {
			r.add("missing_canonical_action_mapping", "error", fmt.Sprintf("sensitive action %q does not declare canonical_action", action.ID), target.ID, binding.ID, resolved.File.Path)
		}
	} else {
		canonicalAction, hasCanonicalAction = store.CanonicalAction(action.CanonicalAction)
		if !hasCanonicalAction {
			r.add("missing_canonical_action_mapping", "error", fmt.Sprintf("action %q references unknown canonical action %q", action.ID, action.CanonicalAction), target.ID, binding.ID, resolved.File.Path)
		} else if strings.TrimSpace(action.Type) != "" && canonicalAction.Type != strings.TrimSpace(action.Type) {
			r.add("missing_canonical_action_mapping", "error", fmt.Sprintf("action %q maps to canonical action %q of type %q but declares type %q", action.ID, action.CanonicalAction, canonicalAction.Type, action.Type), target.ID, binding.ID, resolved.File.Path)
		}
	}
	if _, ok := catalog.CatalogEntry("action_type", action.Type); !ok {
		r.add("unknown_action_type", "error", fmt.Sprintf("action %q references unknown action type %q", action.ID, action.Type), target.ID, binding.ID, resolved.File.Path)
	}
	if strings.TrimSpace(binding.Capability) == "" {
		r.add("required_control_missing", "error", fmt.Sprintf("binding %q does not declare a required capability", binding.ID), target.ID, binding.ID, resolved.File.Path)
	} else if _, ok := catalog.Capability(binding.Capability); !ok {
		r.add("capability_not_found", "error", fmt.Sprintf("binding %q references unknown capability %q", binding.ID, binding.Capability), target.ID, binding.ID, resolved.File.Path)
	} else if !contains(target.Capabilities, binding.Capability) {
		r.add("binding_capability_outside_target_scope", "error", fmt.Sprintf("binding %q capability %q is not declared by target %q", binding.ID, binding.Capability, target.ID), target.ID, binding.ID, resolved.File.Path)
	}
	selectorType := selectorType(binding.Selector)
	if selectorType == "" {
		r.add("binding_selector_not_enforced", "error", fmt.Sprintf("binding %q does not declare selector.type", binding.ID), target.ID, binding.ID, resolved.File.Path)
	} else {
		entry, ok := catalog.CatalogEntry("selector_schema", selectorType)
		if !ok {
			r.add("binding_selector_not_enforced", "error", fmt.Sprintf("binding %q references unknown selector schema %q", binding.ID, selectorType), target.ID, binding.ID, resolved.File.Path)
			r.add("selector_schema_not_found", "error", fmt.Sprintf("binding %q references unknown selector schema %q", binding.ID, selectorType), target.ID, binding.ID, resolved.File.Path)
		} else if entry.Status == "planned" {
			r.add("binding_selector_not_enforced", "error", fmt.Sprintf("binding %q selector schema %q is not enforceable yet", binding.ID, selectorType), target.ID, binding.ID, resolved.File.Path)
			r.add("selector_schema_not_ready", "error", fmt.Sprintf("binding %q references planned selector schema %q", binding.ID, selectorType), target.ID, binding.ID, resolved.File.Path)
		}
	}
	if strings.TrimSpace(binding.Capability) != "" && !manifestHasCapability(manifest, binding.Capability, true) {
		r.add("adapter_capability_not_implemented", "error", fmt.Sprintf("adapter %q does not implement binding capability %q", target.Adapter, binding.Capability), target.ID, binding.ID, manifest.Path)
	}
	for _, eventID := range binding.Proof.ExpectedEvents {
		if _, ok := catalog.CatalogEntry("event", eventID); !ok {
			r.add("event_not_found", "error", fmt.Sprintf("binding %q proof references unknown event %q", binding.ID, eventID), target.ID, binding.ID, resolved.File.Path)
		}
	}
	if isSensitive(action.Sensitivity) && len(binding.Proof.ExpectedEvents) == 0 {
		r.add("required_control_missing", "error", fmt.Sprintf("sensitive action %q binding %q does not declare proof.expected_events", action.ID, binding.ID), target.ID, binding.ID, resolved.File.Path)
	}
	if hasCanonicalAction {
		for _, controlID := range canonicalAction.RequiredControls {
			if !contains(binding.Controls, controlID) {
				r.add("required_control_missing", "error", fmt.Sprintf("binding %q for canonical action %q is missing required control %q", binding.ID, canonicalAction.ID, controlID), target.ID, binding.ID, resolved.File.Path)
			}
		}
		for _, eventID := range canonicalAction.RequiredEvents {
			if !contains(binding.Proof.ExpectedEvents, eventID) {
				r.add("required_control_missing", "error", fmt.Sprintf("binding %q for canonical action %q is missing required proof event %q", binding.ID, canonicalAction.ID, eventID), target.ID, binding.ID, resolved.File.Path)
			}
		}
	}
	if isSensitive(action.Sensitivity) && approvalStatus(action.Approval, binding.Approval) != "approved" {
		r.add("binding_not_approved", "error", fmt.Sprintf("sensitive action %q binding %q is not approved", action.ID, binding.ID), target.ID, binding.ID, resolved.File.Path)
	}
}

func (r *CIValidationResult) validatePolicyBindingMatches(catalog *registry.Catalog, store bindings.Store, resolved bindings.ResolvedTarget) {
	meanings := policyMeaningsForSources(resolved.PolicySources)
	for _, meaning := range meanings {
		for _, canonicalActionID := range meaning.CanonicalActions {
			if _, ok := store.CanonicalAction(canonicalActionID); !ok {
				r.add("missing_canonical_action_mapping", "error", fmt.Sprintf("policy meaning for %q references unknown canonical action %q", meaning.PolicyPath, canonicalActionID), resolved.Target.Target.ID, "", store.PolicySourcesPath)
			}
		}
		for _, actionType := range meaning.ActionTypes {
			if _, ok := catalog.CatalogEntry("action_type", actionType); !ok {
				r.add("unknown_action_type", "error", fmt.Sprintf("policy meaning for %q references unknown action type %q", meaning.PolicyPath, actionType), resolved.Target.Target.ID, "", store.PolicySourcesPath)
			}
		}
	}
	for _, resolvedBinding := range resolved.Bindings {
		action := resolvedBinding.Action
		if !isSensitive(action.Sensitivity) {
			continue
		}
		if strings.TrimSpace(action.CanonicalAction) == "" || strings.TrimSpace(action.Type) == "" {
			continue
		}
		if policyMeaningMatchesAction(meanings, action) {
			continue
		}
		r.add("unmapped_sensitive_action", "error", fmt.Sprintf("sensitive action %q has no resolved policy meaning for canonical action %q or action type %q", action.ID, action.CanonicalAction, action.Type), resolved.Target.Target.ID, resolvedBinding.Binding.ID, resolvedBinding.File.Path)
	}
}

func (r *CIValidationResult) validateConfigSnapshot(opts CIOptions, resolved bindings.ResolvedTarget) {
	if len(opts.ChangedPaths) == 0 && opts.ConfigSnapshot == "" {
		return
	}
	if opts.ConfigSnapshot == "" {
		r.add("config_snapshot_unavailable", "error", "changed paths were provided but --config-snapshot is missing", resolved.Target.Target.ID, "", "")
		return
	}
	for _, changedPath := range opts.ChangedPaths {
		cleaned := cleanRel(changedPath)
		if cleaned == "" {
			continue
		}
		if !strings.HasPrefix(cleaned, cleanRel(resolved.Target.Target.ValidationSource.BasePath)+"/") && cleaned != cleanRel(resolved.Target.Target.ValidationSource.BasePath) {
			continue
		}
		snapshotPath := filepath.Join(opts.ConfigSnapshot, filepath.FromSlash(cleaned))
		if _, err := os.Stat(snapshotPath); err != nil {
			r.add("config_snapshot_unavailable", "error", fmt.Sprintf("changed path %q is not available in config snapshot", cleaned), resolved.Target.Target.ID, "", snapshotPath)
		}
	}
	r.validateTargetConfigSnapshot(opts.ConfigSnapshot, resolved)
}

func (r *CIValidationResult) validateTargetConfigSnapshot(snapshotRoot string, resolved bindings.ResolvedTarget) {
	target := resolved.Target.Target
	baseRoot := filepath.Join(snapshotRoot, filepath.FromSlash(cleanRel(target.ValidationSource.BasePath)))
	if _, err := os.Stat(baseRoot); err != nil {
		r.add("config_snapshot_unavailable", "error", fmt.Sprintf("target config base path %q is not available in config snapshot", target.ValidationSource.BasePath), target.ID, "", baseRoot)
		return
	}
	switch target.Adapter {
	case "kernloom.adapter.klshield":
		r.validateKLShieldConfigSnapshot(baseRoot, resolved)
	}
}

type klshieldRuntimeActionConfig struct {
	Capability string         `yaml:"capability"`
	Selector   map[string]any `yaml:"selector"`
	Controls   []string       `yaml:"controls"`
	Proof      bindings.Proof `yaml:"proof"`
}

func (r *CIValidationResult) validateKLShieldConfigSnapshot(baseRoot string, resolved bindings.ResolvedTarget) {
	actions, err := loadKLShieldRuntimeActionConfigs(baseRoot)
	if err != nil {
		r.add("config_snapshot_unavailable", "error", err.Error(), resolved.Target.Target.ID, "", baseRoot)
		return
	}
	for _, resolvedBinding := range resolved.Bindings {
		if !isSensitive(resolvedBinding.Action.Sensitivity) {
			continue
		}
		action, ok := findKLShieldRuntimeActionConfig(actions, resolvedBinding.Binding)
		if !ok {
			r.add("binding_selector_not_enforced", "error", fmt.Sprintf("KLShield config snapshot has no runtime action control matching binding %q capability %q and selector %q", resolvedBinding.Binding.ID, resolvedBinding.Binding.Capability, selectorType(resolvedBinding.Binding.Selector)), resolved.Target.Target.ID, resolvedBinding.Binding.ID, baseRoot)
			continue
		}
		for _, controlID := range resolvedBinding.Binding.Controls {
			if !contains(action.Controls, controlID) {
				r.add("required_control_missing", "error", fmt.Sprintf("KLShield config action for binding %q is missing control %q", resolvedBinding.Binding.ID, controlID), resolved.Target.Target.ID, resolvedBinding.Binding.ID, baseRoot)
			}
		}
		for _, eventID := range resolvedBinding.Binding.Proof.ExpectedEvents {
			if !contains(action.Proof.ExpectedEvents, eventID) {
				r.add("required_control_missing", "error", fmt.Sprintf("KLShield config action for binding %q is missing proof event %q", resolvedBinding.Binding.ID, eventID), resolved.Target.Target.ID, resolvedBinding.Binding.ID, baseRoot)
			}
		}
	}
}

func loadKLShieldRuntimeActionConfigs(baseRoot string) ([]klshieldRuntimeActionConfig, error) {
	var actions []klshieldRuntimeActionConfig
	err := filepath.WalkDir(baseRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc struct {
			RuntimeActions []klshieldRuntimeActionConfig `yaml:"runtime_actions"`
			Spec           struct {
				RuntimeActions []klshieldRuntimeActionConfig `yaml:"runtime_actions"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if len(doc.RuntimeActions) > 0 {
			actions = append(actions, doc.RuntimeActions...)
		}
		if len(doc.Spec.RuntimeActions) > 0 {
			actions = append(actions, doc.Spec.RuntimeActions...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return actions, nil
}

func findKLShieldRuntimeActionConfig(actions []klshieldRuntimeActionConfig, binding bindings.ActionBinding) (klshieldRuntimeActionConfig, bool) {
	for _, action := range actions {
		if strings.TrimSpace(action.Capability) != strings.TrimSpace(binding.Capability) {
			continue
		}
		if selectorContains(action.Selector, binding.Selector) {
			return action, true
		}
	}
	return klshieldRuntimeActionConfig{}, false
}

func selectorContains(candidate, expected map[string]any) bool {
	if len(expected) == 0 {
		return false
	}
	for key, expectedValue := range expected {
		candidateValue, ok := candidate[key]
		if !ok || strings.TrimSpace(fmt.Sprint(candidateValue)) != strings.TrimSpace(fmt.Sprint(expectedValue)) {
			return false
		}
	}
	return true
}

func (r *CIValidationResult) compilePolicyMeaning(opts CIOptions, store bindings.Store, resolved bindings.ResolvedTarget) {
	outputDir := opts.OutputDir
	if outputDir == "" {
		tempDir, err := os.MkdirTemp("", "kernloom-ci-validate-*")
		if err != nil {
			r.add("policy_source_unavailable", "error", err.Error(), "", "", "")
			return
		}
		outputDir = tempDir
	}
	policyFiles := store.PolicyFiles(resolved.PolicySources)
	if len(policyFiles) == 0 {
		r.Compile = &CompileReport{Status: "failed", OutputDir: outputDir}
		r.add("policy_source_unavailable", "error", "resolved target has no scoped policy files", resolved.Target.Target.ID, "", "")
		return
	}
	var policyIDs []string
	var compiledFiles []string
	for _, file := range policyFiles {
		r.Provenance["policy_file:"+file.RelPath] = file.Digest
		results, err := compiler.Compile(compiler.Options{
			PolicyRepo:         opts.PolicyRepo,
			PolicyFile:         file.Path,
			CoreRegistry:       opts.CoreRegistry,
			EnterpriseRegistry: opts.EnterpriseRegistry,
			OutputDir:          outputDir,
			SigningMode:        compiler.SigningModeNone,
		})
		if err != nil {
			r.Compile = &CompileReport{Status: "failed", OutputDir: outputDir, Files: compiledFiles}
			r.add("policy_meaning_compile_failed", "error", err.Error(), resolved.Target.Target.ID, "", file.Path)
			return
		}
		compiledFiles = append(compiledFiles, file.RelPath)
		for _, result := range results {
			policyIDs = append(policyIDs, result.PolicyID)
		}
	}
	sort.Strings(policyIDs)
	sort.Strings(compiledFiles)
	r.Compile = &CompileReport{Status: "passed", Policies: len(policyIDs), OutputDir: outputDir, PolicyIDs: policyIDs, Files: compiledFiles}
}

func (r *CIValidationResult) add(code, severity, message, targetID, bindingID, path string) {
	r.Findings = append(r.Findings, Finding{
		Code:      code,
		Severity:  severity,
		Message:   message,
		TargetID:  targetID,
		BindingID: bindingID,
		Path:      path,
	})
}

func (r *CIValidationResult) failed() bool {
	for _, finding := range r.Findings {
		if finding.Severity == "error" {
			return true
		}
	}
	return false
}

func (r *CIValidationResult) finalize() {
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Code == r.Findings[j].Code {
			return r.Findings[i].Message < r.Findings[j].Message
		}
		return r.Findings[i].Code < r.Findings[j].Code
	})
	if r.failed() {
		r.Status = "failed"
		return
	}
	r.Status = "passed"
}

func applyDefaults(opts *CIOptions) {
	if opts.PolicyRepo == "" {
		opts.PolicyRepo = "../enterprise-kernloom-policies"
	}
	if opts.CoreRegistry == "" {
		opts.CoreRegistry = "../kernloom-core-registry"
	}
	if opts.EnterpriseRegistry == "" {
		opts.EnterpriseRegistry = "../enterprise-kernloom-registry"
	}
}

func targetReport(target bindings.TargetInventory) *TargetReport {
	return &TargetReport{
		ID:                 target.Target.ID,
		URN:                bindings.URNForTarget(target.Target.Tenant, target.Target.Environment, target.Target.ID),
		Tenant:             target.Target.Tenant,
		Environment:        target.Target.Environment,
		Adapter:            target.Target.Adapter,
		AdapterVersion:     target.Target.AdapterVersion,
		ValidationProfiles: append([]string(nil), target.Target.ValidationProfiles...),
		RepoRef:            target.Target.ValidationSource.RepoRef,
		BasePath:           target.Target.ValidationSource.BasePath,
		Digest:             target.Digest,
	}
}

func sourceReports(sources []bindings.ResolvedPolicySource) []SourceReport {
	reports := make([]SourceReport, 0, len(sources))
	for _, source := range sources {
		report := SourceReport{
			ID:         source.Source.ID,
			Type:       source.Source.Type,
			RepoRef:    source.Source.RepoRef,
			Visibility: source.Source.Visibility,
			Owner:      source.Source.Owner,
		}
		for _, file := range source.PolicyFiles {
			report.PolicyFiles = append(report.PolicyFiles, file.RelPath)
		}
		for _, meaning := range source.Source.PolicyMeanings {
			report.PolicyMeanings = append(report.PolicyMeanings, PolicyMeaningReport{
				PolicyPath:       cleanRel(meaning.PolicyPath),
				CanonicalActions: append([]string(nil), meaning.CanonicalActions...),
				ActionTypes:      append([]string(nil), meaning.ActionTypes...),
			})
		}
		sort.Strings(report.PolicyFiles)
		sort.Slice(report.PolicyMeanings, func(i, j int) bool {
			return report.PolicyMeanings[i].PolicyPath < report.PolicyMeanings[j].PolicyPath
		})
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].ID < reports[j].ID
	})
	return reports
}

func bindingReport(resolved bindings.ResolvedBinding) BindingReport {
	return BindingReport{
		ActionID:        resolved.Action.ID,
		ActionURN:       resolved.ActionURN,
		ResourceRef:     resolved.ResourceRef,
		CanonicalAction: resolved.Action.CanonicalAction,
		ActionType:      resolved.Action.Type,
		Sensitivity:     resolved.Action.Sensitivity,
		BindingID:       resolved.Binding.ID,
		Capability:      resolved.Binding.Capability,
		SelectorType:    selectorType(resolved.Binding.Selector),
		BindingDigest:   resolved.File.Digest,
	}
}

func bindingErrorCode(err error, fallback string) string {
	var bindingErr bindings.Error
	if errors.As(err, &bindingErr) && bindingErr.Code != "" {
		return bindingErr.Code
	}
	return fallback
}

func manifestHasCapability(manifest compiler.AdapterManifest, capabilityID string, requireImplemented bool) bool {
	for _, capability := range manifest.Capabilities {
		if capability.CapabilityID != capabilityID {
			continue
		}
		if requireImplemented && capability.ImplementationStatus != "implemented" {
			return false
		}
		return true
	}
	return false
}

func selectorType(selector map[string]any) string {
	value, ok := selector["type"]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func isSensitive(sensitivity string) bool {
	switch strings.ToLower(strings.TrimSpace(sensitivity)) {
	case "medium", "high", "critical", "sensitive":
		return true
	default:
		return false
	}
}

func policyMeaningsForSources(sources []bindings.ResolvedPolicySource) []bindings.PolicyMeaning {
	var meanings []bindings.PolicyMeaning
	for _, source := range sources {
		if source.Source.Type != "policy_repo" {
			continue
		}
		for _, meaning := range source.Source.PolicyMeanings {
			meaning.PolicyPath = cleanRel(meaning.PolicyPath)
			meanings = append(meanings, meaning)
		}
	}
	sort.Slice(meanings, func(i, j int) bool {
		return meanings[i].PolicyPath < meanings[j].PolicyPath
	})
	return meanings
}

func policyMeaningMatchesAction(meanings []bindings.PolicyMeaning, action bindings.BusinessAction) bool {
	for _, meaning := range meanings {
		if contains(meaning.CanonicalActions, action.CanonicalAction) || contains(meaning.ActionTypes, action.Type) {
			return true
		}
	}
	return false
}

func approvalStatus(values ...bindings.Approval) string {
	for _, approval := range values {
		if status := strings.TrimSpace(approval.Status); status != "" {
			return status
		}
	}
	return ""
}

func contains(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, value := range values {
		if strings.TrimSpace(value) == needle {
			return true
		}
	}
	return false
}

func cleanRel(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(path))
}
