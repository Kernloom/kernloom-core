// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import "github.com/kernloom/kernloom-core/internal/core/registry"

type Options struct {
	PolicyRepo         string
	PolicyFile         string
	CoreRegistry       string
	EnterpriseRegistry string
	OutputDir          string
}

type Result struct {
	PolicyID       string
	ReviewPath     string
	ResolvedPath   string
	ManifestPath   string
	CoveragePath   string
	SimulationPath string
	ValidationPath string
	ResolvedSHA256 string
	ManifestSHA256 string
}

type ResolvedPolicy struct {
	Kind     string             `json:"kind"`
	Metadata ResolvedMetadata   `json:"metadata"`
	Spec     ResolvedPolicySpec `json:"spec"`
}

type ResolvedMetadata struct {
	ID           string `json:"id"`
	PolicyID     string `json:"policy_id"`
	SourcePath   string `json:"source_path"`
	SourceCommit string `json:"source_commit"`
}

type ResolvedPolicySpec struct {
	Version      string                 `json:"version"`
	Owner        string                 `json:"owner"`
	Type         string                 `json:"type"`
	Target       string                 `json:"target"`
	Stage        string                 `json:"stage"`
	Profile      string                 `json:"profile"`
	RiskRecipe   string                 `json:"risk_recipe"`
	Guardrails   []string               `json:"guardrails"`
	Rules        []ResolvedRule         `json:"rules"`
	RiskBehavior []ResolvedRiskBehavior `json:"risk_behavior,omitempty"`
	Prohibit     []ResolvedValue        `json:"prohibit,omitempty"`
	Runtime      ResolvedRuntime        `json:"runtime"`
	Simulations  []ResolvedSimulation   `json:"simulations,omitempty"`
}

type ResolvedRule struct {
	Name       string          `json:"name"`
	Effect     ResolvedValue   `json:"effect"`
	Subject    ResolvedValue   `json:"subject"`
	Action     ResolvedValue   `json:"action"`
	Resource   ResolvedValue   `json:"resource"`
	Conditions []ResolvedValue `json:"conditions"`
	CEL        string          `json:"cel"`
}

type ResolvedRiskBehavior struct {
	RiskType ResolvedValue `json:"risk_type"`
	Tier     ResolvedValue `json:"tier"`
	Effect   ResolvedValue `json:"effect"`
}

type ResolvedRuntime struct {
	Allowed        bool            `json:"allowed"`
	Actions        []ResolvedValue `json:"actions,omitempty"`
	MaxTTL         string          `json:"max_ttl"`
	MaxTTLSource   string          `json:"max_ttl_source"`
	MaxScope       ResolvedValue   `json:"max_scope"`
	MaxScopeSource string          `json:"max_scope_source"`
}

type ResolvedSimulation struct {
	Name         string          `json:"name"`
	Given        []ResolvedValue `json:"given"`
	ExpectEffect ResolvedValue   `json:"expect_effect"`
}

type ResolvedValue struct {
	Label       string `json:"label"`
	CanonicalID string `json:"canonical_id"`
	Kind        string `json:"kind"`
	CEL         string `json:"cel,omitempty"`
}

type PolicyBuildManifest struct {
	Kind     string           `json:"kind"`
	Metadata ManifestMetadata `json:"metadata"`
	Spec     ManifestSpec     `json:"spec"`
}

type ManifestMetadata struct {
	ID string `json:"id"`
}

type ManifestSpec struct {
	PolicyRepo         RepoRef               `json:"policy_repo"`
	EnterpriseRegistry RepoRef               `json:"enterprise_registry"`
	CoreRegistry       CoreRegistryRef       `json:"core_registry"`
	Compiler           CompilerRef           `json:"compiler"`
	Adapters           map[string]AdapterRef `json:"adapters"`
	Outputs            map[string]string     `json:"outputs"`
}

type RepoRef struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
}

type CoreRegistryRef struct {
	Repo    string `json:"repo"`
	Version string `json:"version"`
}

type CompilerRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type AdapterRef struct {
	ManifestDigest  string `json:"manifest_digest"`
	ProtocolVersion string `json:"protocol_version"`
}

type MeaningCoverageReport struct {
	Kind     string `json:"kind"`
	PolicyID string `json:"policy_id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type SimulationReport struct {
	Kind        string             `json:"kind"`
	PolicyID    string             `json:"policy_id"`
	Simulations []SimulationStatus `json:"simulations"`
	Findings    []string           `json:"findings"`
}

type SimulationStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type ValidationResult struct {
	Kind     string   `json:"kind"`
	PolicyID string   `json:"policy_id"`
	Status   string   `json:"status"`
	Passed   bool     `json:"passed"`
	Findings []string `json:"findings"`
}

func resolvedValue(value registry.Value) ResolvedValue {
	return ResolvedValue{
		Label:       value.Label,
		CanonicalID: value.CanonicalID,
		Kind:        value.Kind,
		CEL:         value.CEL,
	}
}
