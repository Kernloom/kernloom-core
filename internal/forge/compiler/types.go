// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"time"

	coreartifact "github.com/kernloom/kernloom-core/internal/core/artifact"
	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/storage/artifactstore"
)

type Options struct {
	PolicyRepo               string
	PolicyFile               string
	CoreRegistry             string
	EnterpriseRegistry       string
	OutputDir                string
	ArtifactStoreRoot        string
	ArtifactStoreOrg         string
	ArtifactStoreEnvironment string
	ArtifactStore            artifactstore.ArtifactStore
	SigningMode              string
	SigningKeyPath           string
	SigningKeyID             string
	CorrelationID            string
	BuildCreatedBy           string
	SignatureTTL             time.Duration
	Signer                   signing.Signer
	Now                      func() time.Time
}

type Result struct {
	PolicyID                                string
	ReviewPath                              string
	ResolvedPath                            string
	RuntimeBundlePath                       string
	ContextRoutePackPath                    string
	ConformanceExpectationPath              string
	ManifestPath                            string
	ManifestSignedPath                      string
	CoveragePath                            string
	SimulationPath                          string
	ValidationPath                          string
	ResolvedSignedPath                      string
	RuntimeBundleSignedPath                 string
	ContextRoutePackSignedPath              string
	ConformanceExpectationSignedPath        string
	ResolvedSHA256                          string
	RuntimeBundleSHA256                     string
	ContextRoutePackSHA256                  string
	ConformanceExpectationSHA256            string
	ManifestSHA256                          string
	ManifestSignedSHA256                    string
	ResolvedSignedSHA256                    string
	RuntimeBundleSignedSHA256               string
	ContextRoutePackSignedSHA256            string
	ConformanceExpectationSignedSHA256      string
	ResolvedArtifactRef                     coreartifact.Ref
	RuntimeBundleArtifactRef                coreartifact.Ref
	ContextRoutePackArtifactRef             coreartifact.Ref
	ConformanceExpectationArtifactRef       coreartifact.Ref
	ManifestArtifactRef                     coreartifact.Ref
	ResolvedSignedArtifactRef               coreartifact.Ref
	RuntimeBundleSignedArtifactRef          coreartifact.Ref
	ContextRoutePackSignedArtifactRef       coreartifact.Ref
	ConformanceExpectationSignedArtifactRef coreartifact.Ref
	ManifestSignedArtifactRef               coreartifact.Ref
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
	Approval ManifestApproval `json:"approval,omitempty"`
}

type ManifestMetadata struct {
	ID            string `json:"id"`
	CorrelationID string `json:"correlation_id"`
	CreatedBy     string `json:"created_by"`
}

type ManifestSpec struct {
	KNI                    KNIRef                      `json:"kni"`
	Protocol               ProtocolRef                 `json:"protocol"`
	PolicyRepo             PolicyRepoRef               `json:"policy_repo"`
	EnterpriseRegistry     RegistryRef                 `json:"enterprise_registry"`
	CoreRegistry           RegistryRef                 `json:"core_registry"`
	Compiler               CompilerRef                 `json:"compiler"`
	Profile                DigestRef                   `json:"profile"`
	RiskRecipe             DigestRef                   `json:"risk_recipe"`
	CatalogDigest          string                      `json:"catalog_digest"`
	Adapters               map[string]AdapterRef       `json:"adapters"`
	Bindings               map[string]BindingRef       `json:"bindings,omitempty"`
	RuntimeActions         map[string]RuntimeActionRef `json:"runtime_actions,omitempty"`
	FederatedSourceDigests map[string]string           `json:"federated_source_digests,omitempty"`
	Outputs                map[string]string           `json:"outputs"`
	ArtifactRefs           map[string]coreartifact.Ref `json:"artifact_refs,omitempty"`
	SignedOutputs          map[string]SignedOutputRef  `json:"signed_outputs,omitempty"`
}

type ManifestApproval struct {
	Status        string    `json:"status"`
	ApprovedBy    string    `json:"approved_by,omitempty"`
	ApprovedAt    time.Time `json:"approved_at,omitempty"`
	AuthorityID   string    `json:"authority_id,omitempty"`
	AuthorityKind string    `json:"authority_kind,omitempty"`
	Environment   string    `json:"environment,omitempty"`
	Stage         string    `json:"stage,omitempty"`
	Scope         string    `json:"scope,omitempty"`
}

type KNIRef struct {
	Version string `json:"version"`
}

type ProtocolRef struct {
	Version string `json:"version"`
}

type PolicyRepoRef struct {
	Repo           string `json:"repo"`
	Commit         string `json:"commit"`
	PolicyFile     string `json:"policy_file"`
	PolicyFileHash string `json:"policy_file_hash"`
	ContentDigest  string `json:"content_digest"`
}

type RegistryRef struct {
	Repo          string `json:"repo"`
	Commit        string `json:"commit"`
	Version       string `json:"version,omitempty"`
	ContentDigest string `json:"content_digest"`
}

type DigestRef struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type CompilerRef struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	SourceCommit string `json:"source_commit"`
	BinaryDigest string `json:"binary_digest"`
	Digest       string `json:"digest"`
}

type AdapterRef struct {
	AdapterID       string          `json:"adapter_id,omitempty"`
	AdapterVersion  string          `json:"adapter_version,omitempty"`
	ManifestDigest  string          `json:"manifest_digest"`
	ProtocolVersion string          `json:"protocol_version"`
	SignedManifest  SignedOutputRef `json:"signed_manifest,omitempty"`
}

type BindingRef struct {
	BindingID    string `json:"binding_id"`
	Digest       string `json:"digest"`
	AdapterID    string `json:"adapter_id"`
	CapabilityID string `json:"capability_id"`
}

type RuntimeActionRef struct {
	CapabilityGrantID     string `json:"capability_grant_id"`
	BindingID             string `json:"binding_id,omitempty"`
	AdapterID             string `json:"adapter_id"`
	AdapterManifestDigest string `json:"adapter_manifest_digest,omitempty"`
	CapabilityID          string `json:"capability_id"`
	ActionType            string `json:"action_type"`
	ActionDigest          string `json:"action_digest"`
}

type AdapterManifest struct {
	Path                string                      `yaml:"-" json:"path,omitempty"`
	Digest              string                      `yaml:"-" json:"digest,omitempty"`
	AdapterID           string                      `yaml:"adapter_id" json:"adapter_id"`
	AdapterVersion      string                      `yaml:"adapter_version" json:"adapter_version"`
	ProtocolVersion     string                      `yaml:"protocol_version" json:"protocol_version"`
	Status              string                      `yaml:"status" json:"status"`
	ComponentRole       string                      `yaml:"component_role,omitempty" json:"component_role,omitempty"`
	Capabilities        []AdapterManifestCapability `yaml:"capabilities" json:"capabilities"`
	Signals             []AdapterManifestSignal     `yaml:"signals,omitempty" json:"signals,omitempty"`
	RawSignals          []AdapterManifestRawSignal  `yaml:"raw_signals,omitempty" json:"raw_signals,omitempty"`
	Privileges          []AdapterManifestPrivilege  `yaml:"privileges,omitempty" json:"privileges,omitempty"`
	ContextRequirements []string                    `yaml:"context_requirements,omitempty" json:"context_requirements,omitempty"`
}

type AdapterManifestCapability struct {
	CapabilityID             string   `yaml:"capability_id" json:"capability_id"`
	ImplementationStatus     string   `yaml:"implementation_status" json:"implementation_status"`
	SupportedActions         []string `yaml:"supported_actions,omitempty" json:"supported_actions,omitempty"`
	ImplementedGranularities []string `yaml:"implemented_granularities,omitempty" json:"implemented_granularities,omitempty"`
	RequiredPrivileges       []string `yaml:"required_privileges,omitempty" json:"required_privileges,omitempty"`
}

type AdapterManifestSignal struct {
	SignalID             string `yaml:"signal_id" json:"signal_id"`
	ImplementationStatus string `yaml:"implementation_status,omitempty" json:"implementation_status,omitempty"`
}

type AdapterManifestRawSignal struct {
	SignalID   string   `yaml:"signal_id" json:"signal_id"`
	Projectors []string `yaml:"projectors,omitempty" json:"projectors,omitempty"`
}

type AdapterManifestPrivilege struct {
	PrivilegeID string `yaml:"privilege_id" json:"privilege_id"`
}

type AdapterManifestArtifact struct {
	Kind     string                `json:"kind"`
	Metadata coreartifact.Metadata `json:"metadata"`
	Spec     AdapterManifest       `json:"spec"`
}

type SignedOutputRef struct {
	Path           string           `json:"path,omitempty"`
	ArtifactRef    coreartifact.Ref `json:"artifact_ref"`
	EnvelopeSHA256 string           `json:"envelope_sha256"`
	PayloadSHA256  string           `json:"payload_sha256"`
	KeyID          string           `json:"key_id"`
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
	Status      string             `json:"status"`
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
	Passed   *bool    `json:"passed,omitempty"`
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
