// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"github.com/kernloom/kernloom-core/internal/core/artifact"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
)

type RuntimeBundle struct {
	Kind     string            `json:"kind"`
	Metadata artifact.Metadata `json:"metadata"`
	Spec     RuntimeBundleSpec `json:"spec"`
	Status   artifact.Status   `json:"status"`
}

type RuntimeBundleSpec struct {
	PolicyID         string                        `json:"policy_id"`
	RuntimeAllowed   bool                          `json:"runtime_allowed"`
	RuntimeActions   []RuntimeAction               `json:"runtime_actions,omitempty"`
	CapabilityGrants []CapabilityGrant             `json:"capability_grants,omitempty"`
	RiskRecipe       string                        `json:"risk_recipe,omitempty"`
	RiskBehavior     []corerisk.PolicyRiskBehavior `json:"risk_behavior,omitempty"`
	MaxTTL           string                        `json:"max_ttl"`
	MaxTTLSource     string                        `json:"max_ttl_source"`
	MaxScope         string                        `json:"max_scope"`
	MaxScopeSource   string                        `json:"max_scope_source"`
}

type RuntimeAction struct {
	Label       string `json:"label"`
	CanonicalID string `json:"canonical_id"`
}

type CapabilityGrant struct {
	ID                  string               `json:"capability_grant_id"`
	AdapterID           string               `json:"adapter_id"`
	CapabilityID        string               `json:"capability_id"`
	ActionType          string               `json:"action_type"`
	AllowedTargetScopes []string             `json:"allowed_target_scopes"`
	MaxTTL              string               `json:"max_ttl"`
	Stage               string               `json:"stage,omitempty"`
	Environment         string               `json:"environment,omitempty"`
	Owner               string               `json:"owner,omitempty"`
	ApprovalRef         string               `json:"approval_ref,omitempty"`
	ExpiresAt           string               `json:"expires_at,omitempty"`
	RateLimit           *RateLimitParameters `json:"rate_limit,omitempty"`
}

type RateLimitParameters struct {
	RatePPS uint64 `json:"rate_pps"`
	Burst   uint64 `json:"burst"`
}
