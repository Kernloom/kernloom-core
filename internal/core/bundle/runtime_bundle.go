// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import "github.com/kernloom/kernloom-core/internal/core/artifact"

type RuntimeBundle struct {
	Kind     string            `json:"kind"`
	Metadata artifact.Metadata `json:"metadata"`
	Spec     RuntimeBundleSpec `json:"spec"`
	Status   artifact.Status   `json:"status"`
}

type RuntimeBundleSpec struct {
	PolicyID       string          `json:"policy_id"`
	RuntimeAllowed bool            `json:"runtime_allowed"`
	RuntimeActions []RuntimeAction `json:"runtime_actions,omitempty"`
	MaxTTL         string          `json:"max_ttl"`
	MaxTTLSource   string          `json:"max_ttl_source"`
	MaxScope       string          `json:"max_scope"`
	MaxScopeSource string          `json:"max_scope_source"`
}

type RuntimeAction struct {
	Label       string `json:"label"`
	CanonicalID string `json:"canonical_id"`
}
