// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package conformance

import "github.com/kernloom/kernloom-core/internal/core/artifact"

type ConformanceExpectation struct {
	Kind     string                     `json:"kind"`
	Metadata artifact.Metadata          `json:"metadata"`
	Spec     ConformanceExpectationSpec `json:"spec"`
	Status   artifact.Status            `json:"status"`
}

type ConformanceExpectationSpec struct {
	PolicyID     string              `json:"policy_id"`
	Target       string              `json:"target"`
	Stage        string              `json:"stage"`
	Expectations []Expectation       `json:"expectations"`
	Prohibit     []ProhibitedOutcome `json:"prohibit,omitempty"`
}

type Expectation struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ProhibitedOutcome struct {
	Label       string `json:"label"`
	CanonicalID string `json:"canonical_id"`
}
