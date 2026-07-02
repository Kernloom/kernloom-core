// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package context

import "github.com/kernloom/kernloom-core/internal/core/artifact"

type ContextRoutePack struct {
	Kind     string               `json:"kind"`
	Metadata artifact.Metadata    `json:"metadata"`
	Spec     ContextRoutePackSpec `json:"spec"`
	Status   artifact.Status      `json:"status"`
}

type ContextRoutePackSpec struct {
	PolicyID string         `json:"policy_id"`
	Target   string         `json:"target"`
	Stage    string         `json:"stage"`
	Routes   []ContextRoute `json:"routes"`
}

type ContextRoute struct {
	Name        string   `json:"name"`
	Consumers   []string `json:"consumers"`
	Facts       []string `json:"facts"`
	Sensitivity string   `json:"sensitivity"`
}
