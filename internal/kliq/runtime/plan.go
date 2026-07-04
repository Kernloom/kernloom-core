// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"fmt"
	"sort"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
)

const (
	ActionModeRequired = "required"
	ActionModeOptional = "optional"
	ActionModeFallback = "fallback"
	ActionModeAnyOf    = "any_of"
)

type RuntimeActionPlan struct {
	PlanID        string
	DecisionID    string
	EventType     string
	EventID       string
	BundleID      string
	PolicyID      string
	SourceCommit  string
	CorrelationID string
	Actions       []PlannedRuntimeAction
}

type PlannedRuntimeAction struct {
	ActionID          string
	AdapterID         string
	CapabilityID      string
	CapabilityGrantID string
	CorrelationID     string
	Mode              string
	Required          bool
	ActionType        string
	TargetScope       string
	TargetKey         string
	TTL               string
	Reason            string
	AuditID           string
	Context           map[string]any
	DowngradeReason   string
}

type RuntimeExecutor interface {
	Execute(ctx context.Context, lease actionstate.RuntimeActionLease, signedBundle []byte) error
	Cleanup(ctx context.Context, lease actionstate.RuntimeActionLease) error
}

type RuntimeStateReader interface {
	State(ctx context.Context, lease actionstate.RuntimeActionLease) (domain.RuntimeActionStatus, error)
}

type AdapterRuntimeDescriptor struct {
	AdapterID string
	Healthy   bool
}

type AdapterRuntimeRegistry interface {
	Get(adapterID string) (RuntimeExecutor, bool)
	List() []AdapterRuntimeDescriptor
	Healthy(adapterID string) bool
}

type StaticAdapterRuntimeRegistry struct {
	executors map[string]RuntimeExecutor
}

type StaticAdapterRuntimeEntry struct {
	AdapterID string
	Executor  RuntimeExecutor
}

func NewStaticAdapterRuntimeRegistry(entries ...StaticAdapterRuntimeEntry) StaticAdapterRuntimeRegistry {
	registry := StaticAdapterRuntimeRegistry{executors: map[string]RuntimeExecutor{}}
	for _, entry := range entries {
		if entry.AdapterID == "" || entry.Executor == nil {
			continue
		}
		registry.executors[entry.AdapterID] = entry.Executor
	}
	return registry
}

func (r StaticAdapterRuntimeRegistry) Get(adapterID string) (RuntimeExecutor, bool) {
	executor, ok := r.executors[adapterID]
	return executor, ok
}

func (r StaticAdapterRuntimeRegistry) List() []AdapterRuntimeDescriptor {
	adapterIDs := make([]string, 0, len(r.executors))
	for adapterID := range r.executors {
		adapterIDs = append(adapterIDs, adapterID)
	}
	sort.Strings(adapterIDs)
	descriptors := make([]AdapterRuntimeDescriptor, 0, len(adapterIDs))
	for _, adapterID := range adapterIDs {
		descriptors = append(descriptors, AdapterRuntimeDescriptor{AdapterID: adapterID, Healthy: true})
	}
	return descriptors
}

func (r StaticAdapterRuntimeRegistry) Healthy(adapterID string) bool {
	_, ok := r.executors[adapterID]
	return ok
}

type LocalTestExecutor struct{}

func (LocalTestExecutor) Execute(context.Context, actionstate.RuntimeActionLease, []byte) error {
	return nil
}

func (LocalTestExecutor) Cleanup(context.Context, actionstate.RuntimeActionLease) error {
	return nil
}

func (LocalTestExecutor) State(context.Context, actionstate.RuntimeActionLease) (domain.RuntimeActionStatus, error) {
	return domain.RuntimeActionActive, nil
}

func validateActionMode(mode string) error {
	switch mode {
	case ActionModeRequired, ActionModeOptional, ActionModeFallback, ActionModeAnyOf:
		return nil
	default:
		return fmt.Errorf("unsupported runtime action mode %q", mode)
	}
}
