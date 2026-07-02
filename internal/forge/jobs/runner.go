// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/kernloom/kernloom-core/internal/forge/compiler"
)

type Runner struct {
	Store    Store
	Defaults compiler.Options
}

func (r Runner) RunOnce(ctx context.Context) (*Job, error) {
	if r.Store == nil {
		return nil, fmt.Errorf("job runner requires a store")
	}
	jobID, err := r.Store.Dequeue(ctx)
	if err != nil {
		return nil, err
	}
	job, err := r.Store.Get(ctx, jobID)
	if err != nil {
		return nil, err
	}
	job.SetStatus(StatusRunning)
	if err := r.Store.Update(ctx, job); err != nil {
		return nil, err
	}
	if err := r.run(ctx, job); err != nil {
		job.SetError(err)
		_ = r.Store.Update(ctx, job)
		return job, err
	}
	if err := r.Store.Update(ctx, job); err != nil {
		return nil, err
	}
	return job, nil
}

func (r Runner) run(ctx context.Context, job *Job) error {
	switch job.Type {
	case TypeSimulation:
		return r.runSimulation(ctx, job)
	default:
		return fmt.Errorf("unsupported job type %q", job.Type)
	}
}

func (r Runner) runSimulation(ctx context.Context, job *Job) error {
	var payload SimulationPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return err
	}
	opts := r.Defaults
	if payload.PolicyRepo != "" {
		opts.PolicyRepo = payload.PolicyRepo
	}
	if payload.PolicyFile != "" {
		opts.PolicyFile = payload.PolicyFile
	}
	if payload.CoreRegistry != "" {
		opts.CoreRegistry = payload.CoreRegistry
	}
	if payload.EnterpriseRegistry != "" {
		opts.EnterpriseRegistry = payload.EnterpriseRegistry
	}
	if payload.OutputDir != "" {
		opts.OutputDir = payload.OutputDir
	}
	if opts.OutputDir == "" {
		opts.OutputDir = filepath.Join("/tmp", "kernloom-simulation-jobs", job.ID)
	}
	results, err := compiler.Compile(opts)
	if err != nil {
		return err
	}
	policies := make([]SimulationPolicyResult, 0, len(results))
	for _, result := range results {
		policies = append(policies, SimulationPolicyResult{
			PolicyID:                           result.PolicyID,
			ReviewPath:                         result.ReviewPath,
			ResolvedPath:                       result.ResolvedPath,
			RuntimeBundlePath:                  result.RuntimeBundlePath,
			ContextRoutePackPath:               result.ContextRoutePackPath,
			ConformanceExpectationPath:         result.ConformanceExpectationPath,
			ManifestPath:                       result.ManifestPath,
			CoveragePath:                       result.CoveragePath,
			SimulationPath:                     result.SimulationPath,
			ValidationPath:                     result.ValidationPath,
			ResolvedSignedPath:                 result.ResolvedSignedPath,
			RuntimeBundleSignedPath:            result.RuntimeBundleSignedPath,
			ContextRoutePackSignedPath:         result.ContextRoutePackSignedPath,
			ConformanceExpectationSignedPath:   result.ConformanceExpectationSignedPath,
			ResolvedSHA256:                     result.ResolvedSHA256,
			RuntimeBundleSHA256:                result.RuntimeBundleSHA256,
			ContextRoutePackSHA256:             result.ContextRoutePackSHA256,
			ConformanceExpectationSHA256:       result.ConformanceExpectationSHA256,
			ManifestSHA256:                     result.ManifestSHA256,
			ResolvedSignedSHA256:               result.ResolvedSignedSHA256,
			RuntimeBundleSignedSHA256:          result.RuntimeBundleSignedSHA256,
			ContextRoutePackSignedSHA256:       result.ContextRoutePackSignedSHA256,
			ConformanceExpectationSignedSHA256: result.ConformanceExpectationSignedSHA256,
		})
	}
	return job.SetResult(SimulationResult{
		Kind:     "SimulationJobResult",
		Status:   "resolved_only",
		Policies: policies,
	})
}
