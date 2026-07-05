// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package localrisk

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
)

func TestEvaluatorWritesRiskContextFromDeviation(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	store := &memoryRiskStore{values: map[actionstate.RiskCacheKey]corerisk.RiskContext{}}
	evaluator := Evaluator{Store: store, Now: func() time.Time { return now }}
	ctxRisk, err := evaluator.EvaluateDeviation(context.Background(), testRecipe(), baseline.DeviationEvent{
		EventID:    "baseline_deviation.test",
		VersionID:  "baseline_version.test",
		Key:        baseline.Key{View: baseline.ViewEntity, Entity: "opaque"},
		Metric:     "metric",
		Score:      4,
		ObservedAt: now.Add(-time.Second),
		EmittedAt:  now,
		Reason:     "test deviation",
		Confidence: 0.9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ctxRisk.RiskType != "runtime_anomaly" || ctxRisk.Tier != corerisk.TierCritical {
		t.Fatalf("unexpected risk context %#v", ctxRisk)
	}
	cached, err := store.RiskContext(context.Background(), actionstate.RiskCacheKey{RiskType: "runtime_anomaly", Scope: corerisk.ScopeLocal}, now)
	if err != nil {
		t.Fatal(err)
	}
	if cached.Tier != corerisk.TierCritical {
		t.Fatalf("expected critical cached risk, got %#v", cached)
	}
}

func TestEvaluatorLowConfidenceBecomesUnknown(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	store := &memoryRiskStore{values: map[actionstate.RiskCacheKey]corerisk.RiskContext{}}
	evaluator := Evaluator{Store: store, Now: func() time.Time { return now }}
	ctxRisk, err := evaluator.EvaluateDeviation(context.Background(), testRecipe(), baseline.DeviationEvent{
		EventID:    "baseline_deviation.low-confidence",
		VersionID:  "baseline_version.test",
		Key:        baseline.Key{View: baseline.ViewEntity, Entity: "opaque"},
		Metric:     "metric",
		Score:      4,
		ObservedAt: now.Add(-time.Second),
		EmittedAt:  now,
		Reason:     "test deviation",
		Confidence: 0.1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ctxRisk.Tier != corerisk.TierUnknown {
		t.Fatalf("expected unknown risk, got %#v", ctxRisk)
	}
}

func testRecipe() registry.RiskRecipe {
	return registry.RiskRecipe{
		ID:     "runtime_anomaly.standard",
		Output: map[string]string{"risk_type": "runtime_anomaly"},
		Thresholds: map[string]string{
			"low":      "score < 30",
			"medium":   "score >= 30 && score < 70",
			"high":     "score >= 70 && score < 90",
			"critical": "score >= 90",
		},
		Confidence: map[string]string{"minimum_for_enforcement": "0.70"},
		Freshness:  map[string]string{"max_age": "2m"},
	}
}

type memoryRiskStore struct {
	values map[actionstate.RiskCacheKey]corerisk.RiskContext
}

func (s *memoryRiskStore) SaveRiskContext(_ context.Context, key actionstate.RiskCacheKey, riskContext corerisk.RiskContext) error {
	s.values[key] = riskContext
	return nil
}

func (s *memoryRiskStore) RiskContext(_ context.Context, key actionstate.RiskCacheKey, now time.Time) (corerisk.RiskContext, error) {
	value, ok := s.values[key]
	if !ok {
		return corerisk.UnknownContext(key.RiskType, key.Scope, "memory", now, "missing"), nil
	}
	if !value.ValidUntil.After(now) && value.Tier != corerisk.TierUnknown {
		return corerisk.UnknownContext(key.RiskType, key.Scope, "memory", now, "stale"), nil
	}
	return value, nil
}
