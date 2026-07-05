// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package localrisk

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	corerisk "github.com/kernloom/kernloom-core/internal/core/risk"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
)

type Store interface {
	SaveRiskContext(ctx context.Context, key actionstate.RiskCacheKey, riskContext corerisk.RiskContext) error
	RiskContext(ctx context.Context, key actionstate.RiskCacheKey, now time.Time) (corerisk.RiskContext, error)
}

type Evaluator struct {
	Store Store
	Now   func() time.Time
}

func (e Evaluator) EvaluateDeviation(ctx context.Context, recipe registry.RiskRecipe, event baseline.DeviationEvent) (corerisk.RiskContext, error) {
	if e.Store == nil {
		return corerisk.RiskContext{}, fmt.Errorf("local risk evaluator requires store")
	}
	now := e.now()
	riskType := corerisk.NormalizeType(recipe.Output["risk_type"])
	if riskType == "" {
		riskType = "runtime_anomaly"
	}
	score := deviationScore(event)
	tier := tierForScore(recipe, score)
	validUntil := now.Add(maxAge(recipe))
	signal := corerisk.RiskSignal{
		Type:        riskType,
		Tier:        tier,
		Score:       &score,
		Reasons:     []string{event.Reason},
		Confidence:  event.Confidence,
		ObservedAt:  event.ObservedAt.UTC(),
		EvaluatedAt: now,
		ValidUntil:  validUntil,
		Source:      "baseline.local",
		Scope:       corerisk.ScopeLocal,
	}
	ctxRisk := corerisk.RiskContext{
		RiskType:    riskType,
		Tier:        tier,
		Score:       &score,
		Confidence:  event.Confidence,
		Reasons:     []string{event.Reason},
		Signals:     []corerisk.RiskSignal{signal},
		Source:      "baseline.local",
		Scope:       corerisk.ScopeLocal,
		EvaluatedAt: now,
		ValidUntil:  validUntil,
	}
	minConfidence := minimumConfidence(recipe)
	if event.Confidence < minConfidence {
		ctxRisk = corerisk.UnknownContext(riskType, corerisk.ScopeLocal, "baseline.local", now, "risk confidence below recipe minimum")
	}
	if err := e.Store.SaveRiskContext(ctx, actionstate.RiskCacheKey{RiskType: riskType, Scope: corerisk.ScopeLocal}, ctxRisk); err != nil {
		return corerisk.RiskContext{}, err
	}
	return ctxRisk, nil
}

func (e Evaluator) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func deviationScore(event baseline.DeviationEvent) float64 {
	score := event.Score * 25
	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}

func tierForScore(recipe registry.RiskRecipe, score float64) string {
	type threshold struct {
		tier string
		min  float64
	}
	var thresholds []threshold
	for tier, expression := range recipe.Thresholds {
		min, ok := lowerBound(expression)
		if !ok {
			continue
		}
		thresholds = append(thresholds, threshold{tier: corerisk.NormalizeTier(tier), min: min})
	}
	sort.Slice(thresholds, func(i, j int) bool { return thresholds[i].min > thresholds[j].min })
	for _, threshold := range thresholds {
		if score >= threshold.min {
			return threshold.tier
		}
	}
	return corerisk.TierUnknown
}

var lowerBoundRE = regexp.MustCompile(`score\s*>=\s*([0-9]+(?:\.[0-9]+)?)`)

func lowerBound(expression string) (float64, bool) {
	matches := lowerBoundRE.FindStringSubmatch(expression)
	if len(matches) != 2 {
		if strings.Contains(expression, "score <") {
			return 0, true
		}
		return 0, false
	}
	value, err := strconv.ParseFloat(matches[1], 64)
	return value, err == nil
}

func maxAge(recipe registry.RiskRecipe) time.Duration {
	if value := strings.TrimSpace(recipe.Freshness["max_age"]); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return 2 * time.Minute
}

func minimumConfidence(recipe registry.RiskRecipe) float64 {
	if value := strings.TrimSpace(recipe.Confidence["minimum_for_enforcement"]); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return 0.70
}
