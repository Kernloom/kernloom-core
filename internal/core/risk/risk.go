// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package risk

import (
	"fmt"
	"strings"
	"time"
)

const (
	TierLow      = "low"
	TierMedium   = "medium"
	TierHigh     = "high"
	TierCritical = "critical"
	TierUnknown  = "unknown"

	ScopeLocal  = "local"
	ScopeGlobal = "global"
)

type RiskSignal struct {
	Type        string    `json:"type"`
	Tier        string    `json:"tier"`
	Score       *float64  `json:"score,omitempty"`
	Reasons     []string  `json:"reasons,omitempty"`
	Confidence  float64   `json:"confidence"`
	ObservedAt  time.Time `json:"observed_at"`
	EvaluatedAt time.Time `json:"evaluated_at"`
	ValidUntil  time.Time `json:"valid_until"`
	Source      string    `json:"source"`
	Scope       string    `json:"scope"`
}

type RiskContext struct {
	RiskType    string       `json:"risk_type"`
	Tier        string       `json:"tier"`
	Score       *float64     `json:"score,omitempty"`
	Confidence  float64      `json:"confidence"`
	Reasons     []string     `json:"reasons,omitempty"`
	Signals     []RiskSignal `json:"signals,omitempty"`
	Source      string       `json:"source"`
	Scope       string       `json:"scope"`
	EvaluatedAt time.Time    `json:"evaluated_at"`
	ValidUntil  time.Time    `json:"valid_until"`
}

type PolicyRiskBehavior struct {
	RiskType    string `json:"risk_type"`
	Tier        string `json:"tier"`
	Effect      string `json:"effect"`
	RuntimeHint string `json:"runtime_hint,omitempty"`
}

func NormalizeTier(tier string) string {
	tier = strings.TrimPrefix(strings.TrimSpace(tier), "risk_tier.")
	switch tier {
	case TierLow, TierMedium, TierHigh, TierCritical:
		return tier
	default:
		return TierUnknown
	}
}

func NormalizeType(riskType string) string {
	return strings.TrimPrefix(strings.TrimSpace(riskType), "risk_type.")
}

func NormalizeEffect(effect string) string {
	return strings.TrimPrefix(strings.TrimSpace(effect), "effect.")
}

func RuntimeActionForEffect(effect string) (string, bool) {
	switch NormalizeEffect(effect) {
	case "rate_limit":
		return "runtime_action.rate_limit_source", true
	case "deny_temporarily":
		return "runtime_action.deny_temporarily_source", true
	default:
		return "", false
	}
}

func MatchBehavior(behaviors []PolicyRiskBehavior, ctx RiskContext) (PolicyRiskBehavior, bool) {
	riskType := NormalizeType(ctx.RiskType)
	tier := NormalizeTier(ctx.Tier)
	for _, behavior := range behaviors {
		if NormalizeType(behavior.RiskType) == riskType && NormalizeTier(behavior.Tier) == tier {
			return behavior, true
		}
	}
	return PolicyRiskBehavior{}, false
}

func UnknownContext(riskType, scope, source string, now time.Time, reasons ...string) RiskContext {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return RiskContext{
		RiskType:    NormalizeType(riskType),
		Tier:        TierUnknown,
		Confidence:  0,
		Reasons:     reasons,
		Source:      strings.TrimSpace(source),
		Scope:       strings.TrimSpace(scope),
		EvaluatedAt: now.UTC(),
		ValidUntil:  now.UTC(),
	}
}

func ValidateContext(ctx RiskContext, now time.Time) error {
	if strings.TrimSpace(ctx.RiskType) == "" {
		return fmt.Errorf("risk context requires risk_type")
	}
	if strings.TrimSpace(ctx.Scope) == "" {
		return fmt.Errorf("risk context requires scope")
	}
	if NormalizeTier(ctx.Tier) != ctx.Tier {
		return fmt.Errorf("risk context tier %q is not canonical", ctx.Tier)
	}
	if ctx.EvaluatedAt.IsZero() {
		return fmt.Errorf("risk context requires evaluated_at")
	}
	if ctx.ValidUntil.IsZero() {
		return fmt.Errorf("risk context requires valid_until")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !ctx.ValidUntil.After(now.UTC()) && ctx.Tier != TierUnknown {
		return fmt.Errorf("risk context is stale")
	}
	return nil
}
