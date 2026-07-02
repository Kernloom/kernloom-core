// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package domain

type RiskTier string

const (
	RiskTierLow      RiskTier = "low"
	RiskTierMedium   RiskTier = "medium"
	RiskTierHigh     RiskTier = "high"
	RiskTierCritical RiskTier = "critical"
	RiskTierUnknown  RiskTier = "unknown"
)

type ConformanceStatus string

const (
	ConformanceConformant  ConformanceStatus = "conformant"
	ConformanceDegraded    ConformanceStatus = "degraded"
	ConformanceDrifted     ConformanceStatus = "drifted"
	ConformanceUnsupported ConformanceStatus = "unsupported"
	ConformanceUnsafe      ConformanceStatus = "unsafe"
	ConformanceUnknown     ConformanceStatus = "unknown"
)

type RuntimeActionStatus string

const (
	RuntimeActionPlanned      RuntimeActionStatus = "planned"
	RuntimeActionAuthorized   RuntimeActionStatus = "authorized"
	RuntimeActionExecuting    RuntimeActionStatus = "executing"
	RuntimeActionActive       RuntimeActionStatus = "active"
	RuntimeActionExpiring     RuntimeActionStatus = "expiring"
	RuntimeActionExpired      RuntimeActionStatus = "expired"
	RuntimeActionFailed       RuntimeActionStatus = "failed"
	RuntimeActionUnknown      RuntimeActionStatus = "unknown"
	RuntimeActionCompensating RuntimeActionStatus = "compensating"
)

type RuntimeActionLeaseKey struct {
	ActionType  string
	TargetScope string
	TargetKey   string
}

func (key RuntimeActionLeaseKey) Valid() bool {
	return key.ActionType != "" && key.TargetScope != "" && key.TargetKey != ""
}
