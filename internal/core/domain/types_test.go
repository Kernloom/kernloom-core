// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package domain

import "testing"

func TestUnknownConformanceIsExplicit(t *testing.T) {
	if ConformanceUnknown != "unknown" {
		t.Fatalf("unexpected unknown conformance value: %q", ConformanceUnknown)
	}
}

func TestRuntimeActionLeaseKeyRequiresScope(t *testing.T) {
	if (RuntimeActionLeaseKey{ActionType: "rate_limit_source", TargetScope: "application", TargetKey: "app-1"}).Valid() != true {
		t.Fatal("expected complete runtime action lease key to be valid")
	}
	if (RuntimeActionLeaseKey{ActionType: "rate_limit_source", TargetKey: "app-1"}).Valid() {
		t.Fatal("expected missing scope to make runtime action lease key invalid")
	}
}
