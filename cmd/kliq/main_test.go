// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import "testing"

func TestStatusRedactionHelpersDoNotReturnRawSensitiveValues(t *testing.T) {
	target := "203.0.113.10"
	if got := redactedHash(target); got == "" || got == target {
		t.Fatalf("expected target hash redaction, got %q", got)
	}

	correlationID := "correlation.long-sensitive-context-id"
	if got := redactID(correlationID); got == "" || got == correlationID {
		t.Fatalf("expected shortened id redaction, got %q", got)
	}
}
