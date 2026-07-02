// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompileAccessIntent(t *testing.T) {
	out := t.TempDir()
	results, err := Compile(Options{
		PolicyRepo:         "../../../../enterprise-kernloom-policies",
		PolicyFile:         "../../../../enterprise-kernloom-policies/policies/access/protect-production-admin-access.intent.kni",
		CoreRegistry:       "../../../../kernloom-core-registry",
		EnterpriseRegistry: "../../../../enterprise-kernloom-registry",
		OutputDir:          out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one compile result, got %d", len(results))
	}
	for _, path := range []string{
		filepath.Join(out, "resolved", "access.protect-production-admin-access.resolved.json"),
		filepath.Join(out, "reports", "access.protect-production-admin-access.manifest.json"),
		filepath.Join(out, "reviews", "access.protect-production-admin-access.intent.review.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated artifact %s: %v", path, err)
		}
	}
}
