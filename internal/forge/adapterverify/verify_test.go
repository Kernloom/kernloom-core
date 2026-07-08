// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapterverify

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/forge/compiler"
)

func TestVerifyRequiresMTLSMaterialUnlessDevInsecure(t *testing.T) {
	result := Verify(context.Background(), Options{
		AdapterID: "kernloom.adapter.test",
		Endpoint:  "adapter.example:443",
		Manifest: compiler.AdapterManifest{
			AdapterID: "kernloom.adapter.test",
			Digest:    "sha256:manifest",
		},
		Timeout: time.Millisecond,
	})

	if result.Status != "failed" || len(result.Findings) != 1 {
		t.Fatalf("expected failed transport result, got %#v", result)
	}
	if result.Findings[0].Code != "adapter_transport_invalid" {
		t.Fatalf("expected adapter_transport_invalid finding, got %#v", result.Findings)
	}
}

func TestNormalizeCertificateSHA256Pin(t *testing.T) {
	if got := normalizeCertificateSHA256Pin("ABCDEF"); got != "sha256:abcdef" {
		t.Fatalf("expected normalized sha256 pin, got %q", got)
	}
	if got := normalizeCertificateSHA256Pin("sha256:ABCDEF"); got != "sha256:abcdef" {
		t.Fatalf("expected normalized prefixed sha256 pin, got %q", got)
	}
}
