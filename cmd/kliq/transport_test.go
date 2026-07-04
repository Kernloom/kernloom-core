// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"strings"
	"testing"
)

func TestValidateSecureForgeURLRejectsHTTPWithoutDevFlag(t *testing.T) {
	err := validateSecureForgeURL("http://127.0.0.1:8080", false)
	if err == nil || !strings.Contains(err.Error(), "plaintext http") {
		t.Fatalf("expected plaintext http to be rejected, got %v", err)
	}
	if err := validateSecureForgeURL("http://127.0.0.1:8080", true); err != nil {
		t.Fatalf("expected explicit dev-insecure http to be accepted, got %v", err)
	}
	if err := validateSecureForgeURL("https://forge.example", false); err != nil {
		t.Fatalf("expected https to be accepted, got %v", err)
	}
}

func TestAdapterDialOptionsRejectsPlaintextWithoutDevFlag(t *testing.T) {
	_, err := adapterDialOptions(adapterTransportOptions{})
	if err == nil || !strings.Contains(err.Error(), "adapter transport requires") {
		t.Fatalf("expected adapter mTLS material to be required, got %v", err)
	}
	opts, err := adapterDialOptions(adapterTransportOptions{DevInsecureAdapterTransport: true})
	if err != nil {
		t.Fatalf("expected explicit dev-insecure adapter transport to be accepted, got %v", err)
	}
	if len(opts) == 0 {
		t.Fatal("expected grpc dial options")
	}
}
