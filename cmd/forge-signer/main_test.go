// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"strings"
	"testing"
)

func TestSignerTLSConfigRejectsPlaintextWithoutDevFlag(t *testing.T) {
	_, _, err := signerTLSConfig("", "", "", false)
	if err == nil || !strings.Contains(err.Error(), "requires --tls-cert") {
		t.Fatalf("expected plaintext signer listener to require explicit dev flag, got %v", err)
	}
	config, useTLS, err := signerTLSConfig("", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if config != nil || useTLS {
		t.Fatalf("expected explicit dev plaintext config, got config=%#v useTLS=%t", config, useTLS)
	}
}

func TestSignerTLSConfigRequiresCertAndKeyTogether(t *testing.T) {
	if _, _, err := signerTLSConfig("server.crt", "", "", false); err == nil {
		t.Fatal("expected missing signer tls key to be rejected")
	}
	if _, _, err := signerTLSConfig("", "server.key", "", false); err == nil {
		t.Fatal("expected missing signer tls cert to be rejected")
	}
}

func TestValidateSignerProductionConfigRequiresMTLSAndNonDevKey(t *testing.T) {
	if err := validateSignerProductionConfig("server.crt", "server.key", "ca.pem", false, "forge-management-prod"); err != nil {
		t.Fatalf("expected production signer config, got %v", err)
	}
	if err := validateSignerProductionConfig("server.crt", "server.key", "", false, "forge-management-prod"); err == nil || !strings.Contains(err.Error(), "client-ca") {
		t.Fatalf("expected client ca requirement, got %v", err)
	}
	if err := validateSignerProductionConfig("server.crt", "server.key", "ca.pem", false, "forge-management-dev-local"); err == nil || !strings.Contains(err.Error(), "non-dev") {
		t.Fatalf("expected non-dev key id requirement, got %v", err)
	}
}
