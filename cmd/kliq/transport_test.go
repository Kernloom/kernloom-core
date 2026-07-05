// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernloom/kernloom-core/internal/core/domain"
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

func TestForgeHTTPClientUsesCAAndCertificatePin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	cert := server.Certificate()
	caPath := filepath.Join(t.TempDir(), "forge-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Raw)
	client, err := forgeHTTPClient(forgeTransportOptions{
		CAPath:                  caPath,
		ServerCertificateSHA256: "sha256:" + hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	badClient, err := forgeHTTPClient(forgeTransportOptions{
		CAPath:                  caPath,
		ServerCertificateSHA256: "sha256:" + strings.Repeat("0", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = badClient.Get(server.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected forge certificate pin mismatch")
	}
}

func TestForgeHTTPClientRequiresClientCertKeyPair(t *testing.T) {
	_, err := forgeHTTPClient(forgeTransportOptions{ClientCertPath: "client.pem"})
	if err == nil || !strings.Contains(err.Error(), "both --forge-client-cert and --forge-client-key") {
		t.Fatalf("expected mTLS key pair validation, got %v", err)
	}
}

func TestAdapterTransportForAssignmentPinsIdentity(t *testing.T) {
	base := adapterTransportOptions{
		CAPath:                  "ca.pem",
		ClientCertPath:          "client.pem",
		ClientKeyPath:           "client.key",
		ServerName:              "global.example",
		ServerCertificateSHA256: "sha256:global",
	}
	got := adapterTransportForAssignment(base, domain.AdapterAssignment{
		AdapterID:               "kernloom.adapter.klshield",
		Endpoint:                "klshield.internal:7443",
		TLSServerName:           "klshield.internal",
		ServerCertificateSHA256: "sha256:adapter",
	})
	if got.ServerName != "klshield.internal" {
		t.Fatalf("expected assignment server name pin, got %q", got.ServerName)
	}
	if got.ServerCertificateSHA256 != "sha256:adapter" {
		t.Fatalf("expected assignment certificate pin, got %q", got.ServerCertificateSHA256)
	}
	if base.ServerName != "global.example" || base.ServerCertificateSHA256 != "sha256:global" {
		t.Fatalf("base transport was mutated: %#v", base)
	}
}
