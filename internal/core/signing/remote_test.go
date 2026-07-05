// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteSignerUsesSignerBoundary(t *testing.T) {
	local, err := NewDevLocalSigner("remote.test")
	if err != nil {
		t.Fatal(err)
	}
	local.Now = func() time.Time { return time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC) }
	server := httptest.NewServer(Handler(local))
	defer server.Close()
	envelope, err := (RemoteSigner{URL: server.URL, AllowDevInsecureHTTP: true}).Sign(context.Background(), []byte(`{"kind":"Test"}`), Metadata{SourceCommit: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "remote.test" || envelope.SourceCommit != "abc123" {
		t.Fatalf("unexpected remote envelope %#v", envelope)
	}
	result, err := local.Verify(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("expected valid remote signature, got %#v", result)
	}
}

func TestRemoteSignerRejectsPlainHTTPWithoutDevFlag(t *testing.T) {
	_, err := (RemoteSigner{URL: "http://127.0.0.1:18080"}).Sign(context.Background(), []byte(`{}`), Metadata{})
	if err == nil || !strings.Contains(err.Error(), "plaintext http") {
		t.Fatalf("expected plaintext remote signer rejection, got %v", err)
	}
}

func TestRemoteSignerUsesTLSCAAndCertificatePin(t *testing.T) {
	local, err := NewDevLocalSigner("remote.test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(Handler(local))
	defer server.Close()

	cert := server.Certificate()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := writeTestCertPEM(caPath, cert.Raw); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Raw)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	envelope, err := (RemoteSigner{
		URL:                  server.URL,
		CAPath:               caPath,
		ServerCertificatePin: pin,
	}).Sign(context.Background(), []byte(`{"kind":"Test"}`), Metadata{SourceCommit: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "remote.test" {
		t.Fatalf("unexpected envelope %#v", envelope)
	}
	_, err = (RemoteSigner{
		URL:                  server.URL,
		CAPath:               caPath,
		ServerCertificatePin: "sha256:" + strings.Repeat("0", 64),
	}).Sign(context.Background(), []byte(`{"kind":"Test"}`), Metadata{SourceCommit: "abc123"})
	if err == nil || !strings.Contains(err.Error(), "certificate pin mismatch") {
		t.Fatalf("expected certificate pin mismatch, got %v", err)
	}
}

func writeTestCertPEM(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}
