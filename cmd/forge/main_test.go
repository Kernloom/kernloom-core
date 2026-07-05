// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/forge/management"
)

func TestValidateOrSeedManagementTrustBundleRequiresExplicitDevSeed(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, false); err == nil {
		t.Fatal("expected missing trust bundle to require explicit dev seed")
	}
}

func TestValidateOrSeedManagementTrustBundleDoesNotExtendExistingBundle(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, true); err != nil {
		t.Fatal(err)
	}
	first, err := store.TrustBundle(context.Background(), signer.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, false); err != nil {
		t.Fatal(err)
	}
	second, err := store.TrustBundle(context.Background(), signer.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ExpiresAt.Equal(second.ExpiresAt) {
		t.Fatalf("expected startup seed to leave expiry unchanged, got first=%s second=%s", first.ExpiresAt, second.ExpiresAt)
	}
}

func TestValidateOrSeedManagementTrustBundleRejectsMismatchedPublicKey(t *testing.T) {
	store := management.NewMemoryStore()
	signer, err := signing.NewDevLocalSigner("forge-management-dev-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTrustBundle(context.Background(), domain.TrustBundle{
		KeyID:     signer.KeyID,
		PublicKey: "different-public-key",
		Purpose:   "assignment_verification",
		Status:    "active",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Issuer:    "test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := validateOrSeedManagementTrustBundle(store, signer, false); err == nil {
		t.Fatal("expected startup seed to reject mismatched public key")
	}
}

func TestLoadKLIQServiceTokenSecretRejectsCLISecretWithoutDevGate(t *testing.T) {
	_, err := loadKLIQServiceTokenSecret("secret", "", false)
	if err == nil || !strings.Contains(err.Error(), "process argv") {
		t.Fatalf("expected argv secret to require explicit dev gate, got %v", err)
	}
	secret, err := loadKLIQServiceTokenSecret("secret", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "secret" {
		t.Fatalf("unexpected secret %q", string(secret))
	}
}

func TestLoadKLIQServiceTokenSecretPrefersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KERNLOOM_KLIQ_SERVICE_TOKEN_SECRET", "env-secret")
	secret, err := loadKLIQServiceTokenSecret("", path, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "file-secret" {
		t.Fatalf("expected file secret, got %q", string(secret))
	}
}

func TestForgeAPITLSConfigRejectsPlaintextWithoutDevFlag(t *testing.T) {
	if _, _, err := forgeAPITLSConfig("", "", "", false); err == nil || !strings.Contains(err.Error(), "requires --tls-cert") {
		t.Fatalf("expected plaintext listener to require explicit dev flag, got %v", err)
	}
	config, useTLS, err := forgeAPITLSConfig("", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if config != nil || useTLS {
		t.Fatalf("expected dev plaintext config, got config=%#v useTLS=%t", config, useTLS)
	}
}

func TestForgeAPITLSConfigRequiresClientCertificateWhenClientCAConfigured(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, testCertificatePEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	config, useTLS, err := forgeAPITLSConfig("server.crt", "server.key", caPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if !useTLS || config == nil {
		t.Fatalf("expected tls config, got config=%#v useTLS=%t", config, useTLS)
	}
	if config.ClientAuth != tlsRequireAndVerifyClientCert() || config.ClientCAs == nil {
		t.Fatalf("expected mTLS client cert requirement, got %#v", config)
	}
}

func testCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().UTC().Add(-time.Minute),
		NotAfter:     time.Now().UTC().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func tlsRequireAndVerifyClientCert() tls.ClientAuthType {
	return tls.RequireAndVerifyClientCert
}
