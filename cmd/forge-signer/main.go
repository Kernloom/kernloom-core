// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/core/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version.Binary("forge-signer"))
		return
	}
	fs := flag.NewFlagSet("forge-signer", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:18088", "signer listen address")
	tlsCert := fs.String("tls-cert", "", "TLS server certificate path for remote signer")
	tlsKey := fs.String("tls-key", "", "TLS server private key path for remote signer")
	clientCA := fs.String("client-ca", "", "client CA bundle path; when set, remote signer requires verified client certificates")
	devInsecureHTTP := fs.Bool("dev-insecure-http", false, "allow plaintext HTTP signer listener; dev/smoke-test only")
	production := fs.Bool("production", false, "enforce production-safe signer startup gates")
	keyPath := fs.String("signing-key", "./var/kernloom/signer/management.ed25519.json", "isolated management signing key path")
	keyID := fs.String("signing-key-id", "forge-management", "management signing key id")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *production {
		if err := validateSignerProductionConfig(*tlsCert, *tlsKey, *clientCA, *devInsecureHTTP, *keyID); err != nil {
			slog.Error("forge_signer_production_gate_failed", "error", err.Error())
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	signer, err := signing.LoadOrCreateDevLocalSigner(*keyPath, *keyID)
	if err != nil {
		slog.Error("forge_signer_key_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	tlsConfig, useTLS, err := signerTLSConfig(*tlsCert, *tlsKey, *clientCA, *devInsecureHTTP)
	if err != nil {
		slog.Error("forge_signer_tls_config_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	transport := "https"
	if !useTLS {
		transport = "dev-plaintext-http"
		slog.Warn("forge_signer_plaintext_http_enabled", "message", "plaintext signer transport is dev-only")
	}
	slog.Info("forge_signer_starting", "addr", *addr, "key_id", signer.KeyID, "transport", transport, "client_ca_configured", strings.TrimSpace(*clientCA) != "")
	server := &http.Server{Addr: *addr, Handler: signing.Handler(signer), TLSConfig: tlsConfig}
	if err := listenAndServeSigner(server, useTLS, *tlsCert, *tlsKey); err != nil {
		slog.Error("forge_signer_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func signerTLSConfig(certPath, keyPath, clientCAPath string, allowDevPlaintext bool) (*tls.Config, bool, error) {
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	clientCAPath = strings.TrimSpace(clientCAPath)
	if certPath == "" && keyPath == "" {
		if clientCAPath != "" {
			return nil, false, fmt.Errorf("--client-ca requires --tls-cert and --tls-key")
		}
		if allowDevPlaintext {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("forge-signer requires --tls-cert and --tls-key unless --dev-insecure-http is set")
	}
	if certPath == "" || keyPath == "" {
		return nil, false, fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCAPath != "" {
		caPEM, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, false, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, false, fmt.Errorf("client ca %q does not contain a PEM certificate", clientCAPath)
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, true, nil
}

func listenAndServeSigner(server *http.Server, useTLS bool, certPath, keyPath string) error {
	if useTLS {
		return server.ListenAndServeTLS(certPath, keyPath)
	}
	return server.ListenAndServe()
}

func validateSignerProductionConfig(certPath, keyPath, clientCAPath string, allowDevPlaintext bool, keyID string) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return fmt.Errorf("production forge-signer requires --tls-cert and --tls-key")
	}
	if strings.TrimSpace(clientCAPath) == "" {
		return fmt.Errorf("production forge-signer requires --client-ca for mTLS")
	}
	if allowDevPlaintext {
		return fmt.Errorf("production forge-signer forbids --dev-insecure-http")
	}
	normalizedKeyID := strings.ToLower(strings.TrimSpace(keyID))
	if normalizedKeyID == "" || strings.Contains(normalizedKeyID, "dev") || strings.Contains(normalizedKeyID, "local") {
		return fmt.Errorf("production forge-signer requires a non-dev signing key id")
	}
	return nil
}
