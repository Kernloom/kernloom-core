// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type adapterTransportOptions struct {
	DevInsecureAdapterTransport bool
	CAPath                      string
	ClientCertPath              string
	ClientKeyPath               string
	ServerName                  string
	ServerCertificateSHA256     string
}

type forgeTransportOptions struct {
	CAPath                  string
	ClientCertPath          string
	ClientKeyPath           string
	ServerName              string
	ServerCertificateSHA256 string
}

func validateSecureForgeURL(rawURL string, allowDevInsecure bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("forge url is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if allowDevInsecure {
			return nil
		}
		return fmt.Errorf("forge url %q uses plaintext http; pass --dev-insecure-forge-transport only for local smoke tests", rawURL)
	default:
		return fmt.Errorf("forge url %q must use https", rawURL)
	}
}

func forgeHTTPClient(opts forgeTransportOptions) (*http.Client, error) {
	tlsConfig, err := forgeTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport}, nil
}

func forgeTLSConfig(opts forgeTransportOptions) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: strings.TrimSpace(opts.ServerName),
	}
	if caPath := strings.TrimSpace(opts.CAPath); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("forge ca %q does not contain a PEM certificate", caPath)
		}
		tlsConfig.RootCAs = roots
	}
	certPath := strings.TrimSpace(opts.ClientCertPath)
	keyPath := strings.TrimSpace(opts.ClientKeyPath)
	if (certPath == "") != (keyPath == "") {
		return nil, fmt.Errorf("forge mTLS requires both --forge-client-cert and --forge-client-key")
	}
	if certPath != "" {
		clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	if pin := strings.TrimSpace(opts.ServerCertificateSHA256); pin != "" {
		expectedPin := normalizeCertificateSHA256Pin(pin)
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("forge tls pin requires peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := "sha256:" + hex.EncodeToString(sum[:])
			if got != expectedPin {
				return fmt.Errorf("forge tls server certificate pin mismatch")
			}
			return nil
		}
	}
	return tlsConfig, nil
}

func adapterDialOptions(opts adapterTransportOptions) ([]grpc.DialOption, error) {
	if opts.DevInsecureAdapterTransport {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	if strings.TrimSpace(opts.CAPath) == "" || strings.TrimSpace(opts.ClientCertPath) == "" || strings.TrimSpace(opts.ClientKeyPath) == "" {
		return nil, fmt.Errorf("adapter transport requires --adapter-ca, --adapter-client-cert and --adapter-client-key unless --dev-insecure-adapter-transport is set")
	}
	caPEM, err := os.ReadFile(opts.CAPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("adapter ca %q does not contain a PEM certificate", opts.CAPath)
	}
	clientCert, err := tls.LoadX509KeyPair(opts.ClientCertPath, opts.ClientKeyPath)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   strings.TrimSpace(opts.ServerName),
	}
	if pin := strings.TrimSpace(opts.ServerCertificateSHA256); pin != "" {
		expectedPin := normalizeCertificateSHA256Pin(pin)
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("adapter tls pin requires peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := "sha256:" + hex.EncodeToString(sum[:])
			if got != expectedPin {
				return fmt.Errorf("adapter tls server certificate pin mismatch")
			}
			return nil
		}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}

func normalizeCertificateSHA256Pin(pin string) string {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if strings.HasPrefix(pin, "sha256:") {
		return pin
	}
	return "sha256:" + pin
}
