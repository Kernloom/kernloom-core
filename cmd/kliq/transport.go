// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("adapter tls pin requires peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := "sha256:" + hex.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("adapter tls server certificate pin mismatch")
			}
			return nil
		}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}
