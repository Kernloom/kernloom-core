// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapterverify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type Options struct {
	AdapterID               string
	Endpoint                string
	Manifest                compiler.AdapterManifest
	DevInsecureTransport    bool
	CAPath                  string
	ClientCertPath          string
	ClientKeyPath           string
	TLSServerName           string
	ServerCertificateSHA256 string
	Timeout                 time.Duration
}

type Result struct {
	Kind             string    `json:"kind"`
	Status           string    `json:"status"`
	AdapterID        string    `json:"adapter_id"`
	Endpoint         string    `json:"endpoint"`
	ManifestPath     string    `json:"manifest_path,omitempty"`
	ManifestDigest   string    `json:"manifest_digest,omitempty"`
	DescriptorDigest string    `json:"descriptor_manifest_digest,omitempty"`
	ProtocolVersion  string    `json:"protocol_version,omitempty"`
	Capabilities     []string  `json:"capabilities,omitempty"`
	Privileges       []string  `json:"privileges,omitempty"`
	Findings         []Finding `json:"findings,omitempty"`
}

type Finding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Verify(ctx context.Context, opts Options) Result {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := Result{
		Kind:           "AdapterRuntimeVerifyResult",
		Status:         "passed",
		AdapterID:      strings.TrimSpace(valueOrDefault(opts.AdapterID, opts.Manifest.AdapterID)),
		Endpoint:       strings.TrimSpace(opts.Endpoint),
		ManifestPath:   opts.Manifest.Path,
		ManifestDigest: opts.Manifest.Digest,
	}
	if result.Endpoint == "" {
		result.fail("adapter_endpoint_missing", "adapter verify requires an endpoint")
		return result
	}
	if opts.Manifest.AdapterID == "" || opts.Manifest.Digest == "" {
		result.fail("adapter_manifest_missing", "adapter verify requires a loaded adapter manifest with digest")
		return result
	}
	if result.AdapterID != "" && result.AdapterID != opts.Manifest.AdapterID {
		result.fail("adapter_manifest_mismatch", fmt.Sprintf("requested adapter %q does not match manifest adapter_id %q", result.AdapterID, opts.Manifest.AdapterID))
		return result
	}

	dialOptions, err := dialOptions(opts)
	if err != nil {
		result.fail("adapter_transport_invalid", err.Error())
		return result
	}
	conn, err := grpc.NewClient(result.Endpoint, dialOptions...)
	if err != nil {
		result.fail("adapter_dial_failed", err.Error())
		return result
	}
	defer conn.Close()

	describe, err := adapterv1.NewAdapterServiceClient(conn).Describe(ctx, &adapterv1.DescribeRequest{})
	if err != nil {
		result.fail("adapter_describe_failed", err.Error())
		return result
	}
	desc := describe.GetAdapter()
	if desc != nil {
		result.AdapterID = desc.GetAdapterId()
		result.ProtocolVersion = desc.GetProtocolVersion()
		result.DescriptorDigest = desc.GetManifestDigest()
		for _, capability := range desc.GetCapabilities() {
			result.Capabilities = append(result.Capabilities, capability.GetId())
		}
		for _, privilege := range desc.GetPrivileges() {
			result.Privileges = append(result.Privileges, privilege.GetId())
		}
	}
	if err := compiler.ValidateAdapterRuntimeDescribe(opts.Manifest, compiler.AdapterRuntimeDescribe{Descriptor: desc}); err != nil {
		result.fail("adapter_runtime_verify_failed", err.Error())
		return result
	}
	return result
}

func dialOptions(opts Options) ([]grpc.DialOption, error) {
	if opts.DevInsecureTransport {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	if strings.TrimSpace(opts.CAPath) == "" || strings.TrimSpace(opts.ClientCertPath) == "" || strings.TrimSpace(opts.ClientKeyPath) == "" {
		return nil, fmt.Errorf("adapter transport requires --adapter-ca, --adapter-client-cert and --adapter-client-key unless --dev-insecure-transport is set")
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
	}
	if serverName := strings.TrimSpace(opts.TLSServerName); serverName != "" {
		tlsConfig.ServerName = serverName
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

func (r *Result) fail(code, message string) {
	r.Status = "failed"
	r.Findings = append(r.Findings, Finding{Code: code, Message: message})
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fallback)
}
