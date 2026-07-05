// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
)

type enrollRequest struct {
	EnrollmentToken string   `json:"enrollment_token"`
	NodeID          string   `json:"node_id"`
	Environment     string   `json:"environment"`
	Stage           string   `json:"stage"`
	Scope           string   `json:"scope"`
	Version         string   `json:"version"`
	TrustKeyID      string   `json:"trust_key_id,omitempty"`
	PublicKeyPEM    string   `json:"public_key_pem"`
	SPIFFEID        string   `json:"spiffe_id,omitempty"`
	Adapters        []string `json:"adapter_inventory,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

type enrollResponse struct {
	Registration domain.KLIQRegistration `json:"registration"`
	ServiceToken string                  `json:"service_token,omitempty"`
}

func enroll(args []string) {
	fs := flag.NewFlagSet("kliq enroll", flag.ExitOnError)
	forgeURL := fs.String("forge", "", "Forge API base URL")
	devInsecureForgeTransport := fs.Bool("dev-insecure-forge-transport", false, "allow plaintext http Forge transport; dev/smoke only")
	forgeTransport := forgeTransportOptions{}
	fs.StringVar(&forgeTransport.CAPath, "forge-ca", "", "Forge HTTPS CA bundle")
	fs.StringVar(&forgeTransport.ClientCertPath, "forge-client-cert", "", "Forge mTLS client certificate")
	fs.StringVar(&forgeTransport.ClientKeyPath, "forge-client-key", "", "Forge mTLS client private key")
	fs.StringVar(&forgeTransport.ServerName, "forge-server-name", "", "expected Forge TLS server name")
	fs.StringVar(&forgeTransport.ServerCertificateSHA256, "forge-cert-sha256", "", "expected Forge leaf certificate SHA-256 pin")
	enrollmentToken := fs.String("enrollment-token", "", "single-use KLIQ enrollment token")
	nodeID := fs.String("node-id", "", "local node id")
	environment := fs.String("environment", "", "KLIQ environment")
	stage := fs.String("stage", "", "KLIQ stage")
	scope := fs.String("scope", "", "KLIQ assigned scope")
	version := fs.String("version", "dev", "local KLIQ version")
	trustKeyID := fs.String("trust-key-id", "forge-management-dev-local", "trusted assignment signing key id")
	adapterInventory := fs.String("adapter-inventory", "", "comma-separated adapter ids observed locally")
	capabilities := fs.String("capabilities", "", "comma-separated KLIQ/adapter capabilities")
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *forgeURL == "" || *enrollmentToken == "" || *nodeID == "" || *environment == "" || *stage == "" || *scope == "" {
		fmt.Fprintln(os.Stderr, "kliq enroll requires --forge, --enrollment-token, --node-id, --environment, --stage and --scope")
		os.Exit(2)
	}
	publicKeyPEM, privateKeyPEM, err := generateLocalIdentityPEM()
	if err != nil {
		logError("kliq_enroll_identity_generation_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	httpClient, err := forgeHTTPClient(forgeTransport)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	response, err := requestEnrollment(context.Background(), httpClient, *forgeURL, *devInsecureForgeTransport, enrollRequest{
		EnrollmentToken: *enrollmentToken,
		NodeID:          *nodeID,
		Environment:     *environment,
		Stage:           *stage,
		Scope:           *scope,
		Version:         *version,
		TrustKeyID:      *trustKeyID,
		PublicKeyPEM:    publicKeyPEM,
		Adapters:        splitCSV(*adapterInventory),
		Capabilities:    splitCSV(*capabilities),
	})
	if err != nil {
		logError("kliq_enroll_failed", "node_id", *nodeID, "environment", *environment, "stage", *stage, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if response.Registration.KLIQID == "" {
		fmt.Fprintln(os.Stderr, "forge enrollment response did not include kliq_id")
		os.Exit(1)
	}
	serviceToken := response.ServiceToken
	if serviceToken == "" {
		serviceToken, err = authn.IssueKLIQIdentitySignedToken(response.Registration.Identity, privateKeyPEM, 24*time.Hour, time.Now)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	tokenExpiresAt, err := serviceTokenExpiresAt(serviceToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := actionstate.OpenSQLite(*statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	now := time.Now().UTC()
	if err := store.SaveKLIQCredential(context.Background(), actionstate.KLIQCredential{
		KLIQID:                  response.Registration.KLIQID,
		NodeID:                  *nodeID,
		Environment:             *environment,
		Stage:                   *stage,
		Scope:                   *scope,
		TrustKeyID:              response.Registration.Identity.TrustKeyID,
		AssignmentURL:           strings.TrimRight(*forgeURL, "/"),
		PublicKeyPEM:            publicKeyPEM,
		PrivateKeyPEM:           privateKeyPEM,
		ServiceIdentityProvider: response.Registration.Identity.ServiceIdentityProvider,
		SPIFFEID:                response.Registration.Identity.SPIFFEID,
		CredentialStatus:        response.Registration.Identity.CredentialStatus,
		ServiceToken:            serviceToken,
		ServiceTokenExpiresAt:   tokenExpiresAt,
		CreatedAt:               now,
		UpdatedAt:               now,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logInfo("kliq_enrolled", "kliq_id", response.Registration.KLIQID, "environment", *environment, "stage", *stage, "scope", *scope)
	fmt.Println("kliq enrolled")
	fmt.Printf("  kliq_id: %s\n", response.Registration.KLIQID)
	fmt.Printf("  state: %s\n", *statePath)
	fmt.Printf("  service_token_expires_at: %s\n", tokenExpiresAt.Format(time.RFC3339))
}

func requestEnrollment(ctx context.Context, client *http.Client, forgeURL string, allowDevInsecureTransport bool, req enrollRequest) (enrollResponse, error) {
	if err := validateSecureForgeURL(forgeURL, allowDevInsecureTransport); err != nil {
		return enrollResponse{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	data, err := json.Marshal(req)
	if err != nil {
		return enrollResponse{}, err
	}
	url := strings.TrimRight(forgeURL, "/") + "/v1/kliq/enroll"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return enrollResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return enrollResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return enrollResponse{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return enrollResponse{}, fmt.Errorf("forge enrollment returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed enrollResponse
	return parsed, json.Unmarshal(body, &parsed)
}

func generateLocalIdentityPEM() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return string(publicPEM), string(privatePEM), nil
}

func serviceTokenExpiresAt(token string) (time.Time, error) {
	if !strings.HasPrefix(token, "kliqsvc.") && !strings.HasPrefix(token, "kliqsig.") {
		return time.Time{}, fmt.Errorf("unsupported kliq service token format")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid kliq service token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, err
	}
	var claims authn.KLIQServiceClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, err
	}
	if claims.ExpiresAt <= 0 {
		return time.Time{}, fmt.Errorf("kliq service token missing exp")
	}
	return time.Unix(claims.ExpiresAt, 0).UTC(), nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func loadLocalKLIQCredential(statePath string) (actionstate.KLIQCredential, error) {
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		return actionstate.KLIQCredential{}, err
	}
	defer store.Close()
	return store.KLIQCredential(context.Background())
}
