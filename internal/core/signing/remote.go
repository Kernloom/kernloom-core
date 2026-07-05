// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type RemoteSigner struct {
	URL                  string
	HTTPClient           *http.Client
	AllowDevInsecureHTTP bool
	CAPath               string
	ClientCertPath       string
	ClientKeyPath        string
	ServerName           string
	ServerCertificatePin string
}

type SignRequest struct {
	Payload []byte   `json:"payload"`
	Meta    Metadata `json:"meta"`
}

type SignResponse struct {
	Envelope SignedEnvelope `json:"envelope"`
}

func (s RemoteSigner) Sign(ctx context.Context, payload []byte, meta Metadata) (SignedEnvelope, error) {
	endpoint, err := s.endpoint()
	if err != nil {
		return SignedEnvelope{}, err
	}
	body, err := json.Marshal(SignRequest{Payload: payload, Meta: meta})
	if err != nil {
		return SignedEnvelope{}, err
	}
	client, err := s.client()
	if err != nil {
		return SignedEnvelope{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return SignedEnvelope{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return SignedEnvelope{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return SignedEnvelope{}, fmt.Errorf("remote signer returned %s", resp.Status)
	}
	var signResp SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return SignedEnvelope{}, err
	}
	if signResp.Envelope.Kind != "SignedEnvelope" {
		return SignedEnvelope{}, fmt.Errorf("remote signer returned invalid envelope")
	}
	return signResp.Envelope, nil
}

func (s RemoteSigner) endpoint() (string, error) {
	rawURL := strings.TrimSpace(s.URL)
	if rawURL == "" {
		return "", fmt.Errorf("remote signer url is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !s.AllowDevInsecureHTTP {
			return "", fmt.Errorf("remote signer url %q uses plaintext http; pass explicit dev-insecure signer transport only for local smoke tests", rawURL)
		}
	default:
		return "", fmt.Errorf("remote signer url %q must use https", rawURL)
	}
	return strings.TrimRight(rawURL, "/") + "/v1/sign", nil
}

func (s RemoteSigner) client() (*http.Client, error) {
	if s.HTTPClient != nil {
		return s.HTTPClient, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(strings.TrimSpace(s.URL), "https://") {
		config, err := s.tlsConfig()
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = config
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}, nil
}

func (s RemoteSigner) tlsConfig() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: strings.TrimSpace(s.ServerName),
	}
	if caPath := strings.TrimSpace(s.CAPath); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("remote signer ca %q does not contain a PEM certificate", caPath)
		}
		config.RootCAs = pool
	}
	clientCertPath := strings.TrimSpace(s.ClientCertPath)
	clientKeyPath := strings.TrimSpace(s.ClientKeyPath)
	if clientCertPath != "" || clientKeyPath != "" {
		if clientCertPath == "" || clientKeyPath == "" {
			return nil, fmt.Errorf("remote signer client cert and key must be provided together")
		}
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{clientCert}
	}
	if pin := normalizeSHA256Pin(s.ServerCertificatePin); pin != "" {
		config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("remote signer certificate pin requires peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := "sha256:" + hex.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("remote signer certificate pin mismatch")
			}
			return nil
		}
	}
	return config, nil
}

func normalizeSHA256Pin(pin string) string {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if pin == "" {
		return ""
	}
	if strings.HasPrefix(pin, "sha256:") {
		return pin
	}
	return "sha256:" + pin
}

func Handler(signer Signer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/sign", func(w http.ResponseWriter, r *http.Request) {
		if signer == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signer_not_configured"})
			return
		}
		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
			return
		}
		envelope, err := signer.Sign(r.Context(), req.Payload, req.Meta)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, SignResponse{Envelope: envelope})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
