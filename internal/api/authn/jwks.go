// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func LoadJWKS(ctx context.Context, jwksURL string) (map[string]*rsa.PublicKey, error) {
	jwksURL = strings.TrimSpace(jwksURL)
	if jwksURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("jwks fetch failed: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseJWKS(data)
}

func ParseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for index, key := range doc.Keys {
		if strings.ToUpper(strings.TrimSpace(key.Kty)) != "RSA" {
			continue
		}
		if strings.TrimSpace(key.Use) != "" && strings.TrimSpace(key.Use) != "sig" {
			continue
		}
		if strings.TrimSpace(key.Alg) != "" && strings.TrimSpace(key.Alg) != "RS256" {
			continue
		}
		publicKey, err := parseJWKRSAKey(key)
		if err != nil {
			return nil, fmt.Errorf("jwks key %q invalid: %w", key.Kid, err)
		}
		kid := strings.TrimSpace(key.Kid)
		if kid == "" {
			kid = fmt.Sprintf("jwks.key.%d", index)
		}
		if _, exists := keys[kid]; exists {
			return nil, fmt.Errorf("duplicate jwks kid %q", kid)
		}
		keys[kid] = publicKey
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks contains no usable RS256 signing keys")
	}
	return keys, nil
}

func parseJWKRSAKey(key jwkKey) (*rsa.PublicKey, error) {
	if strings.TrimSpace(key.N) == "" || strings.TrimSpace(key.E) == "" {
		return nil, fmt.Errorf("missing modulus or exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	exponent := int(new(big.Int).SetBytes(eBytes).Int64())
	if exponent < 3 {
		return nil, fmt.Errorf("invalid rsa exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: exponent,
	}, nil
}
