// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var ErrUnauthenticated = errors.New("unauthenticated")

type Verifier interface {
	Verify(ctx context.Context, token string) (Principal, error)
}

type RequestVerifier interface {
	VerifyRequest(ctx context.Context, r *http.Request) (Principal, error)
}

type Chain []Verifier

func (c Chain) Verify(ctx context.Context, token string) (Principal, error) {
	var lastErr error
	for _, verifier := range c {
		principal, err := verifier.Verify(ctx, token)
		if err == nil {
			return principal, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return Principal{}, lastErr
	}
	return Principal{}, ErrUnauthenticated
}

func (c Chain) VerifyRequest(ctx context.Context, r *http.Request) (Principal, error) {
	var lastErr error
	for _, verifier := range c {
		requestVerifier, ok := verifier.(RequestVerifier)
		if !ok {
			continue
		}
		principal, err := requestVerifier.VerifyRequest(ctx, r)
		if err == nil {
			return principal, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return Principal{}, lastErr
	}
	return Principal{}, ErrUnauthenticated
}

func BearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", ErrUnauthenticated
	}
	return token, nil
}

type DevTokenVerifier struct{}

func (DevTokenVerifier) Verify(_ context.Context, token string) (Principal, error) {
	if !strings.HasPrefix(token, "dev:") {
		return Principal{}, ErrUnauthenticated
	}
	parts := strings.Split(token, ":")
	if len(parts) != 6 {
		return Principal{}, fmt.Errorf("invalid dev token shape")
	}
	roles := splitCSV(parts[2])
	if parts[1] == "" || len(roles) == 0 {
		return Principal{}, fmt.Errorf("invalid dev token subject or roles")
	}
	return Principal{
		Subject: parts[1],
		Roles:   roles,
		Scope: Scope{
			Org:         parts[3],
			Environment: parts[4],
			Stage:       parts[5],
		},
		Claims: map[string]any{"provider": "dev-token"},
	}, nil
}

type JWTVerifier struct {
	Issuer            string
	Audience          string
	HMACSecret        []byte
	RSAPublicKey      *rsa.PublicKey
	RSAPublicKeys     map[string]*rsa.PublicKey
	AllowMissingRoles bool
	Now               func() time.Time
}

func (v JWTVerifier) Verify(_ context.Context, token string) (Principal, error) {
	if len(v.HMACSecret) == 0 && v.RSAPublicKey == nil && len(v.RSAPublicKeys) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, ErrUnauthenticated
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Principal{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid,omitempty"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Principal{}, err
	}
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Principal{}, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	switch header.Alg {
	case "HS256":
		if len(v.HMACSecret) == 0 {
			return Principal{}, ErrUnauthenticated
		}
		mac := hmac.New(sha256.New, v.HMACSecret)
		mac.Write(signed)
		if !hmac.Equal(actual, mac.Sum(nil)) {
			return Principal{}, ErrUnauthenticated
		}
	case "RS256":
		publicKey, err := v.rsaPublicKey(header.Kid)
		if err != nil {
			return Principal{}, ErrUnauthenticated
		}
		digest := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], actual); err != nil {
			return Principal{}, ErrUnauthenticated
		}
	default:
		return Principal{}, fmt.Errorf("unsupported jwt alg %q", header.Alg)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Principal{}, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Principal{}, err
	}
	if err := v.validateClaims(claims); err != nil {
		return Principal{}, err
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return Principal{}, fmt.Errorf("jwt missing subject")
	}
	roles := rolesFromClaims(claims)
	if len(roles) == 0 && !v.AllowMissingRoles {
		return Principal{}, fmt.Errorf("jwt missing roles")
	}
	return Principal{
		Subject: subject,
		Roles:   roles,
		Scope:   scopeFromClaims(claims),
		Claims:  claims,
	}, nil
}

func (v JWTVerifier) rsaPublicKey(kid string) (*rsa.PublicKey, error) {
	kid = strings.TrimSpace(kid)
	if len(v.RSAPublicKeys) == 0 {
		if v.RSAPublicKey == nil {
			return nil, ErrUnauthenticated
		}
		return v.RSAPublicKey, nil
	}
	if kid != "" {
		key, ok := v.RSAPublicKeys[kid]
		if !ok || key == nil {
			return nil, fmt.Errorf("jwt kid %q is not trusted", kid)
		}
		return key, nil
	}
	if len(v.RSAPublicKeys) == 1 {
		for _, key := range v.RSAPublicKeys {
			if key != nil {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("jwt kid is required when multiple JWKS keys are configured")
}

func (v JWTVerifier) validateClaims(claims map[string]any) error {
	if v.Issuer != "" {
		issuer, _ := claims["iss"].(string)
		if issuer != v.Issuer {
			return fmt.Errorf("jwt issuer %q does not match configured issuer", issuer)
		}
	}
	if v.Audience != "" && !audienceContains(claims["aud"], v.Audience) {
		return fmt.Errorf("jwt audience does not include configured audience")
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	current := now().Unix()
	if exp, ok := numericClaim(claims["exp"]); ok && current >= exp {
		return fmt.Errorf("jwt expired")
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && current < nbf {
		return fmt.Errorf("jwt not valid yet")
	}
	return nil
}

func rolesFromClaims(claims map[string]any) []string {
	for _, key := range []string{"roles", "groups"} {
		if roles := stringSliceClaim(claims[key]); len(roles) > 0 {
			return roles
		}
	}
	if access, ok := claims["realm_access"].(map[string]any); ok {
		return stringSliceClaim(access["roles"])
	}
	if scope, ok := claims["scope"].(string); ok {
		return strings.Fields(scope)
	}
	return nil
}

func scopeFromClaims(claims map[string]any) Scope {
	scope := Scope{}
	if raw, ok := claims["kernloom_scope"].(map[string]any); ok {
		scope.Org, _ = raw["org"].(string)
		scope.Environment, _ = raw["environment"].(string)
		scope.Stage, _ = raw["stage"].(string)
		scope.PolicyType, _ = raw["policy_type"].(string)
		scope.Resource, _ = raw["resource"].(string)
		scope.Adapter, _ = raw["adapter"].(string)
		scope.Repo, _ = raw["repo"].(string)
	}
	if value, ok := claims["org"].(string); ok && scope.Org == "" {
		scope.Org = value
	}
	if value, ok := claims["environment"].(string); ok && scope.Environment == "" {
		scope.Environment = value
	}
	if value, ok := claims["stage"].(string); ok && scope.Stage == "" {
		scope.Stage = value
	}
	return scope
}

func audienceContains(raw any, expected string) bool {
	switch value := raw.(type) {
	case string:
		return value == expected
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok && text == expected {
				return true
			}
		}
	}
	return false
}

func numericClaim(raw any) (int64, bool) {
	switch value := raw.(type) {
	case float64:
		return int64(value), true
	case int64:
		return value, true
	}
	return 0, false
}

func stringSliceClaim(raw any) []string {
	switch value := raw.(type) {
	case []string:
		return value
	case []any:
		var out []string
		for _, item := range value {
			if text, ok := item.(string); ok && text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		return splitCSV(value)
	}
	return nil
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
