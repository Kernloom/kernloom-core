// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const KLIQServiceRole = "kliq-service"

type KLIQServiceTokenIssuer struct {
	Secret []byte
	Now    func() time.Time
}

type KLIQServiceClaims struct {
	Subject     string `json:"sub"`
	KLIQID      string `json:"kliq_id"`
	Environment string `json:"environment"`
	Stage       string `json:"stage"`
	Scope       string `json:"scope"`
	ExpiresAt   int64  `json:"exp"`
	IssuedAt    int64  `json:"iat"`
}

func (i KLIQServiceTokenIssuer) Issue(kliqID, environment, stage, scope string, ttl time.Duration) (string, error) {
	if len(i.Secret) == 0 {
		return "", fmt.Errorf("kliq service token issuer requires secret")
	}
	if kliqID == "" {
		return "", fmt.Errorf("kliq service token requires kliq_id")
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	issuedAt := now().UTC()
	claims := KLIQServiceClaims{
		Subject:     "kliq:" + kliqID,
		KLIQID:      kliqID,
		Environment: environment,
		Stage:       stage,
		Scope:       scope,
		IssuedAt:    issuedAt.Unix(),
		ExpiresAt:   issuedAt.Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := serviceTokenSignature(i.Secret, encodedPayload)
	return "kliqsvc." + encodedPayload + "." + signature, nil
}

func (i KLIQServiceTokenIssuer) Verify(_ context.Context, token string) (Principal, error) {
	if len(i.Secret) == 0 || !strings.HasPrefix(token, "kliqsvc.") {
		return Principal{}, ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, ErrUnauthenticated
	}
	expected := serviceTokenSignature(i.Secret, parts[1])
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return Principal{}, ErrUnauthenticated
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Principal{}, err
	}
	var claims KLIQServiceClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Principal{}, err
	}
	if claims.Subject == "" || claims.KLIQID == "" {
		return Principal{}, fmt.Errorf("kliq service token missing subject or kliq_id")
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	if claims.ExpiresAt <= now().UTC().Unix() {
		return Principal{}, fmt.Errorf("kliq service token expired")
	}
	return Principal{
		Subject: claims.Subject,
		Roles:   []string{KLIQServiceRole},
		Scope: Scope{
			Environment: claims.Environment,
			Stage:       claims.Stage,
		},
		Claims: map[string]any{
			"provider":    "kliq-service-token",
			"kliq_id":     claims.KLIQID,
			"kliq_scope":  claims.Scope,
			"environment": claims.Environment,
			"stage":       claims.Stage,
		},
	}, nil
}

func serviceTokenSignature(secret []byte, encodedPayload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(encodedPayload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func PrincipalKLIQID(principal Principal) string {
	if value, ok := principal.Claims["kliq_id"].(string); ok {
		return value
	}
	return strings.TrimPrefix(principal.Subject, "kliq:")
}

func PrincipalKLIQScope(principal Principal) string {
	if value, ok := principal.Claims["kliq_scope"].(string); ok {
		return value
	}
	return ""
}
