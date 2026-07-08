// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRefreshingJWKSRefreshesOnUnknownKID(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	jwksBody := testJWKSBody(t, "kid-1", &key1.PublicKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"jwks-test"`)
		w.Header().Set("Cache-Control", "max-age=60")
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(jwksBody)
	}))
	defer server.Close()

	provider, err := NewRefreshingJWKS(context.Background(), RefreshingJWKSOptions{
		URL:                server.URL,
		RefreshInterval:    time.Hour,
		MinRefreshInterval: time.Nanosecond,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := JWTVerifier{
		Issuer:             "https://issuer.example",
		Audience:           "kernloom-api",
		RSAPublicKeySource: provider,
		Now:                func() time.Time { return now },
	}
	claims := map[string]any{
		"sub":   "rotating-user",
		"iss":   "https://issuer.example",
		"aud":   "kernloom-api",
		"exp":   now.Add(time.Hour).Unix(),
		"roles": []string{"security-owner"},
	}
	if _, err := verifier.Verify(context.Background(), signedTestRS256JWTWithKID(t, key1, "kid-1", claims)); err != nil {
		t.Fatalf("expected initial key to verify: %v", err)
	}

	mu.Lock()
	jwksBody = testJWKSBody(t, "kid-2", &key2.PublicKey)
	mu.Unlock()
	now = now.Add(time.Second)
	if _, err := verifier.Verify(context.Background(), signedTestRS256JWTWithKID(t, key2, "kid-2", claims)); err != nil {
		t.Fatalf("expected unknown kid to trigger JWKS refresh: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), signedTestRS256JWTWithKID(t, key1, "kid-1", claims)); err == nil {
		t.Fatal("expected old rotated-out kid to be rejected")
	}
}

func testJWKSBody(t *testing.T, kid string, key *rsa.PublicKey) []byte {
	t.Helper()
	exponent := big.NewInt(int64(key.E)).Bytes()
	data, err := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signedTestRS256JWTWithKID(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
