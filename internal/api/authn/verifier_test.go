// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
)

func TestDevTokenVerifier(t *testing.T) {
	principal, err := (DevTokenVerifier{}).Verify(context.Background(), "dev:alice:policy-author,security-owner:acme:dev:prod")
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "alice" || !principal.HasRole("policy-author") || principal.Scope.Stage != "prod" {
		t.Fatalf("unexpected principal %#v", principal)
	}
}

func TestJWTVerifier(t *testing.T) {
	token := signedTestJWT(t, []byte("secret"), map[string]any{
		"sub":   "bob",
		"iss":   "https://issuer.example",
		"aud":   []string{"kernloom-api"},
		"exp":   time.Date(2026, 7, 2, 13, 0, 0, 0, time.UTC).Unix(),
		"roles": []string{"policy-reviewer"},
		"kernloom_scope": map[string]any{
			"org":         "acme",
			"environment": "prod",
			"stage":       "prod",
		},
	})
	verifier := JWTVerifier{
		Issuer:     "https://issuer.example",
		Audience:   "kernloom-api",
		HMACSecret: []byte("secret"),
		Now:        func() time.Time { return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC) },
	}
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "bob" || !principal.HasRole("policy-reviewer") || principal.Scope.Org != "acme" {
		t.Fatalf("unexpected principal %#v", principal)
	}
}

func TestJWTVerifierRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := signedTestRS256JWT(t, key, map[string]any{
		"sub":   "oidc-user",
		"iss":   "https://issuer.example",
		"aud":   "kernloom-api",
		"exp":   time.Date(2026, 7, 2, 13, 0, 0, 0, time.UTC).Unix(),
		"roles": []string{"security-owner"},
	})
	verifier := JWTVerifier{
		Issuer:       "https://issuer.example",
		Audience:     "kernloom-api",
		RSAPublicKey: &key.PublicKey,
		Now:          func() time.Time { return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC) },
	}
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "oidc-user" || !principal.HasRole("security-owner") {
		t.Fatalf("unexpected principal %#v", principal)
	}
}

func TestKLIQIdentityTokenVerifierUsesRegisteredPublicKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	identity := domain.KLIQIdentity{
		KLIQID:                  "kliq.test",
		NodeID:                  "node-1",
		Environment:             "prod",
		Stage:                   "prod",
		Scope:                   "edge-prod",
		PublicKeyPEM:            string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		ServiceIdentityProvider: ServiceIdentityProviderSPIFFEReady,
		SPIFFEID:                DefaultKLIQSPIFFEID("kliq.test", "prod", "prod", "edge-prod"),
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	token, err := IssueKLIQIdentitySignedToken(identity, privatePEM, time.Hour, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	verifier := KLIQIdentityTokenVerifier{
		Store: testIdentityStore{identity: identity},
		Now:   func() time.Time { return now },
	}
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "kliq:kliq.test" || !principal.HasRole(KLIQServiceRole) || PrincipalSPIFFEID(principal) != identity.SPIFFEID {
		t.Fatalf("unexpected principal %#v", principal)
	}
}

func TestKLIQMTLSSPIFFEVerifierUsesRegisteredIdentity(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	spiffeID := DefaultKLIQSPIFFEID("kliq.test", "prod", "prod", "edge-prod")
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	identity := domain.KLIQIdentity{
		KLIQID:                  "kliq.test",
		NodeID:                  "node-1",
		Environment:             "prod",
		Stage:                   "prod",
		Scope:                   "edge-prod",
		ServiceIdentityProvider: ServiceIdentityProviderSPIFFEReady,
		SPIFFEID:                spiffeID,
		CredentialStatus:        "active",
		Status:                  "active",
		CredentialExpiresAt:     now.Add(time.Hour),
	}
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{uri}}}}}
	principal, err := (KLIQMTLSSPIFFEVerifier{
		Store: testIdentityStore{identity: identity},
		Now:   func() time.Time { return now },
	}).VerifyRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "kliq:kliq.test" || PrincipalSPIFFEID(principal) != spiffeID {
		t.Fatalf("unexpected mTLS principal %#v", principal)
	}
}

func signedTestJWT(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signedTestRS256JWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
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

type testIdentityStore struct {
	identity domain.KLIQIdentity
}

func (s testIdentityStore) Identity(_ context.Context, kliqID string) (domain.KLIQIdentity, error) {
	if kliqID != s.identity.KLIQID {
		return domain.KLIQIdentity{}, ErrUnauthenticated
	}
	return s.identity, nil
}
