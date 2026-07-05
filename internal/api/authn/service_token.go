// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
)

const KLIQServiceRole = "kliq-service"

const (
	ServiceIdentityProviderDevLocalSignedToken = "dev-local-signed-token"
	ServiceIdentityProviderSPIFFEReady         = "spiffe-ready"
)

type KLIQServiceTokenIssuer struct {
	Secret []byte
	Now    func() time.Time
}

type KLIQIdentityStore interface {
	Identity(ctx context.Context, kliqID string) (domain.KLIQIdentity, error)
}

type KLIQIdentityTokenVerifier struct {
	Store KLIQIdentityStore
	Now   func() time.Time
}

type KLIQMTLSSPIFFEVerifier struct {
	Store KLIQIdentityStore
	Now   func() time.Time
}

type KLIQServiceClaims struct {
	Subject                 string `json:"sub"`
	KLIQID                  string `json:"kliq_id"`
	Environment             string `json:"environment"`
	Stage                   string `json:"stage"`
	Scope                   string `json:"scope"`
	ServiceIdentityProvider string `json:"service_identity_provider"`
	SPIFFEID                string `json:"spiffe_id,omitempty"`
	IdentityMaterialSHA256  string `json:"identity_material_sha256,omitempty"`
	ExpiresAt               int64  `json:"exp"`
	IssuedAt                int64  `json:"iat"`
}

func (i KLIQServiceTokenIssuer) Issue(kliqID, environment, stage, scope string, ttl time.Duration) (string, error) {
	return i.issue(kliqID, environment, stage, scope, ServiceIdentityProviderDevLocalSignedToken, DefaultKLIQSPIFFEID(kliqID, environment, stage, scope), "", ttl)
}

func (i KLIQServiceTokenIssuer) IssueForIdentity(identity domain.KLIQIdentity, ttl time.Duration) (string, error) {
	provider := strings.TrimSpace(identity.ServiceIdentityProvider)
	if provider == "" {
		provider = ServiceIdentityProviderSPIFFEReady
	}
	return i.issue(identity.KLIQID, identity.Environment, identity.Stage, identity.Scope, provider, identity.SPIFFEID, IdentityMaterialSHA256(identity), ttl)
}

func (i KLIQServiceTokenIssuer) issue(kliqID, environment, stage, scope, provider, spiffeID, identityMaterialSHA256 string, ttl time.Duration) (string, error) {
	if len(i.Secret) == 0 {
		return "", fmt.Errorf("kliq service token issuer requires secret")
	}
	if kliqID == "" {
		return "", fmt.Errorf("kliq service token requires kliq_id")
	}
	if provider == "" {
		provider = ServiceIdentityProviderDevLocalSignedToken
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	issuedAt := now().UTC()
	claims := KLIQServiceClaims{
		Subject:                 "kliq:" + kliqID,
		KLIQID:                  kliqID,
		Environment:             environment,
		Stage:                   stage,
		Scope:                   scope,
		ServiceIdentityProvider: provider,
		SPIFFEID:                spiffeID,
		IdentityMaterialSHA256:  identityMaterialSHA256,
		IssuedAt:                issuedAt.Unix(),
		ExpiresAt:               issuedAt.Add(ttl).Unix(),
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
			"provider":                  "kliq-service-token",
			"kliq_id":                   claims.KLIQID,
			"kliq_scope":                claims.Scope,
			"environment":               claims.Environment,
			"stage":                     claims.Stage,
			"service_identity_provider": claims.ServiceIdentityProvider,
			"spiffe_id":                 claims.SPIFFEID,
			"identity_material_sha256":  claims.IdentityMaterialSHA256,
		},
	}, nil
}

func IssueKLIQIdentitySignedToken(identity domain.KLIQIdentity, privateKeyPEM string, ttl time.Duration, now func() time.Time) (string, error) {
	privateKey, err := parseEd25519PrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}
	if identity.KLIQID == "" {
		return "", fmt.Errorf("kliq identity signed token requires kliq_id")
	}
	if now == nil {
		now = time.Now
	}
	issuedAt := now().UTC()
	provider := strings.TrimSpace(identity.ServiceIdentityProvider)
	if provider == "" {
		provider = ServiceIdentityProviderSPIFFEReady
	}
	claims := KLIQServiceClaims{
		Subject:                 "kliq:" + identity.KLIQID,
		KLIQID:                  identity.KLIQID,
		Environment:             identity.Environment,
		Stage:                   identity.Stage,
		Scope:                   identity.Scope,
		ServiceIdentityProvider: provider,
		SPIFFEID:                identity.SPIFFEID,
		IdentityMaterialSHA256:  IdentityMaterialSHA256(identity),
		IssuedAt:                issuedAt.Unix(),
		ExpiresAt:               issuedAt.Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(privateKey, []byte(encodedPayload))
	return "kliqsig." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (v KLIQIdentityTokenVerifier) Verify(ctx context.Context, token string) (Principal, error) {
	if v.Store == nil || !strings.HasPrefix(token, "kliqsig.") {
		return Principal{}, ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, ErrUnauthenticated
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Principal{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Principal{}, err
	}
	var claims KLIQServiceClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Principal{}, err
	}
	if claims.Subject == "" || claims.KLIQID == "" {
		return Principal{}, fmt.Errorf("kliq identity token missing subject or kliq_id")
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if claims.ExpiresAt <= now().UTC().Unix() {
		return Principal{}, fmt.Errorf("kliq identity token expired")
	}
	identity, err := v.Store.Identity(ctx, claims.KLIQID)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	publicKey, err := parseEd25519PublicKeyPEM(identity.PublicKeyPEM)
	if err != nil {
		return Principal{}, err
	}
	if !ed25519.Verify(publicKey, []byte(parts[1]), signature) {
		return Principal{}, ErrUnauthenticated
	}
	if claims.Environment != identity.Environment ||
		claims.Stage != identity.Stage ||
		claims.Scope != identity.Scope ||
		claims.IdentityMaterialSHA256 != IdentityMaterialSHA256(identity) {
		return Principal{}, fmt.Errorf("kliq identity token claims do not match registered identity")
	}
	if claims.ServiceIdentityProvider != "" && identity.ServiceIdentityProvider != "" && claims.ServiceIdentityProvider != identity.ServiceIdentityProvider {
		return Principal{}, fmt.Errorf("kliq identity token provider does not match registered identity")
	}
	if claims.SPIFFEID != "" && identity.SPIFFEID != "" && claims.SPIFFEID != identity.SPIFFEID {
		return Principal{}, fmt.Errorf("kliq identity token spiffe id does not match registered identity")
	}
	return Principal{
		Subject: claims.Subject,
		Roles:   []string{KLIQServiceRole},
		Scope: Scope{
			Environment: claims.Environment,
			Stage:       claims.Stage,
		},
		Claims: map[string]any{
			"provider":                  "kliq-identity-signed-token",
			"kliq_id":                   claims.KLIQID,
			"kliq_scope":                claims.Scope,
			"environment":               claims.Environment,
			"stage":                     claims.Stage,
			"service_identity_provider": claims.ServiceIdentityProvider,
			"spiffe_id":                 claims.SPIFFEID,
			"identity_material_sha256":  claims.IdentityMaterialSHA256,
		},
	}, nil
}

func (v KLIQMTLSSPIFFEVerifier) Verify(_ context.Context, token string) (Principal, error) {
	return Principal{}, ErrUnauthenticated
}

func (v KLIQMTLSSPIFFEVerifier) VerifyRequest(ctx context.Context, r *http.Request) (Principal, error) {
	if v.Store == nil || r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	cert := r.TLS.PeerCertificates[0]
	spiffeID := ""
	for _, uri := range cert.URIs {
		if uri != nil && uri.Scheme == "spiffe" {
			spiffeID = uri.String()
			break
		}
	}
	if spiffeID == "" {
		return Principal{}, ErrUnauthenticated
	}
	kliqID := kliqIDFromSPIFFEID(spiffeID)
	if kliqID == "" {
		return Principal{}, fmt.Errorf("spiffe id does not contain kliq id")
	}
	identity, err := v.Store.Identity(ctx, kliqID)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	if identity.Status == "revoked" || identity.CredentialStatus == "revoked" || !identity.RevokedAt.IsZero() {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if !identity.CredentialExpiresAt.IsZero() && !now().UTC().Before(identity.CredentialExpiresAt.UTC()) {
		return Principal{}, fmt.Errorf("kliq mTLS identity credential expired")
	}
	if identity.SPIFFEID != "" && identity.SPIFFEID != spiffeID {
		return Principal{}, fmt.Errorf("spiffe id does not match registered identity")
	}
	return Principal{
		Subject: "kliq:" + identity.KLIQID,
		Roles:   []string{KLIQServiceRole},
		Scope: Scope{
			Environment: identity.Environment,
			Stage:       identity.Stage,
		},
		Claims: map[string]any{
			"provider":                  "kliq-mtls-spiffe",
			"kliq_id":                   identity.KLIQID,
			"kliq_scope":                identity.Scope,
			"environment":               identity.Environment,
			"stage":                     identity.Stage,
			"service_identity_provider": ServiceIdentityProviderSPIFFEReady,
			"spiffe_id":                 spiffeID,
			"identity_material_sha256":  IdentityMaterialSHA256(identity),
		},
	}, nil
}

func kliqIDFromSPIFFEID(spiffeID string) string {
	parts := strings.Split(strings.TrimSpace(spiffeID), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "kliq" {
			return parts[i+1]
		}
	}
	return ""
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

func PrincipalServiceIdentityProvider(principal Principal) string {
	if value, ok := principal.Claims["service_identity_provider"].(string); ok {
		return value
	}
	return ""
}

func PrincipalSPIFFEID(principal Principal) string {
	if value, ok := principal.Claims["spiffe_id"].(string); ok {
		return value
	}
	return ""
}

func PrincipalIdentityMaterialSHA256(principal Principal) string {
	if value, ok := principal.Claims["identity_material_sha256"].(string); ok {
		return value
	}
	return ""
}

func IdentityMaterialSHA256(identity domain.KLIQIdentity) string {
	material := strings.TrimSpace(identity.PublicKeyPEM)
	if material == "" {
		material = strings.TrimSpace(identity.CSRPEM)
	}
	if material == "" {
		return ""
	}
	return domain.SHA256JSON([]byte(material))
}

func parseEd25519PublicKeyPEM(value string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(value)))
	if block == nil {
		return nil, fmt.Errorf("missing public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return publicKey, nil
}

func parseEd25519PrivateKeyPEM(value string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(value)))
	if block == nil {
		return nil, fmt.Errorf("missing private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is not Ed25519")
	}
	return privateKey, nil
}

func DefaultKLIQSPIFFEID(kliqID, environment, stage, scope string) string {
	if kliqID == "" {
		return ""
	}
	parts := []string{"environment", environment, "stage", stage, "scope", scope, "kliq", kliqID}
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.TrimSpace(parts[i]), "/", "_")
	}
	return "spiffe://kernloom.local/" + strings.Join(parts, "/")
}
