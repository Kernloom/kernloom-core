// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

const defaultTrustBundlePath = "/etc/kernloom/trust/forge-management.public.json"

type trustMaterial struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	PublicKey  []byte `json:"public_key,omitempty"`
}

func loadTrustVerifier(path string, allowPrivateDevMaterial bool) (signing.Verifier, domain.TrustBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, domain.TrustBundle{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, domain.TrustBundle{}, err
	}
	if privateRaw, ok := raw["private_key"]; ok && string(privateRaw) != `""` && string(privateRaw) != "null" {
		if !allowPrivateDevMaterial {
			return nil, domain.TrustBundle{}, fmt.Errorf("%s contains private signing material; use a public trust bundle for KLIQ verification", path)
		}
		var key trustMaterial
		if err := json.Unmarshal(data, &key); err != nil {
			return nil, domain.TrustBundle{}, err
		}
		return verifierFromTrustMaterial(path, key)
	}
	if bundle, ok, err := parseDomainTrustBundle(data); ok || err != nil {
		if err != nil {
			return nil, domain.TrustBundle{}, err
		}
		verifier, err := verifierFromTrustBundle(bundle)
		return verifier, bundle, err
	}
	var key trustMaterial
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, domain.TrustBundle{}, err
	}
	return verifierFromTrustMaterial(path, key)
}

func verifierFromTrustMaterial(path string, key trustMaterial) (signing.Verifier, domain.TrustBundle, error) {
	if key.Algorithm != "" && key.Algorithm != "Ed25519" {
		return nil, domain.TrustBundle{}, fmt.Errorf("%s: unsupported trust key algorithm %q", path, key.Algorithm)
	}
	verifier, err := signing.NewEd25519Verifier(key.KeyID, key.PublicKey)
	if err != nil {
		return nil, domain.TrustBundle{}, fmt.Errorf("%s: %w", path, err)
	}
	return verifier, domain.TrustBundle{
		KeyID:     key.KeyID,
		PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey),
		Purpose:   "assignment_verification",
		Status:    "active",
		Issuer:    "local-dev-public-key",
	}, nil
}

func parseDomainTrustBundle(data []byte) (domain.TrustBundle, bool, error) {
	var bundle domain.TrustBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return domain.TrustBundle{}, false, nil
	}
	if bundle.KeyID == "" && bundle.PublicKey == "" && bundle.Status == "" && bundle.Purpose == "" {
		return domain.TrustBundle{}, false, nil
	}
	if bundle.KeyID == "" || strings.TrimSpace(bundle.PublicKey) == "" {
		return domain.TrustBundle{}, true, fmt.Errorf("trust bundle requires key_id and public_key")
	}
	if bundle.Status == "" {
		bundle.Status = "active"
	}
	if bundle.Purpose == "" {
		bundle.Purpose = "assignment_verification"
	}
	return bundle, true, validateTrustBundleForKLIQ(bundle)
}

func verifierFromTrustBundle(bundle domain.TrustBundle) (signing.Verifier, error) {
	publicKey, err := decodeTrustBundlePublicKey(bundle.PublicKey)
	if err != nil {
		return nil, err
	}
	return signing.NewEd25519Verifier(bundle.KeyID, publicKey)
}

func decodeTrustBundlePublicKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if block, _ := pem.Decode([]byte(value)); block != nil {
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		edKey, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("trust bundle public key is not Ed25519")
		}
		return []byte(edKey), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, fmt.Errorf("trust bundle public_key must be PEM or base64 Ed25519 key")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trust bundle public_key has invalid Ed25519 length")
	}
	return decoded, nil
}

func validateTrustBundleForKLIQ(bundle domain.TrustBundle) error {
	switch bundle.Status {
	case "active", "previous":
	default:
		return fmt.Errorf("trust bundle %q is %q and cannot verify new managed assignments", bundle.KeyID, bundle.Status)
	}
	if !bundle.ExpiresAt.IsZero() && !time.Now().UTC().Before(bundle.ExpiresAt.UTC()) {
		return fmt.Errorf("trust bundle %q is expired", bundle.KeyID)
	}
	return nil
}
