// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type DevLocalKeyFile struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	PrivateKey []byte `json:"private_key,omitempty"`
	PublicKey  []byte `json:"public_key"`
}

func LoadOrCreateDevLocalSigner(path, keyID string) (*DevLocalSigner, error) {
	if path == "" {
		return nil, fmt.Errorf("dev-local signing key path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return loadDevLocalSigner(path, true)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	signer, err := NewDevLocalSigner(valueOrDefault(keyID, "dev-local"))
	if err != nil {
		return nil, err
	}
	if err := saveDevLocalKey(path, signer); err != nil {
		return nil, err
	}
	return signer, nil
}

func LoadDevLocalVerifier(path string) (*DevLocalSigner, error) {
	return loadDevLocalSigner(path, false)
}

func loadDevLocalSigner(path string, requirePrivate bool) (*DevLocalSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var key DevLocalKeyFile
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	if key.Algorithm != "Ed25519" {
		return nil, fmt.Errorf("%s: unsupported key algorithm %q", path, key.Algorithm)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s: invalid Ed25519 public key", path)
	}
	if requirePrivate && len(key.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: invalid Ed25519 private key", path)
	}
	return &DevLocalSigner{
		KeyID:      key.KeyID,
		PrivateKey: ed25519.PrivateKey(key.PrivateKey),
		PublicKey:  ed25519.PublicKey(key.PublicKey),
	}, nil
}

func saveDevLocalKey(path string, signer *DevLocalSigner) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(DevLocalKeyFile{
		KeyID:      signer.KeyID,
		Algorithm:  "Ed25519",
		PrivateKey: []byte(signer.PrivateKey),
		PublicKey:  []byte(signer.PublicKey),
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
