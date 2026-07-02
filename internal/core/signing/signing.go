// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Signer interface {
	Sign(ctx context.Context, payload []byte, meta Metadata) (SignedEnvelope, error)
}

type Verifier interface {
	Verify(ctx context.Context, envelope SignedEnvelope) (VerificationResult, error)
}

type Metadata struct {
	KeyID        string     `json:"key_id"`
	SourceCommit string     `json:"source_commit,omitempty"`
	PolicyID     string     `json:"policy_id,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

type SignedEnvelope struct {
	Kind          string     `json:"kind"`
	KeyID         string     `json:"key_id"`
	Algorithm     string     `json:"algorithm"`
	PayloadType   string     `json:"payload_type"`
	Payload       []byte     `json:"payload"`
	PayloadSHA256 string     `json:"payload_sha256"`
	Signature     []byte     `json:"signature"`
	SignedAt      time.Time  `json:"signed_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	SourceCommit  string     `json:"source_commit,omitempty"`
	PolicyID      string     `json:"policy_id,omitempty"`
}

type VerificationResult struct {
	Valid         bool      `json:"valid"`
	KeyID         string    `json:"key_id"`
	PayloadSHA256 string    `json:"payload_sha256"`
	VerifiedAt    time.Time `json:"verified_at"`
	Error         string    `json:"error,omitempty"`
}

type DevLocalSigner struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Now        func() time.Time
}

func NewDevLocalSigner(keyID string) (*DevLocalSigner, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DevLocalSigner{KeyID: keyID, PrivateKey: privateKey, PublicKey: publicKey}, nil
}

func (s *DevLocalSigner) Sign(_ context.Context, payload []byte, meta Metadata) (SignedEnvelope, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize {
		return SignedEnvelope{}, fmt.Errorf("dev-local signer requires an Ed25519 private key")
	}
	keyID := meta.KeyID
	if keyID == "" {
		keyID = s.KeyID
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	payloadHash := sha256.Sum256(payload)
	signature := ed25519.Sign(s.PrivateKey, payload)
	return SignedEnvelope{
		Kind:          "SignedEnvelope",
		KeyID:         keyID,
		Algorithm:     "Ed25519",
		PayloadType:   "application/vnd.kernloom.artifact+json",
		Payload:       payload,
		PayloadSHA256: "sha256:" + hex.EncodeToString(payloadHash[:]),
		Signature:     signature,
		SignedAt:      now().UTC(),
		ExpiresAt:     meta.ExpiresAt,
		SourceCommit:  meta.SourceCommit,
		PolicyID:      meta.PolicyID,
	}, nil
}

func (s *DevLocalSigner) Verify(_ context.Context, envelope SignedEnvelope) (VerificationResult, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	payloadHash := sha256.Sum256(envelope.Payload)
	result := VerificationResult{
		KeyID:         envelope.KeyID,
		PayloadSHA256: "sha256:" + hex.EncodeToString(payloadHash[:]),
		VerifiedAt:    now().UTC(),
	}
	if envelope.Kind != "SignedEnvelope" {
		result.Error = "payload is not a signed envelope"
		return result, nil
	}
	if envelope.Algorithm != "Ed25519" {
		result.Error = fmt.Sprintf("unsupported signing algorithm %q", envelope.Algorithm)
		return result, nil
	}
	if envelope.KeyID == "" {
		result.Error = "signed envelope is missing key_id"
		return result, nil
	}
	if len(s.PublicKey) != ed25519.PublicKeySize {
		result.Error = "verifier requires an Ed25519 public key"
		return result, nil
	}
	if envelope.ExpiresAt != nil && !now().UTC().Before(envelope.ExpiresAt.UTC()) {
		result.Error = "signed envelope expired"
		return result, nil
	}
	if envelope.PayloadSHA256 != result.PayloadSHA256 {
		result.Error = "payload hash mismatch"
		return result, nil
	}
	if !ed25519.Verify(s.PublicKey, envelope.Payload, envelope.Signature) {
		result.Error = "signature verification failed"
		return result, nil
	}
	result.Valid = true
	return result, nil
}
