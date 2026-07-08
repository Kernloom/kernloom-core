// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

type ManagedAssignmentSource struct {
	BaseURL                 string
	BearerToken             string
	KLIQID                  string
	Environment             string
	Stage                   string
	Scope                   string
	TrustKeyID              string
	TrustBundle             domain.TrustBundle
	ActiveAssignmentVersion int64
	ActiveAssignmentDigest  string
	Verifier                signing.Verifier
	HTTPClient              *http.Client

	assignment       domain.KLIQAssignment
	assignmentDigest string
}

type ManagedAssignmentActivation struct {
	KLIQID            string
	AssignmentID      string
	AssignmentVersion int64
	SourceCommit      string
	AssignmentDigest  string
	ExpiresAt         time.Time
}

func (s *ManagedAssignmentSource) AssignmentArtifacts() []domain.KLIQAssignedArtifact {
	return append([]domain.KLIQAssignedArtifact(nil), s.assignment.Artifacts...)
}

func (s *ManagedAssignmentSource) SetActiveAssignment(version int64, digest string) {
	s.ActiveAssignmentVersion = version
	s.ActiveAssignmentDigest = digest
}

func (s *ManagedAssignmentSource) AssignmentActivation() (ManagedAssignmentActivation, bool) {
	if s.assignment.AssignmentID == "" || s.assignmentDigest == "" {
		return ManagedAssignmentActivation{}, false
	}
	return ManagedAssignmentActivation{
		KLIQID:            s.assignment.KLIQID,
		AssignmentID:      s.assignment.AssignmentID,
		AssignmentVersion: s.assignment.AssignmentVersion,
		SourceCommit:      s.assignment.SourceCommit,
		AssignmentDigest:  s.assignmentDigest,
		ExpiresAt:         s.assignment.ExpiresAt,
	}, true
}

func (s *ManagedAssignmentSource) Load(ctx context.Context) ([]byte, string, error) {
	if strings.TrimSpace(s.BaseURL) == "" {
		return nil, "", fmt.Errorf("managed assignment source requires base url")
	}
	if strings.TrimSpace(s.KLIQID) == "" {
		return nil, "", fmt.Errorf("managed assignment source requires kliq id")
	}
	if s.Verifier == nil {
		return nil, "", fmt.Errorf("managed assignment source requires verifier")
	}
	url := strings.TrimRight(s.BaseURL, "/") + "/v1/kliq/assignments/" + s.KLIQID + "/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	if s.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.BearerToken)
	}
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", fmt.Errorf("assignment api returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var envelope signing.SignedEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, "", err
	}
	assignment, err := s.verifyAssignment(ctx, envelope)
	if err != nil {
		return nil, "", err
	}
	s.assignment = assignment
	s.assignmentDigest = envelope.PayloadSHA256
	artifact, ok := domain.RuntimeBundleArtifact(assignment)
	if !ok {
		return nil, "", fmt.Errorf("assignment %q does not include runtime_bundle artifact", assignment.AssignmentID)
	}
	return append([]byte(nil), artifact.Envelope...), url + "#" + assignment.AssignmentID, nil
}

func (s *ManagedAssignmentSource) verifyAssignment(ctx context.Context, envelope signing.SignedEnvelope) (domain.KLIQAssignment, error) {
	result, err := s.Verifier.Verify(ctx, envelope)
	if err != nil {
		return domain.KLIQAssignment{}, err
	}
	if !result.Valid {
		return domain.KLIQAssignment{}, fmt.Errorf("assignment signature invalid: %s", result.Error)
	}
	var assignment domain.KLIQAssignment
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	if err := decoder.Decode(&assignment); err != nil {
		return domain.KLIQAssignment{}, err
	}
	if assignment.TrustKeyID != "" && assignment.TrustKeyID != result.KeyID {
		return domain.KLIQAssignment{}, fmt.Errorf("assignment trust key %q does not match envelope key %q", assignment.TrustKeyID, result.KeyID)
	}
	if err := s.validateTrustBundle(assignment, result); err != nil {
		return domain.KLIQAssignment{}, err
	}
	assignment.SignatureValid = true
	if err := domain.ValidateAssignedArtifactDigests(assignment); err != nil {
		return domain.KLIQAssignment{}, err
	}
	if err := s.verifyAssignedArtifacts(ctx, assignment); err != nil {
		return domain.KLIQAssignment{}, err
	}
	if err := domain.ValidateKLIQAssignmentActivation(assignment, domain.KLIQAssignmentActivationContext{
		KLIQID:                  s.KLIQID,
		Environment:             s.Environment,
		Stage:                   s.Stage,
		Scope:                   s.Scope,
		TrustKeyID:              s.TrustKeyID,
		AssignmentDigest:        result.PayloadSHA256,
		Now:                     result.VerifiedAt,
		ActiveAssignmentVersion: s.ActiveAssignmentVersion,
		ActiveAssignmentDigest:  s.ActiveAssignmentDigest,
	}); err != nil {
		return domain.KLIQAssignment{}, err
	}
	return assignment, nil
}

func (s *ManagedAssignmentSource) verifyAssignedArtifacts(ctx context.Context, assignment domain.KLIQAssignment) error {
	artifactVerifier := s.Verifier
	artifactTrustKeyID := ""
	for _, artifact := range assignment.Artifacts {
		if artifact.ArtifactType != "trust_bundle" {
			continue
		}
		envelope, result, err := s.verifyAssignedArtifactEnvelope(ctx, assignment, artifact, s.Verifier)
		if err != nil {
			return err
		}
		var bundle domain.TrustBundle
		if err := json.Unmarshal(envelope.Payload, &bundle); err != nil {
			return fmt.Errorf("assignment %q artifact %q invalid trust bundle payload: %w", assignment.AssignmentID, artifact.ArtifactID, err)
		}
		if bundle.Purpose != "artifact_verification" {
			continue
		}
		if artifactTrustKeyID != "" {
			return fmt.Errorf("assignment %q contains more than one artifact_verification trust bundle", assignment.AssignmentID)
		}
		verifier, err := artifactVerifierFromTrustBundle(bundle, result.VerifiedAt)
		if err != nil {
			return fmt.Errorf("assignment %q artifact %q invalid artifact verification trust bundle: %w", assignment.AssignmentID, artifact.ArtifactID, err)
		}
		artifactVerifier = verifier
		artifactTrustKeyID = bundle.KeyID
	}
	for _, artifact := range assignment.Artifacts {
		if artifact.ArtifactType == "trust_bundle" {
			continue
		}
		if _, _, err := s.verifyAssignedArtifactEnvelope(ctx, assignment, artifact, artifactVerifier); err != nil {
			if artifactTrustKeyID != "" {
				return fmt.Errorf("%w; expected artifact_verification key %q", err, artifactTrustKeyID)
			}
			return err
		}
	}
	return nil
}

func (s *ManagedAssignmentSource) verifyAssignedArtifactEnvelope(ctx context.Context, assignment domain.KLIQAssignment, artifact domain.KLIQAssignedArtifact, verifier signing.Verifier) (signing.SignedEnvelope, signing.VerificationResult, error) {
	if !domain.SupportedAssignmentArtifactType(artifact.ArtifactType) {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, fmt.Errorf("assignment %q contains unsupported artifact type %q", assignment.AssignmentID, artifact.ArtifactType)
	}
	var envelope signing.SignedEnvelope
	if err := json.Unmarshal(artifact.Envelope, &envelope); err != nil {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, fmt.Errorf("assignment %q artifact %q is not a signed envelope: %w", assignment.AssignmentID, artifact.ArtifactID, err)
	}
	if envelope.Kind != "SignedEnvelope" {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, fmt.Errorf("assignment %q artifact %q is not a signed envelope", assignment.AssignmentID, artifact.ArtifactID)
	}
	result, err := verifier.Verify(ctx, envelope)
	if err != nil {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, err
	}
	if !result.Valid {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, fmt.Errorf("assignment %q artifact %q signature invalid: %s", assignment.AssignmentID, artifact.ArtifactID, result.Error)
	}
	if envelope.SourceCommit != "" && assignment.SourceCommit != "" && envelope.SourceCommit != assignment.SourceCommit {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, fmt.Errorf("assignment %q artifact %q source_commit mismatch", assignment.AssignmentID, artifact.ArtifactID)
	}
	if err := validateAssignedArtifactPayloadType(artifact.ArtifactType, envelope.Payload); err != nil {
		return signing.SignedEnvelope{}, signing.VerificationResult{}, fmt.Errorf("assignment %q artifact %q invalid payload: %w", assignment.AssignmentID, artifact.ArtifactID, err)
	}
	return envelope, result, nil
}

func artifactVerifierFromTrustBundle(bundle domain.TrustBundle, verifiedAt time.Time) (signing.Verifier, error) {
	if bundle.KeyID == "" || bundle.PublicKey == "" {
		return nil, fmt.Errorf("trust bundle requires key_id and public_key")
	}
	if bundle.Purpose != "artifact_verification" {
		return nil, fmt.Errorf("trust bundle %q has purpose %q, expected artifact_verification", bundle.KeyID, bundle.Purpose)
	}
	switch bundle.Status {
	case "active", "previous":
	default:
		return nil, fmt.Errorf("trust bundle %q is %q", bundle.KeyID, bundle.Status)
	}
	if !bundle.ExpiresAt.IsZero() && !bundle.ExpiresAt.After(verifiedAt.UTC()) {
		return nil, fmt.Errorf("trust bundle %q is expired", bundle.KeyID)
	}
	publicKey, err := decodeTrustBundlePublicKey(bundle.PublicKey)
	if err != nil {
		return nil, err
	}
	verifier, err := signing.NewEd25519Verifier(bundle.KeyID, publicKey)
	if err != nil {
		return nil, err
	}
	verifier.Now = func() time.Time { return verifiedAt.UTC() }
	return verifier, nil
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

func validateAssignedArtifactPayloadType(artifactType string, payload []byte) error {
	var header struct {
		Kind     string `json:"kind"`
		Metadata struct {
			ArtifactType string `json:"artifact_type"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return err
	}
	expectedKind := expectedArtifactKind(artifactType)
	if expectedKind != "" && header.Kind != expectedKind {
		return fmt.Errorf("kind %q does not match artifact type %q", header.Kind, artifactType)
	}
	if header.Metadata.ArtifactType != "" && header.Metadata.ArtifactType != artifactType {
		return fmt.Errorf("metadata artifact_type %q does not match %q", header.Metadata.ArtifactType, artifactType)
	}
	return nil
}

func expectedArtifactKind(artifactType string) string {
	switch artifactType {
	case "runtime_bundle":
		return "RuntimeBundle"
	case "adapter_manifest":
		return "AdapterManifest"
	case "context_route_pack":
		return "ContextRoutePack"
	case "conformance_expectation":
		return "ConformanceExpectation"
	case "adapter_assignment":
		return "AdapterAssignment"
	case "trust_bundle":
		return ""
	case "management_profile":
		return ""
	case "fallback_profile":
		return ""
	default:
		return ""
	}
}

func (s *ManagedAssignmentSource) validateTrustBundle(assignment domain.KLIQAssignment, result signing.VerificationResult) error {
	if s.TrustBundle.KeyID == "" {
		return nil
	}
	if s.TrustBundle.KeyID != assignment.TrustBundleRef {
		return fmt.Errorf("assignment trust bundle %q does not match local trust bundle %q", assignment.TrustBundleRef, s.TrustBundle.KeyID)
	}
	if s.TrustBundle.KeyID != result.KeyID {
		return fmt.Errorf("assignment signing key %q does not match trust bundle key %q", result.KeyID, s.TrustBundle.KeyID)
	}
	if s.TrustBundle.Purpose != "assignment_verification" {
		return fmt.Errorf("trust bundle %q has purpose %q, expected assignment_verification", s.TrustBundle.KeyID, s.TrustBundle.Purpose)
	}
	if s.TrustBundle.Status != "active" {
		return fmt.Errorf("trust bundle %q is %q", s.TrustBundle.KeyID, s.TrustBundle.Status)
	}
	if !s.TrustBundle.ExpiresAt.IsZero() && !s.TrustBundle.ExpiresAt.After(result.VerifiedAt) {
		return fmt.Errorf("trust bundle %q is expired", s.TrustBundle.KeyID)
	}
	return nil
}
