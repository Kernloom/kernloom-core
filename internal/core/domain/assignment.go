// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type KLIQEnrollmentToken struct {
	TokenID       string    `json:"token_id"`
	TokenSHA256   string    `json:"token_sha256"`
	Environment   string    `json:"environment"`
	Stage         string    `json:"stage"`
	Scope         string    `json:"scope"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	UsedAt        time.Time `json:"used_at,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
}

type KLIQRegistration struct {
	RegistrationID    string                `json:"registration_id"`
	KLIQID            string                `json:"kliq_id"`
	NodeID            string                `json:"node_id"`
	Environment       string                `json:"environment"`
	Stage             string                `json:"stage"`
	Scope             string                `json:"scope"`
	Version           string                `json:"version"`
	AdapterInventory  []string              `json:"adapter_inventory,omitempty"`
	Capabilities      []string              `json:"capabilities,omitempty"`
	AttestationState  string                `json:"attestation_state,omitempty"`
	Identity          KLIQIdentity          `json:"identity"`
	ManagementProfile KLIQManagementProfile `json:"management_profile"`
	Status            string                `json:"status"`
	RegisteredAt      time.Time             `json:"registered_at"`
	RevokedAt         time.Time             `json:"revoked_at,omitempty"`
	RevokedReason     string                `json:"revoked_reason,omitempty"`
}

type KLIQIdentity struct {
	IdentityID    string    `json:"identity_id"`
	KLIQID        string    `json:"kliq_id"`
	NodeID        string    `json:"node_id"`
	Environment   string    `json:"environment"`
	Stage         string    `json:"stage"`
	Scope         string    `json:"scope"`
	TrustKeyID    string    `json:"trust_key_id"`
	PublicKeyPEM  string    `json:"public_key_pem"`
	CSRPEM        string    `json:"csr_pem,omitempty"`
	Status        string    `json:"status"`
	IssuedAt      time.Time `json:"issued_at"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
}

type KLIQManagementProfile struct {
	ProfileID        string `json:"profile_id"`
	Mode             string `json:"mode"`
	PollInterval     string `json:"poll_interval"`
	StatusEndpoint   string `json:"status_endpoint,omitempty"`
	AssignmentSource string `json:"assignment_source,omitempty"`
}

type KLIQAssignment struct {
	AssignmentID           string                 `json:"assignment_id"`
	AssignmentVersion      int64                  `json:"assignment_version"`
	KLIQID                 string                 `json:"kliq_id"`
	Environment            string                 `json:"environment"`
	Stage                  string                 `json:"stage"`
	Scope                  string                 `json:"scope"`
	SourceCommit           string                 `json:"source_commit"`
	TrustKeyID             string                 `json:"trust_key_id"`
	TrustBundleRef         string                 `json:"trust_bundle_ref"`
	CreatedAt              time.Time              `json:"created_at"`
	ExpiresAt              time.Time              `json:"expires_at"`
	ApprovedRollback       bool                   `json:"approved_rollback"`
	Artifacts              []KLIQAssignedArtifact `json:"artifacts,omitempty"`
	Status                 string                 `json:"status,omitempty"`
	RevokedAt              time.Time              `json:"revoked_at,omitempty"`
	RevokedReason          string                 `json:"revoked_reason,omitempty"`
	SignatureValid         bool                   `json:"signature_valid,omitempty"`
	ManifestSigned         bool                   `json:"manifest_signed,omitempty"`
	ManifestDigest         string                 `json:"manifest_digest,omitempty"`
	ManifestSignatureValid bool                   `json:"manifest_signature_valid,omitempty"`
}

type KLIQAssignedArtifact struct {
	ArtifactType string          `json:"artifact_type"`
	ArtifactID   string          `json:"artifact_id"`
	ArtifactRef  string          `json:"artifact_ref,omitempty"`
	SHA256       string          `json:"sha256"`
	Envelope     json.RawMessage `json:"envelope"`
}

type AssignmentManifest struct {
	Kind              string           `json:"kind"`
	AssignmentID      string           `json:"assignment_id"`
	AssignmentVersion int64            `json:"assignment_version"`
	KLIQID            string           `json:"kliq_id"`
	Environment       string           `json:"environment"`
	Stage             string           `json:"stage"`
	Scope             string           `json:"scope"`
	SourceCommit      string           `json:"source_commit"`
	Artifacts         []ArtifactDigest `json:"artifacts"`
	TrustBundleRef    string           `json:"trust_bundle_ref"`
	CreatedAt         time.Time        `json:"created_at"`
	ExpiresAt         time.Time        `json:"expires_at"`
	ApprovedRollback  bool             `json:"approved_rollback"`
}

type ArtifactDigest struct {
	ArtifactType string `json:"artifact_type"`
	ArtifactID   string `json:"artifact_id"`
	ArtifactRef  string `json:"artifact_ref,omitempty"`
	SHA256       string `json:"sha256"`
}

type TrustBundle struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	Purpose   string    `json:"purpose"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	Issuer    string    `json:"issuer"`
}

type KLIQRevocation struct {
	RevocationID string    `json:"revocation_id"`
	TargetType   string    `json:"target_type"`
	TargetID     string    `json:"target_id"`
	Reason       string    `json:"reason"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by,omitempty"`
}

type ManagementAuditEvent struct {
	EventID     string         `json:"event_id"`
	EventType   string         `json:"event_type"`
	Actor       string         `json:"actor,omitempty"`
	TargetType  string         `json:"target_type"`
	TargetID    string         `json:"target_id"`
	KLIQID      string         `json:"kliq_id,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Stage       string         `json:"stage,omitempty"`
	Scope       string         `json:"scope,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

type KLIQHeartbeat struct {
	KLIQID            string    `json:"kliq_id"`
	Environment       string    `json:"environment"`
	Stage             string    `json:"stage"`
	Scope             string    `json:"scope"`
	Version           string    `json:"version,omitempty"`
	AssignmentVersion int64     `json:"assignment_version"`
	Status            string    `json:"status"`
	Findings          []string  `json:"findings,omitempty"`
	ReportedAt        time.Time `json:"reported_at"`
}

type KLIQStatusReport struct {
	KLIQID            string    `json:"kliq_id"`
	Environment       string    `json:"environment"`
	Stage             string    `json:"stage"`
	Scope             string    `json:"scope"`
	AssignmentVersion int64     `json:"assignment_version"`
	Status            string    `json:"status"`
	Findings          []string  `json:"findings,omitempty"`
	RuntimeActions    int       `json:"runtime_actions"`
	PendingAudits     int       `json:"pending_audits"`
	ReportedAt        time.Time `json:"reported_at"`
}

type KLIQUpdatePlan struct {
	KLIQID             string   `json:"kliq_id"`
	CurrentVersion     int64    `json:"current_version"`
	LatestVersion      int64    `json:"latest_version"`
	UpdateAvailable    bool     `json:"update_available"`
	AssignmentID       string   `json:"assignment_id,omitempty"`
	AssignmentEnvelope any      `json:"assignment_envelope,omitempty"`
	Findings           []string `json:"findings,omitempty"`
}

type KLIQAssignmentActivationContext struct {
	KLIQID                  string
	Environment             string
	Stage                   string
	Scope                   string
	TrustKeyID              string
	AssignmentDigest        string
	Now                     time.Time
	ActiveAssignmentVersion int64
	ActiveAssignmentDigest  string
}

func ValidateKLIQAssignmentActivation(assignment KLIQAssignment, ctx KLIQAssignmentActivationContext) error {
	if assignment.AssignmentID == "" {
		return fmt.Errorf("kliq assignment id is required")
	}
	if assignment.AssignmentVersion <= 0 {
		return fmt.Errorf("kliq assignment %q requires positive assignment_version", assignment.AssignmentID)
	}
	if assignment.SourceCommit == "" {
		return fmt.Errorf("kliq assignment %q requires source_commit", assignment.AssignmentID)
	}
	if assignment.TrustKeyID == "" {
		return fmt.Errorf("kliq assignment %q requires trust key", assignment.AssignmentID)
	}
	if assignment.TrustBundleRef == "" {
		return fmt.Errorf("kliq assignment %q requires trust_bundle_ref", assignment.AssignmentID)
	}
	if assignment.ExpiresAt.IsZero() {
		return fmt.Errorf("kliq assignment %q requires expires_at", assignment.AssignmentID)
	}
	if assignment.Status == "revoked" || !assignment.RevokedAt.IsZero() {
		return fmt.Errorf("kliq assignment %q is revoked", assignment.AssignmentID)
	}
	if !assignment.SignatureValid && !(assignment.ManifestSigned && assignment.ManifestSignatureValid) {
		return fmt.Errorf("kliq assignment %q requires valid assignment or manifest signature", assignment.AssignmentID)
	}
	if assignment.KLIQID != ctx.KLIQID {
		return fmt.Errorf("kliq assignment %q targets kliq_id %q, local is %q", assignment.AssignmentID, assignment.KLIQID, ctx.KLIQID)
	}
	if assignment.Environment != ctx.Environment {
		return fmt.Errorf("kliq assignment %q targets environment %q, local is %q", assignment.AssignmentID, assignment.Environment, ctx.Environment)
	}
	if assignment.Stage != ctx.Stage {
		return fmt.Errorf("kliq assignment %q targets stage %q, local is %q", assignment.AssignmentID, assignment.Stage, ctx.Stage)
	}
	if assignment.Scope != ctx.Scope {
		return fmt.Errorf("kliq assignment %q targets scope %q, local is %q", assignment.AssignmentID, assignment.Scope, ctx.Scope)
	}
	if assignment.TrustKeyID != ctx.TrustKeyID {
		return fmt.Errorf("kliq assignment %q trust key %q does not match local trust key %q", assignment.AssignmentID, assignment.TrustKeyID, ctx.TrustKeyID)
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !assignment.ExpiresAt.After(now.UTC()) {
		return fmt.Errorf("kliq assignment %q is expired", assignment.AssignmentID)
	}
	if assignment.AssignmentVersion > ctx.ActiveAssignmentVersion {
		return nil
	}
	if assignment.AssignmentVersion == ctx.ActiveAssignmentVersion &&
		ctx.ActiveAssignmentVersion > 0 &&
		ctx.AssignmentDigest != "" &&
		ctx.AssignmentDigest == ctx.ActiveAssignmentDigest {
		return nil
	}
	if assignment.AssignmentVersion < ctx.ActiveAssignmentVersion && assignment.ApprovedRollback && assignment.SignatureValid {
		return nil
	}
	return fmt.Errorf("kliq assignment %q is not newer than active assignment and is not an approved signed rollback", assignment.AssignmentID)
}

func RuntimeBundleArtifact(assignment KLIQAssignment) (KLIQAssignedArtifact, bool) {
	for _, artifact := range assignment.Artifacts {
		if artifact.ArtifactType == "runtime_bundle" {
			return artifact, true
		}
	}
	return KLIQAssignedArtifact{}, false
}

func ValidateAssignedArtifactDigests(assignment KLIQAssignment) error {
	for _, artifact := range assignment.Artifacts {
		if artifact.ArtifactType == "" {
			return fmt.Errorf("kliq assignment %q contains artifact without artifact_type", assignment.AssignmentID)
		}
		if len(artifact.Envelope) == 0 {
			return fmt.Errorf("kliq assignment %q artifact %q has no envelope", assignment.AssignmentID, artifact.ArtifactID)
		}
		if artifact.SHA256 == "" {
			return fmt.Errorf("kliq assignment %q artifact %q has no sha256 digest", assignment.AssignmentID, artifact.ArtifactID)
		}
		if artifact.SHA256 != SHA256JSON(artifact.Envelope) {
			return fmt.Errorf("kliq assignment %q artifact %q digest mismatch", assignment.AssignmentID, artifact.ArtifactID)
		}
	}
	return nil
}

func SHA256JSON(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func AssignmentManifestFor(assignment KLIQAssignment) AssignmentManifest {
	manifest := AssignmentManifest{
		Kind:              "AssignmentManifest",
		AssignmentID:      assignment.AssignmentID,
		AssignmentVersion: assignment.AssignmentVersion,
		KLIQID:            assignment.KLIQID,
		Environment:       assignment.Environment,
		Stage:             assignment.Stage,
		Scope:             assignment.Scope,
		SourceCommit:      assignment.SourceCommit,
		TrustBundleRef:    assignment.TrustBundleRef,
		CreatedAt:         assignment.CreatedAt,
		ExpiresAt:         assignment.ExpiresAt,
		ApprovedRollback:  assignment.ApprovedRollback,
	}
	for _, artifact := range assignment.Artifacts {
		manifest.Artifacts = append(manifest.Artifacts, ArtifactDigest{
			ArtifactType: artifact.ArtifactType,
			ArtifactID:   artifact.ArtifactID,
			ArtifactRef:  artifact.ArtifactRef,
			SHA256:       artifact.SHA256,
		})
	}
	return manifest
}
