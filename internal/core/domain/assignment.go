// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package domain

import (
	"fmt"
	"time"
)

type KLIQAssignment struct {
	AssignmentID           string
	AssignmentVersion      int64
	KLIQID                 string
	Environment            string
	Stage                  string
	Scope                  string
	SourceCommit           string
	TrustKeyID             string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ApprovedRollback       bool
	SignatureValid         bool
	ManifestSigned         bool
	ManifestDigest         string
	ManifestSignatureValid bool
}

type KLIQAssignmentActivationContext struct {
	KLIQID                  string
	Environment             string
	Stage                   string
	Scope                   string
	TrustKeyID              string
	Now                     time.Time
	ActiveAssignmentVersion int64
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
	if assignment.ExpiresAt.IsZero() {
		return fmt.Errorf("kliq assignment %q requires expires_at", assignment.AssignmentID)
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
	if assignment.AssignmentVersion < ctx.ActiveAssignmentVersion && assignment.ApprovedRollback && assignment.SignatureValid {
		return nil
	}
	return fmt.Errorf("kliq assignment %q is not newer than active assignment and is not an approved signed rollback", assignment.AssignmentID)
}
