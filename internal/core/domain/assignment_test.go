// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package domain

import (
	"strings"
	"testing"
	"time"
)

func TestValidateKLIQAssignmentActivationAcceptsNewSignedAssignment(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	err := ValidateKLIQAssignmentActivation(validAssignment(now), validAssignmentContext(now))
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateKLIQAssignmentActivationRejectsUnsignedAssignment(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignment := validAssignment(now)
	assignment.SignatureValid = false
	err := ValidateKLIQAssignmentActivation(assignment, validAssignmentContext(now))
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature rejection, got %v", err)
	}
}

func TestValidateKLIQAssignmentActivationRejectsRollbackWithoutApproval(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignment := validAssignment(now)
	assignment.AssignmentVersion = 4
	ctx := validAssignmentContext(now)
	ctx.ActiveAssignmentVersion = 5
	err := ValidateKLIQAssignmentActivation(assignment, ctx)
	if err == nil || !strings.Contains(err.Error(), "approved signed rollback") {
		t.Fatalf("expected rollback rejection, got %v", err)
	}
}

func TestValidateKLIQAssignmentActivationAcceptsSignedApprovedRollback(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignment := validAssignment(now)
	assignment.AssignmentVersion = 4
	assignment.ApprovedRollback = true
	ctx := validAssignmentContext(now)
	ctx.ActiveAssignmentVersion = 5
	if err := ValidateKLIQAssignmentActivation(assignment, ctx); err != nil {
		t.Fatal(err)
	}
}

func TestValidateKLIQAssignmentActivationAcceptsSameVersionSameDigest(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignment := validAssignment(now)
	ctx := validAssignmentContext(now)
	ctx.ActiveAssignmentVersion = assignment.AssignmentVersion
	ctx.AssignmentDigest = "sha256:same"
	ctx.ActiveAssignmentDigest = "sha256:same"
	if err := ValidateKLIQAssignmentActivation(assignment, ctx); err != nil {
		t.Fatal(err)
	}
}

func TestValidateKLIQAssignmentActivationRejectsSameVersionDifferentDigest(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	assignment := validAssignment(now)
	ctx := validAssignmentContext(now)
	ctx.ActiveAssignmentVersion = assignment.AssignmentVersion
	ctx.AssignmentDigest = "sha256:new"
	ctx.ActiveAssignmentDigest = "sha256:old"
	err := ValidateKLIQAssignmentActivation(assignment, ctx)
	if err == nil || !strings.Contains(err.Error(), "not an approved signed rollback") {
		t.Fatalf("expected same-version digest mismatch rejection, got %v", err)
	}
}

func validAssignment(now time.Time) KLIQAssignment {
	return KLIQAssignment{
		AssignmentID:      "assignment.kliq.prod.node-17",
		AssignmentVersion: 6,
		KLIQID:            "kliq.node-17",
		Environment:       "prod",
		Stage:             "prod",
		Scope:             "node-17",
		SourceCommit:      "abc123",
		TrustKeyID:        "dev-local",
		CreatedAt:         now,
		ExpiresAt:         now.Add(time.Hour),
		SignatureValid:    true,
	}
}

func validAssignmentContext(now time.Time) KLIQAssignmentActivationContext {
	return KLIQAssignmentActivationContext{
		KLIQID:                  "kliq.node-17",
		Environment:             "prod",
		Stage:                   "prod",
		Scope:                   "node-17",
		TrustKeyID:              "dev-local",
		Now:                     now,
		ActiveAssignmentVersion: 5,
	}
}
