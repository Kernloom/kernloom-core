// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authz

import (
	"errors"
	"testing"

	"github.com/kernloom/kernloom-core/internal/api/authn"
)

func TestAuthorizerAllowsMatchingRoleAndScope(t *testing.T) {
	principal := authn.Principal{
		Subject: "alice",
		Roles:   []string{RolePolicyAuthor},
		Scope:   authn.Scope{Org: "acme", Environment: "prod", Stage: "prod"},
	}
	err := (Authorizer{}).Authorize(principal, Request{
		Action:       "simulation.submit",
		AllowedRoles: SimulationSubmitRoles(),
		Scope:        authn.Scope{Org: "acme", Environment: "prod", Stage: "prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizerRejectsWrongRole(t *testing.T) {
	principal := authn.Principal{
		Subject: "viewer",
		Roles:   []string{RoleReadOnlyViewer},
	}
	err := (Authorizer{}).Authorize(principal, Request{
		Action:       "simulation.submit",
		AllowedRoles: SimulationSubmitRoles(),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestAuthorizerRejectsMismatchedScope(t *testing.T) {
	principal := authn.Principal{
		Subject: "alice",
		Roles:   []string{RolePolicyAuthor},
		Scope:   authn.Scope{Org: "acme", Stage: "dev"},
	}
	err := (Authorizer{}).Authorize(principal, Request{
		Action:       "simulation.submit",
		AllowedRoles: SimulationSubmitRoles(),
		Scope:        authn.Scope{Org: "acme", Stage: "prod"},
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}
