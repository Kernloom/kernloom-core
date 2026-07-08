// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authz

import (
	"errors"
	"fmt"

	"github.com/kernloom/kernloom-core/internal/api/authn"
)

var ErrForbidden = errors.New("forbidden")

const (
	RolePolicyAuthor        = "policy-author"
	RolePolicyReviewer      = "policy-reviewer"
	RoleSecurityOwner       = "security-owner"
	RolePlatformOwner       = "platform-owner"
	RoleAdapterOwner        = "adapter-owner"
	RoleRiskOwner           = "risk-owner"
	RoleConformanceReviewer = "conformance-reviewer"
	RoleOperator            = "operator"
	RoleReadOnlyViewer      = "read-only-viewer"
	RoleBreakGlassApprover  = "break-glass-approver"
	RoleKLIQService         = "kliq-service"
)

type Request struct {
	Action       string
	AllowedRoles []string
	Scope        authn.Scope
}

type Authorizer struct{}

func (Authorizer) Authorize(principal authn.Principal, req Request) error {
	if principal.Subject == "" {
		return ErrForbidden
	}
	if len(req.AllowedRoles) > 0 && !hasAnyRole(principal, req.AllowedRoles) {
		return fmt.Errorf("%w: role does not allow %s", ErrForbidden, req.Action)
	}
	if !scopeAllows(principal.Scope, req.Scope) {
		return fmt.Errorf("%w: scope does not allow %s", ErrForbidden, req.Action)
	}
	return nil
}

func hasAnyRole(principal authn.Principal, roles []string) bool {
	for _, role := range roles {
		if principal.HasRole(role) {
			return true
		}
	}
	return false
}

func scopeAllows(principal, requested authn.Scope) bool {
	return fieldAllows(principal.Org, requested.Org) &&
		fieldAllows(principal.Environment, requested.Environment) &&
		fieldAllows(principal.Stage, requested.Stage) &&
		fieldAllows(principal.PolicyType, requested.PolicyType) &&
		fieldAllows(principal.Resource, requested.Resource) &&
		fieldAllows(principal.Adapter, requested.Adapter) &&
		fieldAllows(principal.Repo, requested.Repo)
}

func fieldAllows(principalValue, requestedValue string) bool {
	if requestedValue == "" || principalValue == "" || principalValue == "*" {
		return true
	}
	return principalValue == requestedValue
}

func SimulationSubmitRoles() []string {
	return []string{
		RolePolicyAuthor,
		RolePolicyReviewer,
		RoleSecurityOwner,
		RolePlatformOwner,
		RoleOperator,
	}
}

func JobReadRoles() []string {
	return []string{
		RolePolicyAuthor,
		RolePolicyReviewer,
		RoleSecurityOwner,
		RolePlatformOwner,
		RoleAdapterOwner,
		RoleRiskOwner,
		RoleConformanceReviewer,
		RoleOperator,
		RoleReadOnlyViewer,
		RoleBreakGlassApprover,
	}
}

func KLIQManageRoles() []string {
	return []string{
		RoleSecurityOwner,
		RolePlatformOwner,
		RoleOperator,
	}
}

func KLIQReadRoles() []string {
	return []string{
		RoleSecurityOwner,
		RolePlatformOwner,
		RoleOperator,
		RoleReadOnlyViewer,
	}
}

func PolicyBuildApproveRoles() []string {
	return []string{
		RolePolicyReviewer,
		RoleSecurityOwner,
		RolePlatformOwner,
		RoleBreakGlassApprover,
	}
}

func ValidationSubmitRoles() []string {
	return []string{
		RolePolicyAuthor,
		RolePolicyReviewer,
		RoleSecurityOwner,
		RolePlatformOwner,
		RoleOperator,
	}
}
