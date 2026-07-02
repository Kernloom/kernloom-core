// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import "context"

type Scope struct {
	Org         string `json:"org,omitempty"`
	Environment string `json:"environment,omitempty"`
	Stage       string `json:"stage,omitempty"`
	PolicyType  string `json:"policy_type,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Adapter     string `json:"adapter,omitempty"`
	Repo        string `json:"repo,omitempty"`
}

type Principal struct {
	Subject string         `json:"subject"`
	Roles   []string       `json:"roles"`
	Scope   Scope          `json:"scope"`
	Claims  map[string]any `json:"claims,omitempty"`
}

func (p Principal) HasRole(role string) bool {
	for _, candidate := range p.Roles {
		if candidate == role {
			return true
		}
	}
	return false
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok
}
