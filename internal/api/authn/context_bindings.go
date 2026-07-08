// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ContextBinding struct {
	ID       string         `yaml:"id" json:"id"`
	Source   string         `yaml:"source" json:"source"`
	Issuer   string         `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	Audience string         `yaml:"audience,omitempty" json:"audience,omitempty"`
	Claim    string         `yaml:"claim" json:"claim"`
	Contains any            `yaml:"contains,omitempty" json:"contains,omitempty"`
	Equals   any            `yaml:"equals,omitempty" json:"equals,omitempty"`
	MapsTo   map[string]any `yaml:"maps_to" json:"maps_to"`
}

type contextBindingFile struct {
	ContextBindings []ContextBinding `yaml:"context_bindings"`
}

type ContextBindingVerifier struct {
	Inner        Verifier
	Bindings     []ContextBinding
	RequireMatch bool
}

func LoadContextBindings(path string) ([]ContextBinding, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file contextBindingFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if len(file.ContextBindings) == 0 {
		return nil, fmt.Errorf("%s: context_bindings must contain at least one binding", path)
	}
	for _, binding := range file.ContextBindings {
		if err := validateContextBinding(binding); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return file.ContextBindings, nil
}

func validateContextBinding(binding ContextBinding) error {
	if strings.TrimSpace(binding.ID) == "" {
		return fmt.Errorf("context binding requires id")
	}
	if strings.TrimSpace(binding.Source) == "" {
		return fmt.Errorf("context binding %q requires source", binding.ID)
	}
	if strings.TrimSpace(binding.Claim) == "" {
		return fmt.Errorf("context binding %q requires claim", binding.ID)
	}
	if binding.Contains == nil && binding.Equals == nil {
		return fmt.Errorf("context binding %q requires contains or equals", binding.ID)
	}
	if len(binding.MapsTo) == 0 {
		return fmt.Errorf("context binding %q requires maps_to", binding.ID)
	}
	return nil
}

func (v ContextBindingVerifier) Verify(ctx context.Context, token string) (Principal, error) {
	if v.Inner == nil {
		return Principal{}, ErrUnauthenticated
	}
	principal, err := v.Inner.Verify(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	matched := false
	for _, binding := range v.Bindings {
		if !contextBindingMatches(principal.Claims, binding) {
			continue
		}
		matched = true
		applyContextMapping(&principal, binding)
	}
	if v.RequireMatch && !matched {
		return Principal{}, fmt.Errorf("missing_context_binding")
	}
	return principal, nil
}

func contextBindingMatches(claims map[string]any, binding ContextBinding) bool {
	if len(claims) == 0 {
		return false
	}
	if binding.Issuer != "" {
		issuer, _ := claims["iss"].(string)
		if issuer != binding.Issuer {
			return false
		}
	}
	if binding.Audience != "" && !audienceContains(claims["aud"], binding.Audience) {
		return false
	}
	raw, ok := nestedClaim(claims, binding.Claim)
	if !ok {
		return false
	}
	if binding.Contains != nil && !claimContains(raw, binding.Contains) {
		return false
	}
	if binding.Equals != nil && !claimEquals(raw, binding.Equals) {
		return false
	}
	return true
}

func applyContextMapping(principal *Principal, binding ContextBinding) {
	if principal.Claims == nil {
		principal.Claims = map[string]any{}
	}
	contextClaims, _ := principal.Claims["kernloom_context"].(map[string]any)
	if contextClaims == nil {
		contextClaims = map[string]any{}
		principal.Claims["kernloom_context"] = contextClaims
	}
	for key, value := range binding.MapsTo {
		switch strings.TrimSpace(key) {
		case "subject.role":
			role, _ := value.(string)
			if role != "" && !hasRole(*principal, role) {
				principal.Roles = append(principal.Roles, role)
			}
		case "scope.org", "kernloom_scope.org":
			principal.Scope.Org = stringValue(value)
		case "scope.environment", "kernloom_scope.environment":
			principal.Scope.Environment = stringValue(value)
		case "scope.stage", "kernloom_scope.stage":
			principal.Scope.Stage = stringValue(value)
		case "scope.policy_type", "kernloom_scope.policy_type":
			principal.Scope.PolicyType = stringValue(value)
		case "scope.resource", "kernloom_scope.resource":
			principal.Scope.Resource = stringValue(value)
		case "scope.adapter", "kernloom_scope.adapter":
			principal.Scope.Adapter = stringValue(value)
		case "scope.repo", "kernloom_scope.repo":
			principal.Scope.Repo = stringValue(value)
		default:
			contextClaims[key] = value
		}
	}
}

func nestedClaim(claims map[string]any, path string) (any, bool) {
	parts := strings.Split(strings.TrimSpace(path), ".")
	var current any = claims
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func claimContains(raw any, expected any) bool {
	expectedText := stringValue(expected)
	switch value := raw.(type) {
	case string:
		if value == expectedText {
			return true
		}
		for _, field := range strings.Fields(value) {
			if field == expectedText {
				return true
			}
		}
	case []any:
		for _, item := range value {
			if stringValue(item) == expectedText {
				return true
			}
		}
	case []string:
		for _, item := range value {
			if item == expectedText {
				return true
			}
		}
	}
	return false
}

func claimEquals(raw any, expected any) bool {
	return stringValue(raw) == stringValue(expected)
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func hasRole(principal Principal, role string) bool {
	for _, existing := range principal.Roles {
		if existing == role {
			return true
		}
	}
	return false
}
