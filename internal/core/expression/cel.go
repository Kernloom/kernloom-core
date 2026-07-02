// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package expression

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

type CELValidator struct {
	env *cel.Env
}

func NewCELValidator() (*CELValidator, error) {
	env, err := cel.NewEnv(
		cel.Variable("device", cel.DynType),
		cel.Variable("identity", cel.DynType),
		cel.Variable("access_risk", cel.DynType),
		cel.Variable("runtime_action", cel.DynType),
		cel.Variable("bundle", cel.DynType),
		cel.Variable("grant", cel.DynType),
		cel.Variable("baseline", cel.DynType),
		cel.Variable("network", cel.DynType),
		cel.Variable("relationship", cel.DynType),
		cel.Variable("runtime_anomaly", cel.DynType),
		cel.Variable("score", cel.IntType),
	)
	if err != nil {
		return nil, err
	}
	return &CELValidator{env: env}, nil
}

func (v *CELValidator) Validate(expr string) error {
	if expr == "" {
		return nil
	}
	_, issues := v.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("invalid CEL %q: %w", expr, issues.Err())
	}
	return nil
}
