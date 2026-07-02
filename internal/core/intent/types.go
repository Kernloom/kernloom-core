// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package intent

type Card struct {
	ID          string
	SourcePath  string
	Version     string
	Owner       string
	Type        string
	Target      string
	Stage       string
	Profile     string
	RiskRecipe  string
	Rules       []Rule
	Risk        []RiskBehavior
	Prohibit    []string
	Runtime     Runtime
	Simulations []Simulation
}

type Rule struct {
	Name     string
	Effect   string
	Subject  string
	Action   string
	Resource string
	OnlyWhen []string
}

type RiskBehavior struct {
	RiskType string
	Tier     string
	Effect   string
}

type Runtime struct {
	Allowed  bool
	Actions  []string
	MaxTTL   string
	MaxScope string
}

type Simulation struct {
	Name         string
	Given        []string
	ExpectEffect string
}
