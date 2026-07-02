// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/core/version"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "registry" && os.Args[2] == "validate" {
		registryValidate(os.Args[3:])
		return
	}
	fmt.Println(version.Binary("kernloomctl"))
	fmt.Println("usage: kernloomctl registry validate [--core-registry path] [--enterprise-registry path]")
}

func registryValidate(args []string) {
	fs := flag.NewFlagSet("kernloomctl registry validate", flag.ExitOnError)
	coreRegistry := fs.String("core-registry", "../kernloom-core-registry", "path to core registry")
	enterpriseRegistry := fs.String("enterprise-registry", "", "optional path to enterprise registry")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	catalog, err := registry.Load(*coreRegistry, *enterpriseRegistry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("RegistryValidationReport: ok values=%d profiles=%d risk_recipes=%d guardrails=%d\n", len(catalog.Values), len(catalog.Profiles), len(catalog.RiskRecipes), len(catalog.Guardrails))
}
