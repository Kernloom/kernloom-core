// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kernloom/kernloom-core/internal/core/version"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "compile" {
		compile(os.Args[2:])
		return
	}
	fmt.Println(version.Binary("forge"))
	fmt.Println("usage: forge compile [--policy-repo path] [--policy-file path] [--core-registry path] [--enterprise-registry path] [--output-dir path]")
}

func compile(args []string) {
	fs := flag.NewFlagSet("forge compile", flag.ExitOnError)
	opts := compiler.Options{}
	fs.StringVar(&opts.PolicyRepo, "policy-repo", "../enterprise-kernloom-policies", "path to enterprise policy repository")
	fs.StringVar(&opts.PolicyFile, "policy-file", "", "optional single KNI intent file to compile")
	fs.StringVar(&opts.CoreRegistry, "core-registry", "../kernloom-core-registry", "path to core registry repository")
	fs.StringVar(&opts.EnterpriseRegistry, "enterprise-registry", "../enterprise-kernloom-registry", "path to enterprise registry repository")
	fs.StringVar(&opts.OutputDir, "output-dir", "", "output directory; defaults to policy repo generated directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results, err := compiler.Compile(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, result := range results {
		fmt.Printf("%s\n", result.PolicyID)
		fmt.Printf("  review: %s\n", result.ReviewPath)
		fmt.Printf("  resolved: %s\n", result.ResolvedPath)
		fmt.Printf("  manifest: %s\n", result.ManifestPath)
	}
}
