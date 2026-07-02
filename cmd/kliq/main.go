// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/core/version"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify-bundle" {
		verifyBundle(os.Args[2:])
		return
	}
	fmt.Println(version.Binary("kliq"))
	fmt.Println("usage: kliq verify-bundle --bundle path --key path")
}

func verifyBundle(args []string) {
	fs := flag.NewFlagSet("kliq verify-bundle", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "path to signed RuntimeBundle envelope")
	keyPath := fs.String("key", "", "path to dev-local Ed25519 key file")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *bundlePath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "kliq verify-bundle requires --bundle and --key")
		os.Exit(2)
	}
	verifier, err := signing.LoadDevLocalVerifier(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result, err := kliqbundle.LoadSignedRuntimeBundle(context.Background(), *bundlePath, verifier)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("runtime bundle verified")
	fmt.Printf("  policy_id: %s\n", result.Bundle.Metadata.PolicyID)
	fmt.Printf("  key_id: %s\n", result.Envelope.KeyID)
	fmt.Printf("  payload_sha256: %s\n", result.Result.PayloadSHA256)
	if result.Envelope.ExpiresAt != nil {
		fmt.Printf("  expires_at: %s\n", result.Envelope.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	}
}
