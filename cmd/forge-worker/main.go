// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/kernloom/kernloom-core/internal/core/version"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "run-once" {
		runOnce(os.Args[2:])
		return
	}
	fmt.Println(version.Binary("forge-worker"))
	fmt.Println("usage: forge-worker run-once [--queue redis|memory] [--redis-addr 127.0.0.1:6379] [--core-registry path] [--enterprise-registry path]")
}

func runOnce(args []string) {
	fs := flag.NewFlagSet("forge-worker run-once", flag.ExitOnError)
	queueKind := fs.String("queue", "redis", "job queue backend: redis or memory")
	redisAddr := fs.String("redis-addr", "127.0.0.1:6379", "Redis address")
	defaults := compiler.Options{}
	fs.StringVar(&defaults.PolicyRepo, "policy-repo", "../enterprise-kernloom-policies", "default policy repository")
	fs.StringVar(&defaults.CoreRegistry, "core-registry", "../kernloom-core-registry", "default core registry repository")
	fs.StringVar(&defaults.EnterpriseRegistry, "enterprise-registry", "../enterprise-kernloom-registry", "default enterprise registry repository")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := jobStore(*queueKind, *redisAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	job, err := (jobs.Runner{Store: store, Defaults: defaults}).RunOnce(context.Background())
	if errors.Is(err, jobs.ErrNoJob) {
		fmt.Fprintln(os.Stderr, "no job available")
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func jobStore(kind, redisAddr string) (jobs.Store, error) {
	switch kind {
	case "memory":
		return jobs.NewMemoryStore(), nil
	case "redis":
		return jobs.NewRedisStore(redisAddr), nil
	default:
		return nil, fmt.Errorf("unsupported queue %q", kind)
	}
}
