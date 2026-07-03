// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/core/version"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
	kliqruntime "github.com/kernloom/kernloom-core/internal/kliq/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultStatePath = "./var/kernloom/kliq/state.db"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify-bundle" {
		verifyBundle(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "load-bundle" {
		loadBundle(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "execute-action" {
		executeAction(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "reconcile" {
		reconcile(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "status" {
		status(os.Args[2:])
		return
	}
	fmt.Println(version.Binary("kliq"))
	fmt.Println("usage: kliq verify-bundle --bundle path --key path")
	fmt.Println("usage: kliq load-bundle --bundle path --key path [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq execute-action --key path --adapter-id id --adapter-addr host:port --capability-id id --capability-grant-id id --decision-id id --action-type id --target-key value --reason text [--audit-id id|--derive-audit-id] [--state path] [--target-scope scope] [--ttl 1m] [--mode required] [--correlation-id id]")
	fmt.Println("usage: kliq reconcile --key path --adapter-id id --adapter-addr host:port [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq status [--state ./var/kernloom/kliq/state.db]")
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

func loadBundle(args []string) {
	fs := flag.NewFlagSet("kliq load-bundle", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "path to signed RuntimeBundle envelope")
	keyPath := fs.String("key", "", "path to dev-local Ed25519 key file")
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *bundlePath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "kliq load-bundle requires --bundle and --key")
		os.Exit(2)
	}
	manager, closeStore := managerOrExit(*statePath, *keyPath, nil)
	defer closeStore()
	record, err := manager.LoadBundle(context.Background(), kliqbundle.LocalFileSource{Path: *bundlePath})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("runtime bundle loaded")
	fmt.Printf("  state: %s\n", *statePath)
	fmt.Printf("  bundle_id: %s\n", record.BundleID)
	fmt.Printf("  policy_id: %s\n", record.PolicyID)
	fmt.Printf("  expires_at: %s\n", record.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
}

func executeAction(args []string) {
	fs := flag.NewFlagSet("kliq execute-action", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to dev-local Ed25519 key file")
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	adapterID := fs.String("adapter-id", "", "runtime adapter id")
	adapterAddr := fs.String("adapter-addr", "", "runtime adapter gRPC address")
	capabilityID := fs.String("capability-id", "", "adapter capability id")
	capabilityGrantID := fs.String("capability-grant-id", "", "approved capability grant id")
	decisionID := fs.String("decision-id", "", "runtime decision id")
	mode := fs.String("mode", kliqruntime.ActionModeRequired, "runtime action mode: required|optional|fallback|any_of")
	actionType := fs.String("action-type", "", "runtime action type or canonical id")
	targetScope := fs.String("target-scope", "", "target scope; defaults to bundle max_scope")
	targetKey := fs.String("target-key", "", "target key to apply the runtime action to")
	ttl := fs.String("ttl", "", "action ttl; defaults to bundle max_ttl")
	reason := fs.String("reason", "", "human-readable action reason")
	auditID := fs.String("audit-id", "", "audit id")
	correlationID := fs.String("correlation-id", "", "correlation id for runtime logs, adapter requests and evidence")
	deriveAuditID := fs.Bool("derive-audit-id", false, "derive audit id from non-empty decision id")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *keyPath == "" || *adapterID == "" || *adapterAddr == "" || *capabilityID == "" || *capabilityGrantID == "" || *decisionID == "" || *actionType == "" || *targetKey == "" || *reason == "" {
		fmt.Fprintln(os.Stderr, "kliq execute-action requires --key, --adapter-id, --adapter-addr, --capability-id, --capability-grant-id, --decision-id, --action-type, --target-key and --reason")
		os.Exit(2)
	}
	if *auditID == "" && !*deriveAuditID {
		fmt.Fprintln(os.Stderr, "kliq execute-action requires --audit-id or --derive-audit-id")
		os.Exit(2)
	}
	registry, closeAdapters := adapterRegistryOrExit(*adapterID, *adapterAddr)
	defer closeAdapters()
	manager, closeStore := managerOrExit(*statePath, *keyPath, registry)
	defer closeStore()
	result, err := manager.ExecuteAction(context.Background(), kliqruntime.ExecuteRequest{
		DecisionID:                  *decisionID,
		AdapterID:                   *adapterID,
		CapabilityID:                *capabilityID,
		CapabilityGrantID:           *capabilityGrantID,
		Mode:                        *mode,
		ActionType:                  *actionType,
		TargetScope:                 *targetScope,
		TargetKey:                   *targetKey,
		TTL:                         *ttl,
		Reason:                      *reason,
		AuditID:                     *auditID,
		CorrelationID:               *correlationID,
		DeriveAuditIDFromDecisionID: *deriveAuditID,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(result.Results) == 0 {
		fmt.Fprintln(os.Stderr, "runtime action plan produced no execution result")
		os.Exit(1)
	}
	action := result.Results[0]
	fmt.Println("runtime action plan processed")
	fmt.Printf("  plan_id: %s\n", result.Plan.PlanID)
	fmt.Printf("  applied: %t\n", action.Applied)
	fmt.Printf("  runtime_action_id: %s\n", action.Lease.RuntimeActionID)
	fmt.Printf("  adapter_id: %s\n", action.Lease.AdapterID)
	fmt.Printf("  capability_id: %s\n", action.Lease.CapabilityID)
	fmt.Printf("  correlation_id: %s\n", action.Lease.CorrelationID)
	fmt.Printf("  status: %s\n", action.Lease.Status)
	fmt.Printf("  expires_at: %s\n", action.Lease.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
}

func reconcile(args []string) {
	fs := flag.NewFlagSet("kliq reconcile", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to dev-local Ed25519 key file")
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	adapterID := fs.String("adapter-id", "", "runtime adapter id")
	adapterAddr := fs.String("adapter-addr", "", "runtime adapter gRPC address")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *keyPath == "" || *adapterID == "" || *adapterAddr == "" {
		fmt.Fprintln(os.Stderr, "kliq reconcile requires --key, --adapter-id and --adapter-addr")
		os.Exit(2)
	}
	registry, closeAdapters := adapterRegistryOrExit(*adapterID, *adapterAddr)
	defer closeAdapters()
	manager, closeStore := managerOrExit(*statePath, *keyPath, registry)
	defer closeStore()
	result, err := manager.Reconcile(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("kliq reconciliation complete")
	fmt.Printf("  active: %d\n", result.Active)
	fmt.Printf("  expired: %d\n", result.Expired)
	fmt.Printf("  unknown: %d\n", result.Unknown)
	for _, finding := range result.Findings {
		fmt.Printf("  finding: %s\n", finding)
	}
}

func status(args []string) {
	fs := flag.NewFlagSet("kliq status", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := actionstate.OpenSQLite(*statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	ctx := context.Background()
	bundle, bundleErr := store.LastBundle(ctx)
	if bundleErr != nil && !errors.Is(bundleErr, actionstate.ErrNotFound) {
		fmt.Fprintln(os.Stderr, bundleErr)
		os.Exit(1)
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	audits, err := store.PendingAudits(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("kliq status")
	fmt.Printf("  state: %s\n", *statePath)
	if bundleErr == nil {
		fmt.Printf("  bundle_id: %s\n", bundle.BundleID)
		fmt.Printf("  policy_id: %s\n", bundle.PolicyID)
		fmt.Printf("  source_commit: %s\n", redactID(bundle.SourceCommit))
		fmt.Printf("  correlation_id: %s\n", redactID(bundle.CorrelationID))
		fmt.Printf("  expires_at: %s\n", bundle.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	} else {
		fmt.Println("  bundle: unavailable")
	}
	fmt.Printf("  runtime_actions: %d\n", len(leases))
	fmt.Printf("  pending_audit_records: %d\n", len(audits))
	for _, lease := range leases {
		fmt.Printf("  action: %s\n", lease.RuntimeActionID)
		fmt.Printf("    plan_id: %s\n", lease.PlanID)
		fmt.Printf("    adapter_id: %s\n", lease.AdapterID)
		fmt.Printf("    capability_id: %s\n", lease.CapabilityID)
		fmt.Printf("    correlation_id: %s\n", redactID(lease.CorrelationID))
		fmt.Printf("    action_type: %s\n", lease.ActionType)
		fmt.Printf("    target_scope: %s\n", lease.TargetScope)
		fmt.Printf("    target_key_sha256: %s\n", redactedHash(lease.TargetKey))
		fmt.Printf("    idempotency_key_sha256: %s\n", redactedHash(lease.IdempotencyKey))
		fmt.Printf("    status: %s\n", lease.Status)
		fmt.Printf("    expires_at: %s\n", lease.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	}
}

func managerOrExit(statePath, keyPath string, registry kliqruntime.AdapterRuntimeRegistry) (kliqruntime.Manager, func()) {
	verifier, err := signing.LoadDevLocalVerifier(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	manager := kliqruntime.Manager{
		Store:    store,
		Verifier: verifier,
		Registry: registry,
	}
	return manager, func() {
		_ = store.Close()
	}
}

func adapterRegistryOrExit(adapterID, adapterAddr string) (kliqruntime.AdapterRuntimeRegistry, func()) {
	var conn *grpc.ClientConn
	conn, err := grpc.NewClient(adapterAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	registry := kliqruntime.NewStaticAdapterRuntimeRegistry(kliqruntime.StaticAdapterRuntimeEntry{
		AdapterID: adapterID,
		Executor:  kliqruntime.NewAdapterRuntimeExecutor(conn),
	})
	return registry, func() {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func redactID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 12 {
		return value
	}
	return value[:8] + "..." + value[len(value)-4:]
}

func redactedHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}
