// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	if len(os.Args) > 1 && os.Args[1] == "load-managed-bundle" {
		loadManagedBundle(os.Args[2:])
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
	if len(os.Args) > 1 && os.Args[1] == "status-api" {
		serveStatusAPI(os.Args[2:])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "bundle" && os.Args[2] == "status" {
		bundleStatusCmd(os.Args[3:])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "adapters" && os.Args[2] == "status" {
		adaptersStatusCmd(os.Args[3:])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "runtime" && os.Args[2] == "actions" {
		runtimeActionsCmd(os.Args[3:])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "runtime" && os.Args[2] == "journal" {
		runtimeJournalCmd(os.Args[3:])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "audit" && os.Args[2] == "pending" {
		auditPendingCmd(os.Args[3:])
		return
	}
	fmt.Println(version.Binary("kliq"))
	fmt.Println("usage: kliq verify-bundle --bundle path --key path")
	fmt.Println("usage: kliq load-bundle --bundle path --key path [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq load-managed-bundle --assignment-url http://127.0.0.1:8080 --bearer-token token --kliq-id id --environment env --stage stage --scope scope --trust-key-id key --key path [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq execute-action --key path --adapter-id id --adapter-addr host:port --capability-id id --capability-grant-id id --decision-id id --action-type id --target-key value --reason text [--audit-id id|--derive-audit-id] [--state path] [--target-scope scope] [--ttl 1m] [--mode required] [--correlation-id id]")
	fmt.Println("usage: kliq reconcile --key path --adapter-id id --adapter-addr host:port [--state ./var/kernloom/kliq/state.db] [--dry-run]")
	fmt.Println("usage: kliq status [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq bundle status [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq adapters status [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq runtime actions [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq runtime journal --action-id id [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq audit pending [--state ./var/kernloom/kliq/state.db]")
	fmt.Println("usage: kliq status-api [--state ./var/kernloom/kliq/state.db] [--listen 127.0.0.1:18090]")
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
		logError("kliq_verify_bundle_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logInfo("kliq_runtime_bundle_verified", "policy_id", result.Bundle.Metadata.PolicyID, "key_id", redactID(result.Envelope.KeyID), "payload_sha256", result.Result.PayloadSHA256)
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
		logError("kliq_load_bundle_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logInfo("kliq_runtime_bundle_loaded", "bundle_id", record.BundleID, "policy_id", record.PolicyID, "correlation_id", redactID(record.CorrelationID))
	fmt.Println("runtime bundle loaded")
	fmt.Printf("  state: %s\n", *statePath)
	fmt.Printf("  bundle_id: %s\n", record.BundleID)
	fmt.Printf("  policy_id: %s\n", record.PolicyID)
	fmt.Printf("  expires_at: %s\n", record.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
}

func loadManagedBundle(args []string) {
	fs := flag.NewFlagSet("kliq load-managed-bundle", flag.ExitOnError)
	assignmentURL := fs.String("assignment-url", "", "Forge Assignment API base URL")
	bearerToken := fs.String("bearer-token", "", "bearer token for Forge Assignment API")
	kliqID := fs.String("kliq-id", "", "local KLIQ id")
	environment := fs.String("environment", "", "local KLIQ environment")
	stage := fs.String("stage", "", "local KLIQ stage")
	scope := fs.String("scope", "", "local KLIQ scope")
	trustKeyID := fs.String("trust-key-id", "", "trusted assignment signing key id")
	keyPath := fs.String("key", "", "path to dev-local Ed25519 verifier key file")
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *assignmentURL == "" || *bearerToken == "" || *kliqID == "" || *environment == "" || *stage == "" || *scope == "" || *trustKeyID == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "kliq load-managed-bundle requires --assignment-url, --bearer-token, --kliq-id, --environment, --stage, --scope, --trust-key-id and --key")
		os.Exit(2)
	}
	manager, closeStore := managerOrExit(*statePath, *keyPath, nil)
	defer closeStore()
	record, err := manager.LoadManagedBundle(context.Background(), &kliqbundle.ManagedAssignmentSource{
		BaseURL:     *assignmentURL,
		BearerToken: *bearerToken,
		KLIQID:      *kliqID,
		Environment: *environment,
		Stage:       *stage,
		Scope:       *scope,
		TrustKeyID:  *trustKeyID,
		Verifier:    manager.Verifier,
	})
	if err != nil {
		logError("kliq_load_managed_bundle_failed", "kliq_id", *kliqID, "environment", *environment, "stage", *stage, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logInfo("kliq_managed_runtime_bundle_loaded", "bundle_id", record.BundleID, "policy_id", record.PolicyID, "correlation_id", redactID(record.CorrelationID))
	fmt.Println("managed runtime bundle loaded")
	fmt.Printf("  state: %s\n", *statePath)
	fmt.Printf("  bundle_id: %s\n", record.BundleID)
	fmt.Printf("  policy_id: %s\n", record.PolicyID)
	fmt.Printf("  source: %s\n", record.BundleSource)
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
		logError("kliq_execute_action_failed", "decision_id", redactID(*decisionID), "adapter_id", *adapterID, "correlation_id", redactID(*correlationID), "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(result.Results) == 0 {
		fmt.Fprintln(os.Stderr, "runtime action plan produced no execution result")
		os.Exit(1)
	}
	action := result.Results[0]
	logInfo("kliq_runtime_action_processed", "plan_id", result.Plan.PlanID, "runtime_action_id", action.Lease.RuntimeActionID, "adapter_id", action.Lease.AdapterID, "capability_id", action.Lease.CapabilityID, "correlation_id", redactID(action.Lease.CorrelationID), "status", string(action.Lease.Status), "applied", action.Applied)
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
	dryRun := fs.Bool("dry-run", false, "inspect reconciliation work without adapter calls or state mutations")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *dryRun {
		store, closeStore := stateStoreOrExit(*statePath)
		defer closeStore()
		result, err := (kliqruntime.Manager{Store: store}).ReconcileDryRun(context.Background())
		if err != nil {
			logError("kliq_reconcile_dry_run_failed", "error", err.Error())
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		logInfo("kliq_reconcile_dry_run_complete", "active", result.Active, "expired", result.Expired, "unknown", result.Unknown)
		fmt.Println("kliq reconciliation dry run complete")
		printReconcileResult(result)
		return
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
		logError("kliq_reconcile_failed", "adapter_id", *adapterID, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logInfo("kliq_reconcile_complete", "active", result.Active, "expired", result.Expired, "unknown", result.Unknown)
	fmt.Println("kliq reconciliation complete")
	printReconcileResult(result)
}

func status(args []string) {
	fs := flag.NewFlagSet("kliq status", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	snapshot, err := buildStatusSnapshot(context.Background(), store, *statePath, nil)
	if err != nil {
		logError("kliq_status_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printStatusSnapshot(snapshot)
}

func bundleStatusCmd(args []string) {
	fs := flag.NewFlagSet("kliq bundle status", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	bundle, err := store.LastBundle(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printBundleStatus(bundleStatus(bundle))
}

func adaptersStatusCmd(args []string) {
	fs := flag.NewFlagSet("kliq adapters status", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	leases, err := store.AllLeases(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printAdapterStatuses(adapterStatusViews(leases, nil))
}

func runtimeActionsCmd(args []string) {
	fs := flag.NewFlagSet("kliq runtime actions", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	leases, err := store.AllLeases(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printRuntimeActions(runtimeActionViews(leases))
}

func runtimeJournalCmd(args []string) {
	fs := flag.NewFlagSet("kliq runtime journal", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	actionID := fs.String("action-id", "", "runtime action id")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *actionID == "" {
		fmt.Fprintln(os.Stderr, "kliq runtime journal requires --action-id")
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	entries, err := store.JournalEntries(context.Background(), *actionID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printJournalEntries(journalEntryViews(entries))
}

func auditPendingCmd(args []string) {
	fs := flag.NewFlagSet("kliq audit pending", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	records, err := store.PendingAudits(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printAuditRecords(auditRecordViews(records))
}

func managerOrExit(statePath, keyPath string, registry kliqruntime.AdapterRuntimeRegistry) (kliqruntime.Manager, func()) {
	verifier, err := signing.LoadDevLocalVerifier(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, closeStore := stateStoreOrExit(statePath)
	manager := kliqruntime.Manager{
		Store:    store,
		Verifier: verifier,
		Registry: registry,
	}
	return manager, closeStore
}

func stateStoreOrExit(statePath string) (*actionstate.SQLiteStore, func()) {
	store, err := actionstate.OpenSQLite(statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return store, func() {
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

func printReconcileResult(result kliqruntime.ReconcileResult) {
	fmt.Printf("  active: %d\n", result.Active)
	fmt.Printf("  expired: %d\n", result.Expired)
	fmt.Printf("  unknown: %d\n", result.Unknown)
	for _, adapter := range result.AdapterResults {
		fmt.Printf("  adapter: %s active=%d expired=%d unknown=%d\n", adapter.AdapterID, adapter.Active, adapter.Expired, adapter.Unknown)
	}
	for _, finding := range result.Findings {
		fmt.Printf("  finding: %s\n", finding)
	}
}

func printStatusSnapshot(snapshot statusSnapshot) {
	fmt.Println("kliq status")
	fmt.Printf("  state: %s\n", snapshot.StatePath)
	if snapshot.Bundle != nil {
		printBundleStatus(*snapshot.Bundle)
	} else {
		fmt.Println("  bundle: unavailable")
	}
	fmt.Printf("  runtime_actions: %d\n", len(snapshot.RuntimeActions))
	fmt.Printf("  pending_audit_records: %d\n", snapshot.PendingAuditCount)
	printAdapterStatuses(snapshot.Adapters)
}

func printBundleStatus(bundle bundleStatusView) {
	fmt.Println("bundle status")
	fmt.Printf("  bundle_id: %s\n", bundle.BundleID)
	fmt.Printf("  policy_id: %s\n", bundle.PolicyID)
	fmt.Printf("  source_commit: %s\n", bundle.SourceCommit)
	fmt.Printf("  correlation_id: %s\n", bundle.CorrelationID)
	fmt.Printf("  key_id: %s\n", bundle.KeyID)
	fmt.Printf("  payload_sha256: %s\n", bundle.PayloadSHA256)
	fmt.Printf("  bundle_source_sha256: %s\n", bundle.BundleSourceSHA256)
	fmt.Printf("  expires_at: %s\n", bundle.ExpiresAt)
	fmt.Printf("  verified_at: %s\n", bundle.VerifiedAt)
}

func printAdapterStatuses(adapters []adapterStatusView) {
	fmt.Println("adapters status")
	if len(adapters) == 0 {
		fmt.Println("  none")
		return
	}
	for _, adapter := range adapters {
		fmt.Printf("  adapter: %s\n", adapter.AdapterID)
		fmt.Printf("    registered: %t\n", adapter.Registered)
		fmt.Printf("    health: %s\n", adapter.Health)
		fmt.Printf("    leases: %d\n", adapter.Leases)
		fmt.Printf("    active: %d\n", adapter.Active)
		fmt.Printf("    expired: %d\n", adapter.Expired)
		fmt.Printf("    unknown: %d\n", adapter.Unknown)
	}
}

func printRuntimeActions(actions []runtimeActionView) {
	fmt.Println("runtime actions")
	if len(actions) == 0 {
		fmt.Println("  none")
		return
	}
	for _, action := range actions {
		fmt.Printf("  action: %s\n", action.RuntimeActionID)
		fmt.Printf("    plan_id: %s\n", action.PlanID)
		fmt.Printf("    adapter_id: %s\n", action.AdapterID)
		fmt.Printf("    capability_id: %s\n", action.CapabilityID)
		fmt.Printf("    correlation_id: %s\n", action.CorrelationID)
		fmt.Printf("    action_type: %s\n", action.ActionType)
		fmt.Printf("    target_scope: %s\n", action.TargetScope)
		fmt.Printf("    target_key_sha256: %s\n", action.TargetKeySHA256)
		fmt.Printf("    idempotency_key_sha256: %s\n", action.IdempotencyKeySHA256)
		fmt.Printf("    status: %s\n", action.Status)
		fmt.Printf("    expires_at: %s\n", action.ExpiresAt)
	}
}

func printJournalEntries(entries []journalEntryView) {
	fmt.Println("runtime journal")
	if len(entries) == 0 {
		fmt.Println("  none")
		return
	}
	for _, entry := range entries {
		fmt.Printf("  entry: %s\n", entry.ID)
		fmt.Printf("    runtime_action_id: %s\n", entry.RuntimeActionID)
		fmt.Printf("    event: %s\n", entry.Event)
		fmt.Printf("    status: %s\n", entry.Status)
		fmt.Printf("    message_sha256: %s\n", entry.MessageSHA256)
		fmt.Printf("    created_at: %s\n", entry.CreatedAt)
	}
}

func printAuditRecords(records []auditRecordView) {
	fmt.Println("pending audit")
	if len(records) == 0 {
		fmt.Println("  none")
		return
	}
	for _, record := range records {
		fmt.Printf("  record: %s\n", record.ID)
		fmt.Printf("    runtime_action_id: %s\n", record.RuntimeActionID)
		fmt.Printf("    status: %s\n", record.Status)
		fmt.Printf("    payload_sha256: %s\n", record.PayloadSHA256)
		fmt.Printf("    created_at: %s\n", record.CreatedAt)
	}
}
