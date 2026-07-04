// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
	kliqruntime "github.com/kernloom/kernloom-core/internal/kliq/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	kliqRunModeManaged    = "managed"
	kliqRunModeStandalone = "standalone"
)

type adapterFlag []string

func (f *adapterFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *adapterFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("adapter value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

type runOptions struct {
	Mode               string
	StatePath          string
	TrustBundlePath    string
	DevAllowPrivateKey bool
	ForgeURL           string
	BundleSource       string
	StatusListen       string
	PollInterval       time.Duration
	HeartbeatInterval  time.Duration
	StatusInterval     time.Duration
	DecisionInterval   time.Duration
	ReconcileInterval  time.Duration
	AuditFlushInterval time.Duration
	Once               bool
	Adapters           []string
	HTTPClient         *http.Client
}

type runDaemon struct {
	opts                 runOptions
	store                *actionstate.SQLiteStore
	manager              kliqruntime.Manager
	credential           actionstate.KLIQCredential
	httpClient           *http.Client
	now                  func() time.Time
	decisions            RuntimeDecisionSource
	findings             []string
	closeManagedAdapters func()
}

type RuntimeDecisionSource interface {
	NextDecision(ctx context.Context) (kliqruntime.ExecuteRequest, bool, error)
}

func run(args []string) {
	fs := flag.NewFlagSet("kliq run", flag.ExitOnError)
	var adapters adapterFlag
	opts := runOptions{}
	fs.StringVar(&opts.Mode, "mode", kliqRunModeManaged, "runtime mode: managed or standalone")
	fs.StringVar(&opts.StatePath, "state", defaultStatePath, "path to KLIQ local SQLite state")
	fs.StringVar(&opts.TrustBundlePath, "trust-bundle", defaultTrustBundlePath, "path to public assignment/runtime artifact trust bundle")
	fs.BoolVar(&opts.DevAllowPrivateKey, "dev-allow-private-trust-key", false, "allow dev-local key files containing private material; never use in production")
	fs.StringVar(&opts.ForgeURL, "forge-url", "", "Forge API base URL for managed mode")
	fs.StringVar(&opts.BundleSource, "bundle-source", "", "standalone bundle source, currently file://path or path")
	fs.StringVar(&opts.StatusListen, "status-listen", "", "optional local read-only status API listen address")
	fs.DurationVar(&opts.PollInterval, "poll-interval", 30*time.Second, "managed assignment polling interval")
	fs.DurationVar(&opts.HeartbeatInterval, "heartbeat-interval", 30*time.Second, "managed heartbeat interval")
	fs.DurationVar(&opts.StatusInterval, "status-interval", time.Minute, "managed status report interval")
	fs.DurationVar(&opts.DecisionInterval, "decision-interval", 5*time.Second, "runtime decision source polling interval")
	fs.DurationVar(&opts.ReconcileInterval, "reconcile-interval", 30*time.Second, "runtime action lease reconciliation interval")
	fs.DurationVar(&opts.AuditFlushInterval, "audit-flush-interval", time.Minute, "audit spool flush interval")
	fs.BoolVar(&opts.Once, "once", false, "run one daemon cycle and exit; intended for smoke tests")
	fs.Var(&adapters, "adapter", "dev/bootstrap adapter runtime endpoint as adapter_id=host:port; repeatable; managed production should prefer adapter_assignment artifacts")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.Adapters = append([]string(nil), adapters...)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runKLIQ(ctx, opts); err != nil {
		logError("kliq_run_failed", "mode", opts.Mode, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runKLIQ(ctx context.Context, opts runOptions) error {
	if opts.TrustBundlePath == "" {
		return fmt.Errorf("kliq run requires --trust-bundle")
	}
	verifier, trustBundle, err := loadTrustVerifier(opts.TrustBundlePath, opts.DevAllowPrivateKey)
	if err != nil {
		return err
	}
	store, err := actionstate.OpenSQLite(opts.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()
	registry, closeAdapters, err := adapterRegistryFromFlags(opts.Adapters)
	if err != nil {
		return err
	}
	defer closeAdapters()
	daemon := &runDaemon{
		opts:    opts,
		store:   store,
		manager: kliqruntime.Manager{Store: store, Verifier: verifier, TrustBundle: trustBundle, Registry: registry},
		now:     time.Now,
	}
	defer func() {
		if daemon.closeManagedAdapters != nil {
			daemon.closeManagedAdapters()
		}
	}()
	if opts.HTTPClient != nil {
		daemon.httpClient = opts.HTTPClient
	} else {
		daemon.httpClient = http.DefaultClient
	}
	if opts.Mode == kliqRunModeManaged {
		credential, err := store.KLIQCredential(ctx)
		if err != nil {
			return fmt.Errorf("managed mode requires local KLIQ enrollment credentials: %w", err)
		}
		if opts.ForgeURL != "" {
			credential.AssignmentURL = strings.TrimRight(opts.ForgeURL, "/")
		}
		if credential.AssignmentURL == "" {
			return fmt.Errorf("managed mode requires --forge-url or an enrolled assignment_url")
		}
		daemon.credential = credential
	}
	var statusServer *http.Server
	if opts.StatusListen != "" {
		server, err := startRunStatusServer(ctx, opts.StatusListen, store, opts.StatePath, registry)
		if err != nil {
			return err
		}
		statusServer = server
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = statusServer.Shutdown(shutdownCtx)
		}()
	}
	logInfo("kliq_started", "mode", opts.Mode, "state", opts.StatePath, "status_listen", opts.StatusListen, "kliq_id", daemon.credential.KLIQID)
	if opts.Once {
		return daemon.runOnce(ctx)
	}
	return daemon.loop(ctx)
}

func (d *runDaemon) runOnce(ctx context.Context) error {
	if err := d.loadOrPoll(ctx); err != nil {
		return err
	}
	if err := d.processRuntimeDecisions(ctx); err != nil {
		return err
	}
	if d.opts.Mode == kliqRunModeManaged {
		if err := d.sendHeartbeat(ctx); err != nil {
			logError("heartbeat_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
		}
		if err := d.sendStatusReport(ctx); err != nil {
			logError("status_report_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
		}
	}
	if err := d.reconcile(ctx); err != nil {
		logError("kliq_run_reconcile_failed", "error", err.Error())
	}
	if err := d.flushAuditSpool(ctx); err != nil {
		logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
		return err
	}
	return nil
}

func (d *runDaemon) loop(ctx context.Context) error {
	if err := d.runOnce(ctx); err != nil {
		logError("kliq_initial_cycle_failed", "error", err.Error())
	}
	pollTicker := newTicker(d.opts.PollInterval)
	heartbeatTicker := newTicker(d.opts.HeartbeatInterval)
	statusTicker := newTicker(d.opts.StatusInterval)
	decisionTicker := newTicker(d.opts.DecisionInterval)
	reconcileTicker := newTicker(d.opts.ReconcileInterval)
	auditTicker := newTicker(d.opts.AuditFlushInterval)
	defer pollTicker.Stop()
	defer heartbeatTicker.Stop()
	defer statusTicker.Stop()
	defer decisionTicker.Stop()
	defer reconcileTicker.Stop()
	defer auditTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pollTicker.C:
			if err := d.loadOrPoll(ctx); err != nil {
				logError("assignment_poll_failed", "mode", d.opts.Mode, "kliq_id", d.credential.KLIQID, "error", err.Error())
			}
		case <-heartbeatTicker.C:
			if d.opts.Mode == kliqRunModeManaged {
				if err := d.sendHeartbeat(ctx); err != nil {
					logError("heartbeat_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
				}
			}
		case <-statusTicker.C:
			if d.opts.Mode == kliqRunModeManaged {
				if err := d.sendStatusReport(ctx); err != nil {
					logError("status_report_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
				}
			}
		case <-decisionTicker.C:
			if err := d.processRuntimeDecisions(ctx); err != nil {
				logError("runtime_decision_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
			}
		case <-reconcileTicker.C:
			if err := d.reconcile(ctx); err != nil {
				logError("kliq_run_reconcile_failed", "error", err.Error())
			}
		case <-auditTicker.C:
			if err := d.flushAuditSpool(ctx); err != nil {
				logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
			}
		}
	}
}

func (d *runDaemon) loadOrPoll(ctx context.Context) error {
	switch d.opts.Mode {
	case kliqRunModeManaged:
		return d.pollManagedAssignment(ctx)
	case kliqRunModeStandalone:
		return d.loadStandaloneBundle(ctx)
	default:
		return fmt.Errorf("unsupported kliq run mode %q", d.opts.Mode)
	}
}

func (d *runDaemon) pollManagedAssignment(ctx context.Context) error {
	if err := d.ensureServiceTokenFresh(ctx); err != nil {
		return err
	}
	logInfo("assignment_poll_started", "kliq_id", d.credential.KLIQID, "environment", d.credential.Environment, "stage", d.credential.Stage, "scope", d.credential.Scope)
	record, err := d.manager.LoadManagedBundle(ctx, &kliqbundle.ManagedAssignmentSource{
		BaseURL:     d.credential.AssignmentURL,
		BearerToken: d.credential.ServiceToken,
		KLIQID:      d.credential.KLIQID,
		Environment: d.credential.Environment,
		Stage:       d.credential.Stage,
		Scope:       d.credential.Scope,
		TrustKeyID:  d.credential.TrustKeyID,
		TrustBundle: d.activeTrustBundle(),
		Verifier:    d.manager.Verifier,
		HTTPClient:  d.httpClient,
	})
	if err != nil {
		d.recordFinding("assignment poll failed; using cached assignment if still valid: " + err.Error())
		logError("assignment_poll_failed", "kliq_id", d.credential.KLIQID, "environment", d.credential.Environment, "stage", d.credential.Stage, "scope", d.credential.Scope, "error", err.Error())
		logError("assignment_rejected", "kliq_id", d.credential.KLIQID, "environment", d.credential.Environment, "stage", d.credential.Stage, "scope", d.credential.Scope, "error", err.Error())
		return d.managedPollFallback(ctx, err)
	}
	state, _ := d.store.KLIQManagementState(ctx, d.credential.KLIQID)
	logInfo("assignment_downloaded", "kliq_id", d.credential.KLIQID, "assignment_id", state.ActiveAssignmentID, "assignment_version", state.ActiveAssignmentVersion)
	logInfo("assignment_verified", "kliq_id", d.credential.KLIQID, "assignment_id", state.ActiveAssignmentID, "assignment_version", state.ActiveAssignmentVersion, "source_commit", record.SourceCommit)
	logInfo("assignment_activated", "kliq_id", d.credential.KLIQID, "assignment_id", state.ActiveAssignmentID, "assignment_version", state.ActiveAssignmentVersion, "bundle_id", record.BundleID, "policy_id", record.PolicyID, "source_commit", record.SourceCommit, "correlation_id", redactID(record.CorrelationID))
	if err := d.activateManagedAdapterAssignments(ctx); err != nil {
		d.recordFinding("adapter assignment activation failed: " + err.Error())
		logError("adapter_assignment_rejected", "kliq_id", d.credential.KLIQID, "assignment_id", state.ActiveAssignmentID, "error", err.Error())
	}
	return nil
}

func (d *runDaemon) managedPollFallback(ctx context.Context, pollErr error) error {
	record, err := d.store.LastBundle(ctx)
	if err != nil {
		return pollErr
	}
	if !d.now().UTC().Before(record.ExpiresAt.UTC()) {
		return fmt.Errorf("managed assignment poll failed and cached bundle is expired: %w", pollErr)
	}
	logInfo("kliq_managed_poll_fallback_to_cached_bundle", "bundle_id", record.BundleID, "expires_at", record.ExpiresAt.Format(time.RFC3339), "error", pollErr.Error())
	return nil
}

func (d *runDaemon) loadStandaloneBundle(ctx context.Context) error {
	path := strings.TrimSpace(d.opts.BundleSource)
	if strings.HasPrefix(path, "file://") {
		path = strings.TrimPrefix(path, "file://")
	}
	if path == "" {
		return fmt.Errorf("standalone mode requires --bundle-source file://path")
	}
	resolvedPath, err := resolveStandaloneBundlePath(path)
	if err != nil {
		return err
	}
	record, err := d.manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: resolvedPath})
	if err != nil {
		return err
	}
	logInfo("kliq_standalone_bundle_loaded", "bundle_id", record.BundleID, "policy_id", record.PolicyID, "source_commit", record.SourceCommit, "correlation_id", redactID(record.CorrelationID))
	return nil
}

func (d *runDaemon) sendHeartbeat(ctx context.Context) error {
	assignment := d.activeAssignment(ctx)
	bundle := d.activeBundle(ctx)
	heartbeat := domain.KLIQHeartbeat{
		KLIQID:            d.credential.KLIQID,
		Environment:       d.credential.Environment,
		Stage:             d.credential.Stage,
		Scope:             d.credential.Scope,
		AssignmentID:      assignment.ActiveAssignmentID,
		AssignmentVersion: assignment.ActiveAssignmentVersion,
		BundleID:          bundle.BundleID,
		SourceCommit:      bundle.SourceCommit,
		Status:            "ok",
		ReportedAt:        d.now().UTC(),
	}
	if err := d.postManagedJSON(ctx, "/v1/kliq/heartbeat", heartbeat); err != nil {
		return err
	}
	logInfo("heartbeat_sent", "kliq_id", d.credential.KLIQID, "assignment_id", assignment.ActiveAssignmentID, "assignment_version", assignment.ActiveAssignmentVersion, "bundle_id", bundle.BundleID, "source_commit", bundle.SourceCommit)
	return nil
}

func (d *runDaemon) sendStatusReport(ctx context.Context) error {
	assignment := d.activeAssignment(ctx)
	bundle := d.activeBundle(ctx)
	actions, _ := d.store.AllLeases(ctx)
	audits, _ := d.store.PendingAudits(ctx)
	snapshot, _ := buildStatusSnapshot(ctx, d.store, d.opts.StatePath, d.manager.Registry)
	report := domain.KLIQStatusReport{
		KLIQID:            d.credential.KLIQID,
		Environment:       d.credential.Environment,
		Stage:             d.credential.Stage,
		Scope:             d.credential.Scope,
		AssignmentID:      assignment.ActiveAssignmentID,
		AssignmentVersion: assignment.ActiveAssignmentVersion,
		BundleID:          bundle.BundleID,
		SourceCommit:      bundle.SourceCommit,
		Status:            "ok",
		Findings:          d.statusFindings(snapshot.Findings),
		RuntimeActions:    len(actions),
		PendingAudits:     len(audits),
		AdapterHealth:     adapterHealthSummary(snapshot.Adapters),
		RuntimeSummary:    runtimeSummary(snapshot.RuntimeCounts),
		AuditSpoolState:   auditSpoolState(len(audits)),
		ReportedAt:        d.now().UTC(),
	}
	if err := d.postManagedJSON(ctx, "/v1/kliq/status-reports", report); err != nil {
		return err
	}
	d.clearFindings()
	logInfo("status_report_sent", "kliq_id", d.credential.KLIQID, "assignment_id", assignment.ActiveAssignmentID, "assignment_version", assignment.ActiveAssignmentVersion, "bundle_id", bundle.BundleID, "source_commit", bundle.SourceCommit)
	return nil
}

func (d *runDaemon) postManagedJSON(ctx context.Context, path string, value any) error {
	if err := d.ensureServiceTokenFresh(ctx); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	url := strings.TrimRight(d.credential.AssignmentURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.credential.ServiceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s returned %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (d *runDaemon) reconcile(ctx context.Context) error {
	logInfo("reconcile_started", "kliq_id", d.credential.KLIQID)
	assignment := d.activeAssignment(ctx)
	result, err := d.manager.Reconcile(ctx)
	if err != nil {
		if errors.Is(err, actionstate.ErrNotFound) {
			return nil
		}
		return err
	}
	for _, adapterResult := range result.AdapterResults {
		if adapterResult.Unknown > 0 {
			logError("adapter_unavailable", "kliq_id", d.credential.KLIQID, "assignment_id", assignment.ActiveAssignmentID, "assignment_version", assignment.ActiveAssignmentVersion, "adapter_id", adapterResult.AdapterID, "unknown", adapterResult.Unknown)
		}
		for _, finding := range adapterResult.Findings {
			if strings.Contains(finding, "failed to cleanup") {
				logError("runtime_action_cleanup_failed", "kliq_id", d.credential.KLIQID, "adapter_id", adapterResult.AdapterID, "finding", finding)
			}
		}
	}
	logInfo("reconcile_completed", "kliq_id", d.credential.KLIQID, "assignment_id", assignment.ActiveAssignmentID, "assignment_version", assignment.ActiveAssignmentVersion, "active", result.Active, "expired", result.Expired, "unknown", result.Unknown)
	return nil
}

func (d *runDaemon) flushAuditSpool(ctx context.Context) error {
	logInfo("audit_flush_started", "kliq_id", d.credential.KLIQID)
	records, err := d.store.PendingAudits(ctx)
	if err != nil {
		logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
		return err
	}
	for _, record := range records {
		if d.opts.Mode != kliqRunModeManaged {
			continue
		}
		uploadedAt := d.now().UTC()
		upload := domain.KLIQAuditUpload{
			KLIQID:          d.credential.KLIQID,
			Environment:     d.credential.Environment,
			Stage:           d.credential.Stage,
			Scope:           d.credential.Scope,
			AuditRecordID:   record.ID,
			RuntimeActionID: record.RuntimeActionID,
			Payload:         []byte(record.Payload),
			PayloadSHA256:   domain.SHA256JSON([]byte(record.Payload)),
			CreatedAt:       record.CreatedAt,
			UploadedAt:      uploadedAt,
		}
		if err := d.postManagedJSON(ctx, "/v1/kliq/audit-events", upload); err != nil {
			_ = d.store.MarkAuditFailed(ctx, record.ID, uploadedAt, err.Error())
			logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "audit_record_id", record.ID, "runtime_action_id", record.RuntimeActionID, "error", err.Error())
			continue
		}
		if err := d.store.MarkAuditUploaded(ctx, record.ID, uploadedAt); err != nil {
			logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "audit_record_id", record.ID, "error", err.Error())
			return err
		}
	}
	logInfo("kliq_audit_spool_flush_checked", "pending", len(records))
	return nil
}

func (d *runDaemon) processRuntimeDecisions(ctx context.Context) error {
	if d.decisions == nil {
		return nil
	}
	for {
		req, ok, err := d.decisions.NextDecision(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		result, err := d.manager.ExecuteAction(ctx, req)
		if err != nil {
			return err
		}
		for _, action := range result.Results {
			logInfo("runtime_decision_processed", "kliq_id", d.credential.KLIQID, "plan_id", result.Plan.PlanID, "runtime_action_id", action.Lease.RuntimeActionID, "adapter_id", action.Lease.AdapterID, "capability_id", action.Lease.CapabilityID, "bundle_id", action.Lease.BundleID, "source_commit", action.Lease.SourceCommit, "correlation_id", redactID(action.Lease.CorrelationID), "status", string(action.Lease.Status), "applied", action.Applied)
		}
	}
}

func (d *runDaemon) activeAssignment(ctx context.Context) actionstate.KLIQManagementState {
	if d.credential.KLIQID == "" {
		return actionstate.KLIQManagementState{}
	}
	state, err := d.store.KLIQManagementState(ctx, d.credential.KLIQID)
	if err != nil {
		return actionstate.KLIQManagementState{}
	}
	return state
}

func (d *runDaemon) activeBundle(ctx context.Context) actionstate.BundleRecord {
	bundle, err := d.store.LastBundle(ctx)
	if err != nil {
		return actionstate.BundleRecord{}
	}
	return bundle
}

func (d *runDaemon) activeTrustBundle() domain.TrustBundle {
	if bundle := d.manager.TrustBundle; bundle.KeyID != "" {
		return bundle
	}
	return domain.TrustBundle{}
}

func (d *runDaemon) ensureServiceTokenFresh(ctx context.Context) error {
	if d.credential.ServiceToken == "" {
		return fmt.Errorf("managed mode requires local KLIQ service token")
	}
	if d.credential.ServiceTokenExpiresAt.IsZero() {
		return nil
	}
	now := d.now().UTC()
	if !now.Before(d.credential.ServiceTokenExpiresAt.UTC()) {
		return fmt.Errorf("local KLIQ service token is expired")
	}
	if d.credential.ServiceTokenExpiresAt.UTC().Sub(now) <= 5*time.Minute {
		return d.refreshServiceToken(ctx)
	}
	return nil
}

func (d *runDaemon) refreshServiceToken(ctx context.Context) error {
	url := strings.TrimRight(d.credential.AssignmentURL, "/") + "/v1/kliq/service-token/refresh"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.credential.ServiceToken)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("service token refresh returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		ServiceToken string    `json:"service_token"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return err
	}
	if parsed.ServiceToken == "" {
		return fmt.Errorf("service token refresh response missing token")
	}
	expiresAt, err := serviceTokenExpiresAt(parsed.ServiceToken)
	if err != nil {
		return err
	}
	if !parsed.ExpiresAt.IsZero() && !expiresAt.Equal(parsed.ExpiresAt.UTC()) {
		expiresAt = parsed.ExpiresAt.UTC()
	}
	d.credential.ServiceToken = parsed.ServiceToken
	d.credential.ServiceTokenExpiresAt = expiresAt
	d.credential.UpdatedAt = d.now().UTC()
	if err := d.store.SaveKLIQCredential(ctx, d.credential); err != nil {
		return err
	}
	logInfo("service_token_refreshed", "kliq_id", d.credential.KLIQID, "expires_at", expiresAt.Format(time.RFC3339))
	return nil
}

func (d *runDaemon) activateManagedAdapterAssignments(ctx context.Context) error {
	artifacts, err := d.store.AssignmentArtifacts(ctx, d.credential.KLIQID)
	if err != nil {
		return err
	}
	values := make([]string, 0)
	for _, artifact := range artifacts {
		if artifact.ArtifactType != "adapter_assignment" {
			continue
		}
		var envelope struct {
			Payload []byte `json:"payload"`
		}
		if err := json.Unmarshal(artifact.EnvelopeJSON, &envelope); err != nil {
			return err
		}
		var assignment domain.AdapterAssignment
		if err := json.Unmarshal(envelope.Payload, &assignment); err != nil {
			return err
		}
		if strings.TrimSpace(assignment.AdapterID) == "" || strings.TrimSpace(assignment.Endpoint) == "" {
			return fmt.Errorf("adapter assignment %q requires adapter_id and endpoint", artifact.ArtifactID)
		}
		values = append(values, assignment.AdapterID+"="+assignment.Endpoint)
	}
	if len(values) == 0 {
		return nil
	}
	registry, closeFn, err := adapterRegistryFromFlags(values)
	if err != nil {
		return err
	}
	if d.closeManagedAdapters != nil {
		d.closeManagedAdapters()
	}
	d.closeManagedAdapters = closeFn
	d.manager.Registry = registry
	logInfo("adapter_assignment_activated", "kliq_id", d.credential.KLIQID, "adapters", strings.Join(values, ","))
	return nil
}

func (d *runDaemon) recordFinding(finding string) {
	finding = strings.TrimSpace(finding)
	if finding == "" {
		return
	}
	d.findings = append(d.findings, finding)
}

func (d *runDaemon) statusFindings(snapshotFindings []string) []string {
	if len(snapshotFindings) == 0 && len(d.findings) == 0 {
		return nil
	}
	out := make([]string, 0, len(snapshotFindings)+len(d.findings))
	out = append(out, snapshotFindings...)
	out = append(out, d.findings...)
	sort.Strings(out)
	return out
}

func (d *runDaemon) clearFindings() {
	d.findings = nil
}

func startRunStatusServer(ctx context.Context, listen string, store actionstate.Store, statePath string, registry kliqruntime.AdapterRuntimeRegistry) (*http.Server, error) {
	if err := validateLocalListenAddress(listen); err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:    listen,
		Handler: statusAPIHandler(store, statePath, registry),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		logInfo("kliq_status_api_starting", "addr", listen, "state", statePath)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logError("kliq_status_api_failed", "error", err.Error())
		}
	}()
	return server, nil
}

func newTicker(interval time.Duration) *time.Ticker {
	if interval <= 0 {
		interval = time.Minute
	}
	return time.NewTicker(interval)
}

func adapterRegistryFromFlags(values []string) (kliqruntime.AdapterRuntimeRegistry, func(), error) {
	if len(values) == 0 {
		return nil, func() {}, nil
	}
	entries := make([]kliqruntime.StaticAdapterRuntimeEntry, 0, len(values))
	var conns []*grpc.ClientConn
	closeFn := func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}
	for _, value := range values {
		adapterID, addr, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(adapterID) == "" || strings.TrimSpace(addr) == "" {
			closeFn()
			return nil, func() {}, fmt.Errorf("adapter must be adapter_id=host:port")
		}
		conn, err := grpc.NewClient(strings.TrimSpace(addr), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			closeFn()
			return nil, func() {}, err
		}
		conns = append(conns, conn)
		entries = append(entries, kliqruntime.StaticAdapterRuntimeEntry{
			AdapterID: strings.TrimSpace(adapterID),
			Executor:  kliqruntime.NewAdapterRuntimeExecutor(conn),
		})
	}
	registry := kliqruntime.NewStaticAdapterRuntimeRegistry(entries...)
	return registry, closeFn, nil
}

func resolveStandaloneBundlePath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return path, nil
	}
	candidates, err := filepath.Glob(filepath.Join(path, "*.runtime_bundle.signed.json"))
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		defaultPath := filepath.Join(path, "runtime_bundle.signed.json")
		if _, err := os.Stat(defaultPath); err == nil {
			return defaultPath, nil
		}
		return "", fmt.Errorf("standalone bundle directory %q does not contain a signed runtime bundle", path)
	}
	sort.Strings(candidates)
	return candidates[0], nil
}

func adapterHealthSummary(adapters []adapterStatusView) []string {
	if len(adapters) == 0 {
		return nil
	}
	summary := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		status := adapter.Health
		if status == "" {
			status = "unknown"
		}
		if adapter.Registered {
			summary = append(summary, fmt.Sprintf("%s:%s", adapter.AdapterID, status))
			continue
		}
		summary = append(summary, fmt.Sprintf("%s:unregistered:%s", adapter.AdapterID, status))
	}
	sort.Strings(summary)
	return summary
}

func runtimeSummary(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, ",")
}

func auditSpoolState(pending int) string {
	if pending == 0 {
		return "empty"
	}
	return fmt.Sprintf("pending_upload:%d", pending)
}
