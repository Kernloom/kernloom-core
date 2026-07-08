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

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
	"github.com/kernloom/kernloom-core/internal/kliq/localrisk"
	kliqruntime "github.com/kernloom/kernloom-core/internal/kliq/runtime"
	"github.com/kernloom/kernloom-core/internal/kliq/signals/projector"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
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
	Mode                      string
	StatePath                 string
	TrustBundlePath           string
	DevAllowPrivateKey        bool
	ForgeURL                  string
	BundleSource              string
	StatusListen              string
	PollInterval              time.Duration
	HeartbeatInterval         time.Duration
	StatusInterval            time.Duration
	DecisionInterval          time.Duration
	SignalInterval            time.Duration
	ReconcileInterval         time.Duration
	AuditFlushInterval        time.Duration
	DecisionSource            string
	BaselineRiskRecipe        string
	BaselineMinSamples        int
	Once                      bool
	Production                bool
	Adapters                  []string
	HTTPClient                *http.Client
	DevInsecureForgeTransport bool
	ForgeTransport            forgeTransportOptions
	AdapterTransport          adapterTransportOptions
}

type runDaemon struct {
	opts                 runOptions
	store                *actionstate.SQLiteStore
	manager              kliqruntime.Manager
	credential           actionstate.KLIQCredential
	httpClient           *http.Client
	now                  func() time.Time
	decisions            RuntimeDecisionSource
	signalReaders        map[string]AdapterSignalReader
	baselineSamples      map[string][]baseline.Sample
	findings             []string
	closeManagedAdapters func()
}

type RuntimeDecisionSource interface {
	NextDecision(ctx context.Context) (kliqruntime.ExecuteRequest, bool, error)
}

type AdapterSignalReader interface {
	ReadSignals(ctx context.Context, scope string) ([]baseline.AdapterSignal, error)
}

type grpcAdapterSignalReader struct {
	adapterID string
	client    adapterv1.AdapterServiceClient
	now       func() time.Time
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
	fs.DurationVar(&opts.SignalInterval, "signal-interval", 30*time.Second, "adapter signal ingestion interval")
	fs.DurationVar(&opts.ReconcileInterval, "reconcile-interval", 30*time.Second, "runtime action lease reconciliation interval")
	fs.DurationVar(&opts.AuditFlushInterval, "audit-flush-interval", time.Minute, "audit spool flush interval")
	fs.StringVar(&opts.DecisionSource, "decision-source", "", "optional local runtime decision source file; JSON object or array of local runtime events or debug execute-action requests")
	fs.StringVar(&opts.BaselineRiskRecipe, "baseline-risk-recipe", "runtime_anomaly.standard", "local baseline risk recipe id for adapter signal deviations")
	fs.IntVar(&opts.BaselineMinSamples, "baseline-min-samples", 5, "minimum clean samples before writing a frozen baseline version")
	fs.BoolVar(&opts.Once, "once", false, "run one daemon cycle and exit; intended for smoke tests")
	fs.BoolVar(&opts.Production, "production", false, "enforce production-safe managed daemon gates")
	fs.Var(&adapters, "adapter", "dev/bootstrap adapter runtime endpoint as adapter_id=host:port; repeatable; managed production should prefer adapter_assignment artifacts")
	fs.BoolVar(&opts.DevInsecureForgeTransport, "dev-insecure-forge-transport", false, "allow plaintext http Forge transport; dev/smoke only")
	fs.StringVar(&opts.ForgeTransport.CAPath, "forge-ca", "", "Forge HTTPS CA bundle")
	fs.StringVar(&opts.ForgeTransport.ClientCertPath, "forge-client-cert", "", "Forge mTLS client certificate")
	fs.StringVar(&opts.ForgeTransport.ClientKeyPath, "forge-client-key", "", "Forge mTLS client private key")
	fs.StringVar(&opts.ForgeTransport.ServerName, "forge-server-name", "", "expected Forge TLS server name")
	fs.StringVar(&opts.ForgeTransport.ServerCertificateSHA256, "forge-cert-sha256", "", "expected Forge leaf certificate SHA-256 pin")
	fs.BoolVar(&opts.AdapterTransport.DevInsecureAdapterTransport, "dev-insecure-adapter-transport", false, "allow plaintext adapter gRPC transport; dev/smoke only")
	fs.StringVar(&opts.AdapterTransport.CAPath, "adapter-ca", "", "adapter mTLS CA bundle")
	fs.StringVar(&opts.AdapterTransport.ClientCertPath, "adapter-client-cert", "", "adapter mTLS client certificate")
	fs.StringVar(&opts.AdapterTransport.ClientKeyPath, "adapter-client-key", "", "adapter mTLS client private key")
	fs.StringVar(&opts.AdapterTransport.ServerName, "adapter-server-name", "", "expected adapter TLS server name")
	fs.StringVar(&opts.AdapterTransport.ServerCertificateSHA256, "adapter-server-cert-sha256", "", "expected adapter leaf certificate SHA-256 pin")
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
	if opts.Production {
		if err := validateKLIQProductionOptions(opts); err != nil {
			return err
		}
	}
	store, err := actionstate.OpenSQLite(opts.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()
	verifier, trustBundle, err := loadTrustVerifierForStore(ctx, opts.TrustBundlePath, opts.DevAllowPrivateKey, store)
	if err != nil {
		return err
	}
	registry, signalReaders, closeAdapters, err := adapterRegistryAndSignalsFromFlags(opts.Adapters, opts.AdapterTransport)
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
	daemon.signalReaders = signalReaders
	daemon.baselineSamples = map[string][]baseline.Sample{}
	defer func() {
		if daemon.closeManagedAdapters != nil {
			daemon.closeManagedAdapters()
		}
	}()
	if opts.HTTPClient != nil {
		daemon.httpClient = opts.HTTPClient
	} else {
		httpClient, err := forgeHTTPClient(opts.ForgeTransport)
		if err != nil {
			return err
		}
		daemon.httpClient = httpClient
	}
	if opts.DecisionSource != "" {
		source, err := runtimeDecisionSourceFromFile(opts.DecisionSource)
		if err != nil {
			return err
		}
		daemon.decisions = source
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
		if err := validateSecureForgeURL(credential.AssignmentURL, opts.DevInsecureForgeTransport); err != nil {
			return err
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

func validateKLIQProductionOptions(opts runOptions) error {
	if opts.Mode != kliqRunModeManaged {
		return fmt.Errorf("production KLIQ requires --mode managed")
	}
	if opts.Once {
		return fmt.Errorf("production KLIQ forbids --once")
	}
	if opts.DevAllowPrivateKey {
		return fmt.Errorf("production KLIQ forbids --dev-allow-private-trust-key")
	}
	if opts.DevInsecureForgeTransport {
		return fmt.Errorf("production KLIQ forbids --dev-insecure-forge-transport")
	}
	if opts.AdapterTransport.DevInsecureAdapterTransport {
		return fmt.Errorf("production KLIQ forbids --dev-insecure-adapter-transport")
	}
	if strings.TrimSpace(opts.DecisionSource) != "" {
		return fmt.Errorf("production KLIQ forbids local --decision-source")
	}
	if len(opts.Adapters) != 0 {
		return fmt.Errorf("production KLIQ forbids bootstrap --adapter endpoints; use signed adapter_assignment artifacts")
	}
	if err := validateSecureForgeURL(opts.ForgeURL, false); err != nil {
		return err
	}
	return nil
}

func (d *runDaemon) runOnce(ctx context.Context) error {
	if err := d.loadOrPoll(ctx); err != nil {
		return err
	}
	if err := d.processAdapterSignals(ctx); err != nil {
		logError("adapter_signal_ingestion_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
		d.recordFinding("adapter signal ingestion failed: " + err.Error())
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
	signalTicker := newTicker(d.opts.SignalInterval)
	reconcileTicker := newTicker(d.opts.ReconcileInterval)
	auditTicker := newTicker(d.opts.AuditFlushInterval)
	defer pollTicker.Stop()
	defer heartbeatTicker.Stop()
	defer statusTicker.Stop()
	defer decisionTicker.Stop()
	defer signalTicker.Stop()
	defer reconcileTicker.Stop()
	defer auditTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pollTicker.C:
			if err := d.loadOrPoll(ctx); err != nil {
				logError("assignment_poll_failed", "mode", d.opts.Mode, "kliq_id", d.credential.KLIQID, "error", err.Error())
			} else {
				resetTicker(pollTicker, d.opts.PollInterval)
				resetTicker(heartbeatTicker, d.opts.HeartbeatInterval)
				resetTicker(statusTicker, d.opts.StatusInterval)
				resetTicker(decisionTicker, d.opts.DecisionInterval)
				resetTicker(signalTicker, d.opts.SignalInterval)
				resetTicker(reconcileTicker, d.opts.ReconcileInterval)
				resetTicker(auditTicker, d.opts.AuditFlushInterval)
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
		case <-signalTicker.C:
			if err := d.processAdapterSignals(ctx); err != nil {
				logError("adapter_signal_ingestion_failed", "kliq_id", d.credential.KLIQID, "error", err.Error())
				d.recordFinding("adapter signal ingestion failed: " + err.Error())
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
	if err := d.activateManagedArtifacts(ctx); err != nil {
		d.recordFinding("managed assignment artifact activation failed: " + err.Error())
		logError("managed_assignment_artifact_activation_failed", "kliq_id", d.credential.KLIQID, "assignment_id", state.ActiveAssignmentID, "error", err.Error())
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
	return d.postManagedJSONResponse(ctx, path, value, nil)
}

func (d *runDaemon) postManagedJSONResponse(ctx context.Context, path string, value any, response any) error {
	if err := d.ensureServiceTokenFresh(ctx); err != nil {
		return err
	}
	if err := validateSecureForgeURL(d.credential.AssignmentURL, d.opts.DevInsecureForgeTransport); err != nil {
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
	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return err
		}
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
	if d.opts.Mode != kliqRunModeManaged {
		if len(records) > 0 {
			message := "standalone audit spool is local/offline only; use `kliq audit export` for controlled evidence export"
			d.recordFinding(message)
			logInfo("standalone_audit_spool_export_required", "pending", len(records), "mode", d.opts.Mode)
		}
		return nil
	}
	for _, record := range records {
		if !auditRetryDue(record, d.now().UTC()) {
			continue
		}
		uploadedAt := d.now().UTC()
		payloadSHA256 := record.PayloadSHA256
		if payloadSHA256 == "" {
			payloadSHA256 = domain.SHA256JSON([]byte(record.Payload))
		}
		upload := domain.KLIQAuditUpload{
			KLIQID:          d.credential.KLIQID,
			Environment:     d.credential.Environment,
			Stage:           d.credential.Stage,
			Scope:           d.credential.Scope,
			AuditRecordID:   record.ID,
			RuntimeActionID: record.RuntimeActionID,
			Payload:         []byte(record.Payload),
			PayloadSHA256:   payloadSHA256,
			CreatedAt:       record.CreatedAt,
			UploadedAt:      uploadedAt,
		}
		var ack domain.KLIQAuditUploadAck
		if err := d.postManagedJSONResponse(ctx, "/v1/kliq/audit-events", upload, &ack); err != nil {
			_ = d.store.MarkAuditFailed(ctx, record.ID, uploadedAt, err.Error())
			logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "audit_record_id", record.ID, "runtime_action_id", record.RuntimeActionID, "error", err.Error())
			continue
		}
		if ack.Status != "accepted" || ack.AuditRecordID != record.ID || ack.AckID == "" {
			message := "forge audit upload acknowledgement invalid"
			_ = d.store.MarkAuditFailed(ctx, record.ID, uploadedAt, message)
			logError("audit_flush_failed", "kliq_id", d.credential.KLIQID, "audit_record_id", record.ID, "runtime_action_id", record.RuntimeActionID, "error", message)
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

func auditRetryDue(record actionstate.AuditRecord, now time.Time) bool {
	if record.RetryCount <= 0 || record.LastAttemptAt.IsZero() {
		return true
	}
	backoff := time.Second * time.Duration(1<<min(record.RetryCount-1, 8))
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}
	return !now.Before(record.LastAttemptAt.Add(backoff))
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

func (d *runDaemon) processAdapterSignals(ctx context.Context) error {
	if len(d.signalReaders) == 0 {
		return nil
	}
	recipe, err := localBaselineRiskRecipe(d.opts.BaselineRiskRecipe)
	if err != nil {
		return err
	}
	scope := strings.TrimSpace(d.credential.Scope)
	if scope == "" {
		scope = "local_node"
	}
	for adapterID, reader := range d.signalReaders {
		if reader == nil {
			continue
		}
		signals, err := reader.ReadSignals(ctx, scope)
		if err != nil {
			d.recordFinding("adapter signal read failed for " + adapterID + ": " + err.Error())
			continue
		}
		for _, signal := range signals {
			if signal.ObservedAt.IsZero() {
				signal.ObservedAt = d.daemonNow()
			}
			if err := d.processAdapterSignal(ctx, recipe, signal); err != nil {
				d.recordFinding("adapter signal processing failed for " + adapterID + ": " + err.Error())
				logError("adapter_signal_processing_failed", "kliq_id", d.credential.KLIQID, "adapter_id", adapterID, "signal_id", signal.SignalID, "error", err.Error())
			}
		}
	}
	return nil
}

func (d *runDaemon) processAdapterSignal(ctx context.Context, recipe registry.RiskRecipe, signal baseline.AdapterSignal) error {
	var signalProjector baseline.SignalProjector
	switch strings.TrimSpace(signal.AdapterID) {
	case projector.KLShieldAdapterID:
		signalProjector = projector.KLShieldProjector{}
	default:
		return nil
	}
	samples, err := signalProjector.Project(signal)
	if err != nil {
		return err
	}
	engine := baseline.Engine{
		Store:      d.store,
		Estimator:  baseline.MedianMADEstimator{MinSamples: d.baselineMinSamples()},
		Now:        d.daemonNow,
		MinSamples: d.baselineMinSamples(),
	}
	evaluator := localrisk.Evaluator{Store: d.store, Now: d.daemonNow}
	for _, sample := range samples {
		if err := d.evaluateBaselineSample(ctx, evaluator, recipe, sample); err != nil {
			return err
		}
		if err := d.learnBaselineSample(ctx, engine, sample); err != nil {
			return err
		}
	}
	return nil
}

func (d *runDaemon) evaluateBaselineSample(ctx context.Context, evaluator localrisk.Evaluator, recipe registry.RiskRecipe, sample baseline.Sample) error {
	version, ok, err := d.store.ActiveBaselineVersion(ctx, sample.Key.View, sample.Key.Entity)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	stats, err := d.store.BaselineStats(ctx, version.VersionID, sample.Metric)
	if err != nil {
		return err
	}
	event, deviates := baseline.EvaluateSample(sample, stats, d.daemonNow())
	if !deviates {
		return nil
	}
	event.RiskRecipe = recipe.ID
	event.PolicyScope = d.credential.Scope
	if err := d.store.SaveBaselineDeviation(ctx, event); err != nil {
		return err
	}
	riskContext, err := evaluator.EvaluateDeviation(ctx, recipe, event)
	if err != nil {
		return err
	}
	logInfo("baseline_deviation_risk_cached", "kliq_id", d.credential.KLIQID, "event_id", event.EventID, "risk_type", riskContext.RiskType, "risk_tier", riskContext.Tier, "scope", riskContext.Scope)
	return nil
}

func (d *runDaemon) learnBaselineSample(ctx context.Context, engine baseline.Engine, sample baseline.Sample) error {
	key := baselineSampleBufferKey(sample)
	if d.baselineSamples == nil {
		d.baselineSamples = map[string][]baseline.Sample{}
	}
	buffer := append(d.baselineSamples[key], sample)
	minSamples := d.baselineMinSamples()
	if len(buffer) < minSamples {
		d.baselineSamples[key] = buffer
		return nil
	}
	_, _, learned, err := engine.LearnWindow(ctx, buffer, 0.90, 0.0, true, false)
	if err != nil {
		return err
	}
	if learned {
		logInfo("baseline_version_frozen", "kliq_id", d.credential.KLIQID, "view", sample.Key.View, "entity", redactID(sample.Key.Entity), "metric", sample.Metric, "sample_count", len(buffer))
	}
	delete(d.baselineSamples, key)
	return nil
}

func (d *runDaemon) baselineMinSamples() int {
	if d.opts.BaselineMinSamples > 0 {
		return d.opts.BaselineMinSamples
	}
	return 5
}

func (d *runDaemon) daemonNow() time.Time {
	if d.now != nil {
		return d.now().UTC()
	}
	return time.Now().UTC()
}

func baselineSampleBufferKey(sample baseline.Sample) string {
	return sample.Key.View + "\x00" + sample.Key.Entity + "\x00" + sample.Metric
}

func localBaselineRiskRecipe(recipeID string) (registry.RiskRecipe, error) {
	recipeID = strings.TrimSpace(recipeID)
	if recipeID == "" {
		recipeID = "runtime_anomaly.standard"
	}
	if recipeID != "runtime_anomaly.standard" {
		return registry.RiskRecipe{}, fmt.Errorf("unsupported local baseline risk recipe %q", recipeID)
	}
	return registry.RiskRecipe{
		ID:     "runtime_anomaly.standard",
		Output: map[string]string{"risk_type": "runtime_anomaly"},
		Scoring: map[string]string{
			"method":      "weighted_sum",
			"score_range": "0-100",
		},
		Thresholds: map[string]string{
			"low":      "score < 30",
			"medium":   "score >= 30 && score < 70",
			"high":     "score >= 70 && score < 90",
			"critical": "score >= 90",
		},
		Confidence: map[string]string{"minimum_for_enforcement": "0.70"},
		Freshness:  map[string]string{"max_age": "2m", "stale_behavior": "unknown"},
	}, nil
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
	if strings.EqualFold(strings.TrimSpace(d.credential.CredentialStatus), "revoked") {
		return fmt.Errorf("local KLIQ service credential is revoked")
	}
	if d.credential.ServiceToken == "" {
		return fmt.Errorf("managed mode requires local KLIQ service token")
	}
	if d.credential.ServiceTokenExpiresAt.IsZero() {
		return nil
	}
	now := d.now().UTC()
	if !now.Before(d.credential.ServiceTokenExpiresAt.UTC()) {
		if isKLIQIdentitySignedToken(d.credential.ServiceToken) {
			return d.refreshLocalIdentityServiceToken(ctx)
		}
		return fmt.Errorf("local KLIQ service token is expired")
	}
	if d.credential.ServiceTokenExpiresAt.UTC().Sub(now) <= 5*time.Minute {
		if isKLIQIdentitySignedToken(d.credential.ServiceToken) {
			return d.refreshLocalIdentityServiceToken(ctx)
		}
		return d.refreshServiceToken(ctx)
	}
	return nil
}

func isKLIQIdentitySignedToken(token string) bool {
	return strings.HasPrefix(token, "kliqsig.")
}

func (d *runDaemon) refreshLocalIdentityServiceToken(ctx context.Context) error {
	identity := domain.KLIQIdentity{
		KLIQID:                  d.credential.KLIQID,
		NodeID:                  d.credential.NodeID,
		Environment:             d.credential.Environment,
		Stage:                   d.credential.Stage,
		Scope:                   d.credential.Scope,
		TrustKeyID:              d.credential.TrustKeyID,
		PublicKeyPEM:            d.credential.PublicKeyPEM,
		ServiceIdentityProvider: d.credential.ServiceIdentityProvider,
		SPIFFEID:                d.credential.SPIFFEID,
		CredentialStatus:        d.credential.CredentialStatus,
	}
	token, err := authn.IssueKLIQIdentitySignedToken(identity, d.credential.PrivateKeyPEM, 24*time.Hour, d.now)
	if err != nil {
		return err
	}
	expiresAt, err := serviceTokenExpiresAt(token)
	if err != nil {
		return err
	}
	d.credential.ServiceToken = token
	d.credential.ServiceTokenExpiresAt = expiresAt
	d.credential.UpdatedAt = d.now().UTC()
	if err := d.store.SaveKLIQCredential(ctx, d.credential); err != nil {
		return err
	}
	logInfo("local_kliq_identity_service_token_refreshed", "kliq_id", d.credential.KLIQID, "expires_at", expiresAt.Format(time.RFC3339))
	return nil
}

func (d *runDaemon) refreshServiceToken(ctx context.Context) error {
	if err := validateSecureForgeURL(d.credential.AssignmentURL, d.opts.DevInsecureForgeTransport); err != nil {
		return err
	}
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
	if strings.TrimSpace(d.credential.CredentialStatus) == "" {
		d.credential.CredentialStatus = "active"
	}
	d.credential.UpdatedAt = d.now().UTC()
	if err := d.store.SaveKLIQCredential(ctx, d.credential); err != nil {
		return err
	}
	logInfo("service_token_refreshed", "kliq_id", d.credential.KLIQID, "expires_at", expiresAt.Format(time.RFC3339))
	return nil
}

func (d *runDaemon) activateManagedArtifacts(ctx context.Context) error {
	if err := d.applyManagedManagementProfile(ctx); err != nil {
		return err
	}
	artifacts, err := d.store.AssignmentArtifacts(ctx, d.credential.KLIQID)
	if err != nil {
		return err
	}
	assignments := make([]domain.AdapterAssignment, 0)
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
		assignments = append(assignments, assignment)
	}
	if len(assignments) == 0 {
		return nil
	}
	registry, signalReaders, closeFn, err := adapterRegistryAndSignalsFromAssignments(assignments, d.opts.AdapterTransport)
	if err != nil {
		return err
	}
	if d.closeManagedAdapters != nil {
		d.closeManagedAdapters()
	}
	d.closeManagedAdapters = closeFn
	d.manager.Registry = registry
	d.signalReaders = signalReaders
	logInfo("adapter_assignment_activated", "kliq_id", d.credential.KLIQID, "adapters", strings.Join(adapterAssignmentLogValues(assignments), ","))
	return nil
}

func (d *runDaemon) applyManagedManagementProfile(ctx context.Context) error {
	record, err := d.store.ActiveArtifact(ctx, d.credential.KLIQID, "management_profile")
	if errors.Is(err, actionstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var profile domain.KLIQManagementProfile
	if err := json.Unmarshal(record.PayloadJSON, &profile); err != nil {
		return err
	}
	if interval, ok, err := profileDuration(profile.PollInterval, "poll_interval"); err != nil {
		return err
	} else if ok {
		d.opts.PollInterval = interval
	}
	if interval, ok, err := profileDuration(profile.HeartbeatInterval, "heartbeat_interval"); err != nil {
		return err
	} else if ok {
		d.opts.HeartbeatInterval = interval
	}
	if interval, ok, err := profileDuration(profile.StatusInterval, "status_interval"); err != nil {
		return err
	} else if ok {
		d.opts.StatusInterval = interval
	}
	if interval, ok, err := profileDuration(profile.DecisionInterval, "decision_interval"); err != nil {
		return err
	} else if ok {
		d.opts.DecisionInterval = interval
	}
	if interval, ok, err := profileDuration(profile.ReconcileInterval, "reconcile_interval"); err != nil {
		return err
	} else if ok {
		d.opts.ReconcileInterval = interval
	}
	if interval, ok, err := profileDuration(profile.AuditFlushInterval, "audit_flush_interval"); err != nil {
		return err
	} else if ok {
		d.opts.AuditFlushInterval = interval
	}
	logInfo("management_profile_activated", "kliq_id", d.credential.KLIQID, "profile_id", profile.ProfileID, "poll_interval", d.opts.PollInterval.String(), "heartbeat_interval", d.opts.HeartbeatInterval.String(), "status_interval", d.opts.StatusInterval.String())
	return nil
}

func profileDuration(value, field string) (time.Duration, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, false, fmt.Errorf("invalid management profile %s %q: %w", field, value, err)
	}
	if parsed <= 0 {
		return 0, false, fmt.Errorf("management profile %s must be positive", field)
	}
	return parsed, true, nil
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

func resetTicker(ticker *time.Ticker, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker.Reset(interval)
}

type fileRuntimeDecisionSource struct {
	requests []kliqruntime.ExecuteRequest
	index    int
}

type localRuntimeEvent struct {
	Kind                  string `json:"kind,omitempty"`
	EventID               string `json:"event_id,omitempty"`
	EventType             string `json:"event_type,omitempty"`
	SignalID              string `json:"signal_id,omitempty"`
	RiskType              string `json:"risk_type,omitempty"`
	AdapterID             string `json:"adapter_id"`
	CapabilityID          string `json:"capability_id"`
	CapabilityGrantID     string `json:"capability_grant_id"`
	BindingID             string `json:"binding_id,omitempty"`
	BindingDigest         string `json:"binding_digest,omitempty"`
	AdapterManifestDigest string `json:"adapter_manifest_digest,omitempty"`
	ActionDigest          string `json:"action_digest,omitempty"`
	Mode                  string `json:"mode,omitempty"`
	ActionType            string `json:"action_type"`
	TargetScope           string `json:"target_scope,omitempty"`
	TargetKey             string `json:"target_key"`
	TTL                   string `json:"ttl,omitempty"`
	Reason                string `json:"reason,omitempty"`
	AuditID               string `json:"audit_id,omitempty"`
	CorrelationID         string `json:"correlation_id,omitempty"`
}

func runtimeDecisionSourceFromFile(path string) (*fileRuntimeDecisionSource, error) {
	path = strings.TrimSpace(strings.TrimPrefix(path, "file://"))
	if path == "" {
		return nil, fmt.Errorf("decision source path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return &fileRuntimeDecisionSource{}, nil
	}
	var raws []json.RawMessage
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &raws); err != nil {
			return nil, err
		}
	} else {
		raws = append(raws, json.RawMessage(trimmed))
	}
	requests := make([]kliqruntime.ExecuteRequest, 0, len(raws))
	for _, raw := range raws {
		request, err := runtimeDecisionRequestFromJSON(raw)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return &fileRuntimeDecisionSource{requests: requests}, nil
}

func runtimeDecisionRequestFromJSON(raw json.RawMessage) (kliqruntime.ExecuteRequest, error) {
	var probe struct {
		Kind      string `json:"kind"`
		EventID   string `json:"event_id"`
		EventType string `json:"event_type"`
		SignalID  string `json:"signal_id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return kliqruntime.ExecuteRequest{}, err
	}
	if probe.Kind == "LocalRuntimeEvent" || probe.Kind == "RuntimeEvent" || probe.EventID != "" || probe.EventType != "" || probe.SignalID != "" {
		var event localRuntimeEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return kliqruntime.ExecuteRequest{}, err
		}
		return executeRequestFromLocalRuntimeEvent(event, raw), nil
	}
	var request kliqruntime.ExecuteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return kliqruntime.ExecuteRequest{}, err
	}
	return request, nil
}

func executeRequestFromLocalRuntimeEvent(event localRuntimeEvent, raw []byte) kliqruntime.ExecuteRequest {
	eventID := firstNonEmpty(event.EventID, event.SignalID, redactedHash(string(raw)))
	decisionID := "runtime_decision." + strings.TrimPrefix(redactedHash(eventID), "sha256:")
	mode := event.Mode
	if strings.TrimSpace(mode) == "" {
		mode = kliqruntime.ActionModeRequired
	}
	reason := strings.TrimSpace(event.Reason)
	if reason == "" {
		reason = "local runtime event " + eventID
	}
	auditID := strings.TrimSpace(event.AuditID)
	if auditID == "" {
		auditID = "audit." + strings.TrimPrefix(redactedHash(decisionID), "sha256:")
	}
	return kliqruntime.ExecuteRequest{
		DecisionID:            decisionID,
		EventType:             event.EventType,
		EventID:               eventID,
		RiskType:              event.RiskType,
		AdapterID:             event.AdapterID,
		CapabilityID:          event.CapabilityID,
		CapabilityGrantID:     event.CapabilityGrantID,
		BindingID:             event.BindingID,
		BindingDigest:         event.BindingDigest,
		AdapterManifestDigest: event.AdapterManifestDigest,
		ActionDigest:          event.ActionDigest,
		Mode:                  mode,
		ActionType:            event.ActionType,
		TargetScope:           event.TargetScope,
		TargetKey:             event.TargetKey,
		TTL:                   event.TTL,
		Reason:                reason,
		AuditID:               auditID,
		CorrelationID:         event.CorrelationID,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *fileRuntimeDecisionSource) NextDecision(_ context.Context) (kliqruntime.ExecuteRequest, bool, error) {
	if s == nil || s.index >= len(s.requests) {
		return kliqruntime.ExecuteRequest{}, false, nil
	}
	request := s.requests[s.index]
	s.index++
	return request, true, nil
}

func adapterRegistryFromFlags(values []string, transport adapterTransportOptions) (kliqruntime.AdapterRuntimeRegistry, func(), error) {
	registry, _, closeFn, err := adapterRegistryAndSignalsFromFlags(values, transport)
	return registry, closeFn, err
}

func adapterRegistryAndSignalsFromFlags(values []string, transport adapterTransportOptions) (kliqruntime.AdapterRuntimeRegistry, map[string]AdapterSignalReader, func(), error) {
	if len(values) == 0 {
		return nil, nil, func() {}, nil
	}
	entries := make([]kliqruntime.StaticAdapterRuntimeEntry, 0, len(values))
	signalReaders := map[string]AdapterSignalReader{}
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
			return nil, nil, func() {}, fmt.Errorf("adapter must be adapter_id=host:port")
		}
		dialOptions, err := adapterDialOptions(transport)
		if err != nil {
			closeFn()
			return nil, nil, func() {}, err
		}
		conn, err := grpc.NewClient(strings.TrimSpace(addr), dialOptions...)
		if err != nil {
			closeFn()
			return nil, nil, func() {}, err
		}
		adapterID = strings.TrimSpace(adapterID)
		client := adapterv1.NewAdapterServiceClient(conn)
		conns = append(conns, conn)
		entries = append(entries, kliqruntime.StaticAdapterRuntimeEntry{
			AdapterID: adapterID,
			Executor:  kliqruntime.NewAdapterRuntimeExecutor(conn),
		})
		signalReaders[adapterID] = grpcAdapterSignalReader{adapterID: adapterID, client: client}
	}
	registry := kliqruntime.NewStaticAdapterRuntimeRegistry(entries...)
	return registry, signalReaders, closeFn, nil
}

func adapterRegistryFromAssignments(assignments []domain.AdapterAssignment, transport adapterTransportOptions) (kliqruntime.AdapterRuntimeRegistry, func(), error) {
	registry, _, closeFn, err := adapterRegistryAndSignalsFromAssignments(assignments, transport)
	return registry, closeFn, err
}

func adapterRegistryAndSignalsFromAssignments(assignments []domain.AdapterAssignment, transport adapterTransportOptions) (kliqruntime.AdapterRuntimeRegistry, map[string]AdapterSignalReader, func(), error) {
	entries := make([]kliqruntime.StaticAdapterRuntimeEntry, 0, len(assignments))
	signalReaders := map[string]AdapterSignalReader{}
	var conns []*grpc.ClientConn
	closeFn := func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}
	for _, assignment := range assignments {
		adapterID := strings.TrimSpace(assignment.AdapterID)
		endpoint := strings.TrimSpace(assignment.Endpoint)
		if adapterID == "" || endpoint == "" {
			closeFn()
			return nil, nil, func() {}, fmt.Errorf("adapter assignment requires adapter_id and endpoint")
		}
		adapterTransport := adapterTransportForAssignment(transport, assignment)
		dialOptions, err := adapterDialOptions(adapterTransport)
		if err != nil {
			closeFn()
			return nil, nil, func() {}, err
		}
		conn, err := grpc.NewClient(endpoint, dialOptions...)
		if err != nil {
			closeFn()
			return nil, nil, func() {}, err
		}
		client := adapterv1.NewAdapterServiceClient(conn)
		conns = append(conns, conn)
		entries = append(entries, kliqruntime.StaticAdapterRuntimeEntry{
			AdapterID: adapterID,
			Executor:  kliqruntime.NewAdapterRuntimeExecutor(conn),
		})
		signalReaders[adapterID] = grpcAdapterSignalReader{adapterID: adapterID, client: client}
	}
	return kliqruntime.NewStaticAdapterRuntimeRegistry(entries...), signalReaders, closeFn, nil
}

func (r grpcAdapterSignalReader) ReadSignals(ctx context.Context, scope string) ([]baseline.AdapterSignal, error) {
	if r.client == nil {
		return nil, fmt.Errorf("adapter signal reader %q has no client", r.adapterID)
	}
	resp, err := r.client.ReadSignals(ctx, &adapterv1.ReadSignalsRequest{Scope: scope})
	if err != nil {
		return nil, err
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	signals := make([]baseline.AdapterSignal, 0, len(resp.GetSignals()))
	for _, signal := range resp.GetSignals() {
		converted, err := baselineSignalFromProto(signal, now().UTC())
		if err != nil {
			return nil, err
		}
		if converted.AdapterID == "" {
			converted.AdapterID = r.adapterID
		}
		signals = append(signals, converted)
	}
	return signals, nil
}

func baselineSignalFromProto(signal *adapterv1.Signal, observedAt time.Time) (baseline.AdapterSignal, error) {
	if signal == nil {
		return baseline.AdapterSignal{}, fmt.Errorf("adapter signal is nil")
	}
	labels := map[string]string{
		"entity": signal.GetScope(),
		"scope":  signal.GetScope(),
	}
	metrics := map[string]float64{}
	if len(signal.GetPayload()) > 0 {
		var payload map[string]any
		decoder := json.NewDecoder(bytes.NewReader(signal.GetPayload()))
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			return baseline.AdapterSignal{}, err
		}
		for key, value := range payload {
			if number, ok := numericMetric(value); ok {
				metrics[key] = number
				continue
			}
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				labels[key] = strings.TrimSpace(text)
			}
		}
	}
	return baseline.AdapterSignal{
		SignalID:   signal.GetId(),
		AdapterID:  signal.GetSource(),
		SignalType: signal.GetType(),
		Labels:     labels,
		Metrics:    metrics,
		ObservedAt: observedAt.UTC(),
	}, nil
}

func numericMetric(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	default:
		return 0, false
	}
}

func adapterTransportForAssignment(transport adapterTransportOptions, assignment domain.AdapterAssignment) adapterTransportOptions {
	adapterTransport := transport
	if serverName := strings.TrimSpace(assignment.TLSServerName); serverName != "" {
		adapterTransport.ServerName = serverName
	}
	if certPin := strings.TrimSpace(assignment.ServerCertificateSHA256); certPin != "" {
		adapterTransport.ServerCertificateSHA256 = certPin
	}
	return adapterTransport
}

func adapterAssignmentLogValues(assignments []domain.AdapterAssignment) []string {
	values := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		values = append(values, strings.TrimSpace(assignment.AdapterID)+"="+strings.TrimSpace(assignment.Endpoint))
	}
	return values
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
