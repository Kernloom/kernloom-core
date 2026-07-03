// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqbundle "github.com/kernloom/kernloom-core/internal/kliq/bundle"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
)

func TestAdapterRuntimeExecutorExecutesRuntimeAction(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{executeStatus: string(domain.RuntimeActionActive)}
	executor := AdapterRuntimeExecutor{Client: client}
	lease := testLease(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))

	if err := executor.Execute(ctx, lease, []byte(`{"kind":"SignedEnvelope"}`)); err != nil {
		t.Fatal(err)
	}
	if client.executeRequest.GetRuntimeActionId() != lease.RuntimeActionID {
		t.Fatalf("runtime action id was not forwarded, got %#v", client.executeRequest)
	}
	if client.executeRequest.GetIdempotencyKey() != lease.IdempotencyKey {
		t.Fatalf("idempotency key was not forwarded, got %#v", client.executeRequest)
	}
	if client.executeRequest.GetAdapterId() != lease.AdapterID ||
		client.executeRequest.GetCapabilityId() != lease.CapabilityID ||
		client.executeRequest.GetCorrelationId() != lease.CorrelationID {
		t.Fatalf("adapter-aware execution metadata was not forwarded, got %#v", client.executeRequest)
	}
	if string(client.executeRequest.GetSignedBundle()) == "" {
		t.Fatal("expected signed bundle to be forwarded")
	}
}

func TestAdapterRuntimeExecutorRejectsNonActiveExecuteStatus(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{executeStatus: string(domain.RuntimeActionUnknown)}
	executor := AdapterRuntimeExecutor{Client: client}

	err := executor.Execute(ctx, testLease(time.Now()), []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected non-active execute status to fail, got %v", err)
	}
}

func TestAdapterRuntimeExecutorCleanup(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{revokeStatus: string(domain.RuntimeActionExpired)}
	executor := AdapterRuntimeExecutor{Client: client}
	lease := testLease(time.Now())

	if err := executor.Cleanup(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if client.revokeRequest.GetIdempotencyKey() != lease.IdempotencyKey {
		t.Fatalf("idempotency key was not forwarded, got %#v", client.revokeRequest)
	}
	if client.revokeRequest.GetRuntimeActionId() != lease.RuntimeActionID ||
		client.revokeRequest.GetActionType() != lease.ActionType ||
		client.revokeRequest.GetTargetScope() != lease.TargetScope ||
		client.revokeRequest.GetTargetKey() != lease.TargetKey ||
		client.revokeRequest.GetAdapterId() != lease.AdapterID ||
		client.revokeRequest.GetCapabilityId() != lease.CapabilityID ||
		client.revokeRequest.GetCapabilityGrantId() != lease.CapabilityGrantID ||
		client.revokeRequest.GetSourceCommit() != lease.SourceCommit ||
		client.revokeRequest.GetCorrelationId() != lease.CorrelationID {
		t.Fatalf("full runtime action selector was not forwarded, got %#v", client.revokeRequest)
	}
}

func TestAdapterRuntimeExecutorTreatsNotFoundCleanupAsComplete(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{revokeStatus: string(domain.RuntimeActionNotFound)}
	executor := AdapterRuntimeExecutor{Client: client}

	if err := executor.Cleanup(ctx, testLease(time.Now())); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterRuntimeExecutorRejectsIncompleteCleanupSelector(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{revokeStatus: string(domain.RuntimeActionExpired)}
	executor := AdapterRuntimeExecutor{Client: client}
	lease := testLease(time.Now())
	lease.CapabilityID = ""

	err := executor.Cleanup(ctx, lease)
	if err == nil || !strings.Contains(err.Error(), "complete runtime action selector") {
		t.Fatalf("expected incomplete selector cleanup to fail, got %v", err)
	}
	if client.revokeRequest != nil {
		t.Fatalf("expected no adapter revoke request for incomplete selector, got %#v", client.revokeRequest)
	}
}

func TestAdapterRuntimeExecutorRejectsUnknownCleanup(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{revokeStatus: string(domain.RuntimeActionUnknown)}
	executor := AdapterRuntimeExecutor{Client: client}

	err := executor.Cleanup(ctx, testLease(time.Now()))
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown cleanup to fail, got %v", err)
	}
}

func TestAdapterRuntimeExecutorStateForwardsSelector(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{stateStatus: string(domain.RuntimeActionActive)}
	executor := AdapterRuntimeExecutor{Client: client}
	lease := testLease(time.Now())

	status, err := executor.State(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if status != domain.RuntimeActionActive {
		t.Fatalf("expected active state, got %q", status)
	}
	if client.stateRequest.GetIdempotencyKey() != lease.IdempotencyKey ||
		client.stateRequest.GetRuntimeActionId() != lease.RuntimeActionID ||
		client.stateRequest.GetAdapterId() != lease.AdapterID ||
		client.stateRequest.GetActionType() != lease.ActionType ||
		client.stateRequest.GetTargetScope() != lease.TargetScope ||
		client.stateRequest.GetTargetKey() != lease.TargetKey ||
		client.stateRequest.GetCapabilityId() != lease.CapabilityID ||
		client.stateRequest.GetCorrelationId() != lease.CorrelationID {
		t.Fatalf("full runtime action selector was not forwarded, got %#v", client.stateRequest)
	}
}

func TestAdapterRuntimeExecutorRejectsIncompleteStateSelector(t *testing.T) {
	ctx := context.Background()
	client := &fakeRuntimeActionClient{stateStatus: string(domain.RuntimeActionActive)}
	executor := AdapterRuntimeExecutor{Client: client}
	lease := testLease(time.Now())
	lease.AdapterID = ""

	status, err := executor.State(ctx, lease)
	if err == nil || !strings.Contains(err.Error(), "complete runtime action selector") {
		t.Fatalf("expected incomplete selector state to fail, got status=%q err=%v", status, err)
	}
	if client.stateRequest != nil {
		t.Fatalf("expected no adapter state request for incomplete selector, got %#v", client.stateRequest)
	}
}

func TestReconcileRecordsCleanupFailureFinding(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	bundlePath := signedBundleFile(t, signer, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, failingCleanupExecutor{}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.cleanup-failure",
		ActionType: "runtime_action.deny_temporarily_source",
		TargetKey:  "source-cleanup-failure",
		TTL:        "1s",
		Reason:     "test cleanup failure finding",
		AuditID:    "audit.cleanup-failure",
	})); err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return now.Add(2 * time.Second) }
	result, err := manager.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Expired != 0 {
		t.Fatalf("expected failed cleanup not to mark lease expired, got %#v", result)
	}
	assertFindingContains(t, result.Findings, "failed to cleanup expired runtime action")
}

func TestManagerRecordsAdapterExecuteFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	bundlePath := signedBundleFile(t, signer, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, failingExecuteExecutor{}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.execute-failure",
		ActionType: "runtime_action.deny_temporarily_source",
		TargetKey:  "source-execute-failure",
		TTL:        "1m",
		Reason:     "test execute failure",
		AuditID:    "audit.execute-failure",
	}))
	if err == nil {
		t.Fatal("expected execute failure")
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Status != domain.RuntimeActionFailed {
		t.Fatalf("expected failed lease to be recorded, got %#v", leases)
	}
	assertJournalEvent(t, store, ctx, leases[0].RuntimeActionID, "execute_failed")
}

func TestManagerRecoversActiveLeaseAfterLostExecuteResponse(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	bundlePath := signedBundleFile(t, signer, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, lostResponseExecutor{state: domain.RuntimeActionActive}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	result, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.lost-response-active",
		ActionType: "runtime_action.deny_temporarily_source",
		TargetKey:  "source-lost-response-active",
		TTL:        "1m",
		Reason:     "test lost response active recovery",
		AuditID:    "audit.lost-response-active",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || !result.Results[0].Applied || result.Results[0].Lease.Status != domain.RuntimeActionActive {
		t.Fatalf("expected active recovered lease, got %#v", result)
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Status != domain.RuntimeActionActive {
		t.Fatalf("expected active lease in store, got %#v", leases)
	}
	assertJournalEvent(t, store, ctx, leases[0].RuntimeActionID, "execute_recovered_by_readback")
}

func TestManagerFailsLeaseWhenExecuteReadbackUnknown(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	bundlePath := signedBundleFile(t, signer, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, lostResponseExecutor{state: domain.RuntimeActionUnknown}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.lost-response-unknown",
		ActionType: "runtime_action.deny_temporarily_source",
		TargetKey:  "source-lost-response-unknown",
		TTL:        "1m",
		Reason:     "test lost response unknown readback",
		AuditID:    "audit.lost-response-unknown",
	}))
	if err == nil {
		t.Fatal("expected execute error to remain when readback is unknown")
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Status != domain.RuntimeActionFailed {
		t.Fatalf("expected failed lease in store, got %#v", leases)
	}
	assertJournalEvent(t, store, ctx, leases[0].RuntimeActionID, "execute_readback_unknown")
}

func TestManagerFailsLeaseWhenExecuteReadbackFails(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	defer store.Close()
	signer := testSigner(t, now)
	bundlePath := signedBundleFile(t, signer, now, now.Add(time.Hour))
	manager := testManager(store, signer, now, testAdapter(testAdapterID, lostResponseExecutor{readbackErr: fmt.Errorf("readback unavailable")}))
	if _, err := manager.LoadBundle(ctx, kliqbundle.LocalFileSource{Path: bundlePath}); err != nil {
		t.Fatal(err)
	}
	_, err := manager.ExecuteAction(ctx, defaultExecuteRequest(ExecuteRequest{
		DecisionID: "decision.lost-response-readback-fails",
		ActionType: "runtime_action.deny_temporarily_source",
		TargetKey:  "source-lost-response-readback-fails",
		TTL:        "1m",
		Reason:     "test lost response readback failure",
		AuditID:    "audit.lost-response-readback-fails",
	}))
	if err == nil {
		t.Fatal("expected execute error to remain when readback fails")
	}
	leases, err := store.AllLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Status != domain.RuntimeActionFailed {
		t.Fatalf("expected failed lease in store, got %#v", leases)
	}
	assertJournalEvent(t, store, ctx, leases[0].RuntimeActionID, "execute_readback_failed")
}

type fakeRuntimeActionClient struct {
	executeStatus  string
	revokeStatus   string
	stateStatus    string
	executeRequest *adapterv1.ExecuteRuntimeActionRequest
	stateRequest   *adapterv1.GetRuntimeActionStateRequest
	revokeRequest  *adapterv1.RevokeRuntimeActionRequest
}

func (c *fakeRuntimeActionClient) ExecuteRuntimeAction(_ context.Context, in *adapterv1.ExecuteRuntimeActionRequest, _ ...grpc.CallOption) (*adapterv1.ExecuteRuntimeActionResponse, error) {
	c.executeRequest = in
	return &adapterv1.ExecuteRuntimeActionResponse{Status: c.executeStatus}, nil
}

func (c *fakeRuntimeActionClient) GetRuntimeActionState(_ context.Context, in *adapterv1.GetRuntimeActionStateRequest, _ ...grpc.CallOption) (*adapterv1.GetRuntimeActionStateResponse, error) {
	c.stateRequest = in
	status := c.stateStatus
	if status == "" {
		status = string(domain.RuntimeActionActive)
	}
	return &adapterv1.GetRuntimeActionStateResponse{Status: status}, nil
}

func (c *fakeRuntimeActionClient) RevokeRuntimeAction(_ context.Context, in *adapterv1.RevokeRuntimeActionRequest, _ ...grpc.CallOption) (*adapterv1.RevokeRuntimeActionResponse, error) {
	c.revokeRequest = in
	return &adapterv1.RevokeRuntimeActionResponse{Status: c.revokeStatus}, nil
}

type failingCleanupExecutor struct{}

func (failingCleanupExecutor) Execute(context.Context, actionstate.RuntimeActionLease, []byte) error {
	return nil
}

func (failingCleanupExecutor) Cleanup(context.Context, actionstate.RuntimeActionLease) error {
	return fmt.Errorf("adapter unavailable")
}

type failingExecuteExecutor struct{}

func (failingExecuteExecutor) Execute(context.Context, actionstate.RuntimeActionLease, []byte) error {
	return fmt.Errorf("adapter unavailable")
}

func (failingExecuteExecutor) Cleanup(context.Context, actionstate.RuntimeActionLease) error {
	return nil
}

type lostResponseExecutor struct {
	state       domain.RuntimeActionStatus
	readbackErr error
}

func (e lostResponseExecutor) Execute(context.Context, actionstate.RuntimeActionLease, []byte) error {
	return fmt.Errorf("execute response lost")
}

func (e lostResponseExecutor) Cleanup(context.Context, actionstate.RuntimeActionLease) error {
	return nil
}

func (e lostResponseExecutor) State(context.Context, actionstate.RuntimeActionLease) (domain.RuntimeActionStatus, error) {
	if e.readbackErr != nil {
		return "", e.readbackErr
	}
	return e.state, nil
}

func testLease(now time.Time) actionstate.RuntimeActionLease {
	return actionstate.RuntimeActionLease{
		RuntimeActionID:   "runtime_action.test",
		PlanID:            "runtime_action_plan.test",
		DecisionID:        "decision.test",
		PolicyID:          "policy.test",
		BundleID:          "runtime_bundle.policy.test",
		SourceCommit:      "abc123",
		CorrelationID:     "correlation.test",
		ActionType:        "runtime_action.deny_temporarily_source",
		TargetScope:       "source",
		TargetKey:         "source-1",
		TTL:               "1m",
		ExpiresAt:         now.Add(time.Minute),
		Reason:            "test action",
		AuditID:           "audit.test",
		CapabilityGrantID: "grant.test",
		AdapterID:         "kernloom.adapter.klshield",
		CapabilityID:      "klshield.runtime.source_mitigation",
		Mode:              ActionModeRequired,
		Required:          true,
		IdempotencyKey:    "idem.test",
		CreatedAt:         now,
		LastReconciledAt:  now,
		Status:            domain.RuntimeActionActive,
	}
}
