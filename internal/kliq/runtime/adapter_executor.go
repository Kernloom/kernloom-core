// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"fmt"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
)

type RuntimeActionClient interface {
	ExecuteRuntimeAction(ctx context.Context, in *adapterv1.ExecuteRuntimeActionRequest, opts ...grpc.CallOption) (*adapterv1.ExecuteRuntimeActionResponse, error)
	GetRuntimeActionState(ctx context.Context, in *adapterv1.GetRuntimeActionStateRequest, opts ...grpc.CallOption) (*adapterv1.GetRuntimeActionStateResponse, error)
	RevokeRuntimeAction(ctx context.Context, in *adapterv1.RevokeRuntimeActionRequest, opts ...grpc.CallOption) (*adapterv1.RevokeRuntimeActionResponse, error)
}

type AdapterRuntimeExecutor struct {
	Client RuntimeActionClient
}

func NewAdapterRuntimeExecutor(conn grpc.ClientConnInterface) AdapterRuntimeExecutor {
	return AdapterRuntimeExecutor{Client: adapterv1.NewAdapterServiceClient(conn)}
}

func (e AdapterRuntimeExecutor) Execute(ctx context.Context, lease actionstate.RuntimeActionLease, signedBundle []byte) error {
	if e.Client == nil {
		return fmt.Errorf("adapter runtime executor requires client")
	}
	resp, err := e.Client.ExecuteRuntimeAction(ctx, &adapterv1.ExecuteRuntimeActionRequest{
		RuntimeActionId:   lease.RuntimeActionID,
		IdempotencyKey:    lease.IdempotencyKey,
		AdapterId:         lease.AdapterID,
		CapabilityId:      lease.CapabilityID,
		ActionType:        lease.ActionType,
		TargetScope:       lease.TargetScope,
		TargetKey:         lease.TargetKey,
		Ttl:               lease.TTL,
		Reason:            lease.Reason,
		AuditId:           lease.AuditID,
		SourceCommit:      lease.SourceCommit,
		CapabilityGrantId: lease.CapabilityGrantID,
		CorrelationId:     lease.CorrelationID,
		SignedBundle:      append([]byte(nil), signedBundle...),
	})
	if err != nil {
		return err
	}
	if resp.GetStatus() != string(domain.RuntimeActionActive) {
		return fmt.Errorf("adapter execute returned status %q", resp.GetStatus())
	}
	return nil
}

func (e AdapterRuntimeExecutor) Cleanup(ctx context.Context, lease actionstate.RuntimeActionLease) error {
	if e.Client == nil {
		return fmt.Errorf("adapter runtime executor requires client")
	}
	selector := lease.Selector()
	if !selector.Valid() {
		return fmt.Errorf("runtime action lease %q does not contain a complete runtime action selector", lease.RuntimeActionID)
	}
	resp, err := e.Client.RevokeRuntimeAction(ctx, &adapterv1.RevokeRuntimeActionRequest{
		IdempotencyKey:    selector.IdempotencyKey,
		Reason:            "ttl expired",
		AuditId:           lease.AuditID,
		RuntimeActionId:   selector.RuntimeActionID,
		AdapterId:         selector.AdapterID,
		ActionType:        selector.ActionType,
		TargetScope:       selector.TargetScope,
		TargetKey:         selector.TargetKey,
		SourceCommit:      lease.SourceCommit,
		CapabilityGrantId: lease.CapabilityGrantID,
		CapabilityId:      selector.CapabilityID,
		CorrelationId:     lease.CorrelationID,
	})
	if err != nil {
		return err
	}
	switch resp.GetStatus() {
	case string(domain.RuntimeActionExpired), string(domain.RuntimeActionNotFound):
		return nil
	default:
		return fmt.Errorf("adapter cleanup returned status %q", resp.GetStatus())
	}
}

func (e AdapterRuntimeExecutor) State(ctx context.Context, lease actionstate.RuntimeActionLease) (domain.RuntimeActionStatus, error) {
	if e.Client == nil {
		return "", fmt.Errorf("adapter runtime executor requires client")
	}
	selector := lease.Selector()
	if !selector.Valid() {
		return "", fmt.Errorf("runtime action lease %q does not contain a complete runtime action selector", lease.RuntimeActionID)
	}
	resp, err := e.Client.GetRuntimeActionState(ctx, &adapterv1.GetRuntimeActionStateRequest{
		IdempotencyKey:  selector.IdempotencyKey,
		RuntimeActionId: selector.RuntimeActionID,
		AdapterId:       selector.AdapterID,
		ActionType:      selector.ActionType,
		TargetScope:     selector.TargetScope,
		TargetKey:       selector.TargetKey,
		CapabilityId:    selector.CapabilityID,
		CorrelationId:   lease.CorrelationID,
	})
	if err != nil {
		return "", err
	}
	return domain.RuntimeActionStatus(resp.GetStatus()), nil
}
