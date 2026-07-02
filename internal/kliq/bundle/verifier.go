// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	corebundle "github.com/kernloom/kernloom-core/internal/core/bundle"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

type RuntimeBundleVerification struct {
	Bundle   corebundle.RuntimeBundle
	Envelope signing.SignedEnvelope
	Result   signing.VerificationResult
}

func LoadSignedRuntimeBundle(ctx context.Context, path string, verifier signing.Verifier) (RuntimeBundleVerification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuntimeBundleVerification{}, err
	}
	return VerifySignedRuntimeBundle(ctx, data, verifier)
}

func VerifySignedRuntimeBundle(ctx context.Context, data []byte, verifier signing.Verifier) (RuntimeBundleVerification, error) {
	if verifier == nil {
		return RuntimeBundleVerification{}, fmt.Errorf("runtime bundle verifier is required")
	}
	var envelope signing.SignedEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return RuntimeBundleVerification{}, err
	}
	if envelope.Kind != "SignedEnvelope" {
		return RuntimeBundleVerification{}, fmt.Errorf("runtime bundle must be a signed envelope")
	}
	result, err := verifier.Verify(ctx, envelope)
	if err != nil {
		return RuntimeBundleVerification{}, err
	}
	if !result.Valid {
		return RuntimeBundleVerification{}, fmt.Errorf("runtime bundle signature invalid: %s", result.Error)
	}
	var runtimeBundle corebundle.RuntimeBundle
	if err := json.Unmarshal(envelope.Payload, &runtimeBundle); err != nil {
		return RuntimeBundleVerification{}, err
	}
	if runtimeBundle.Kind != "RuntimeBundle" {
		return RuntimeBundleVerification{}, fmt.Errorf("signed payload is %q, expected RuntimeBundle", runtimeBundle.Kind)
	}
	if runtimeBundle.Metadata.ArtifactType != "runtime_bundle" {
		return RuntimeBundleVerification{}, fmt.Errorf("signed payload artifact_type is %q, expected runtime_bundle", runtimeBundle.Metadata.ArtifactType)
	}
	if envelope.PolicyID != "" && runtimeBundle.Metadata.PolicyID != "" && envelope.PolicyID != runtimeBundle.Metadata.PolicyID {
		return RuntimeBundleVerification{}, fmt.Errorf("signed envelope policy_id %q does not match runtime bundle policy_id %q", envelope.PolicyID, runtimeBundle.Metadata.PolicyID)
	}
	if envelope.SourceCommit != "" && runtimeBundle.Metadata.SourceCommit != "" && envelope.SourceCommit != runtimeBundle.Metadata.SourceCommit {
		return RuntimeBundleVerification{}, fmt.Errorf("signed envelope source_commit %q does not match runtime bundle source_commit %q", envelope.SourceCommit, runtimeBundle.Metadata.SourceCommit)
	}
	return RuntimeBundleVerification{Bundle: runtimeBundle, Envelope: envelope, Result: result}, nil
}
