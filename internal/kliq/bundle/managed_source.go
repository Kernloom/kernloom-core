// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

type ManagedAssignmentSource struct {
	BaseURL                 string
	BearerToken             string
	KLIQID                  string
	Environment             string
	Stage                   string
	Scope                   string
	TrustKeyID              string
	ActiveAssignmentVersion int64
	Verifier                signing.Verifier
	HTTPClient              *http.Client
}

func (s ManagedAssignmentSource) Load(ctx context.Context) ([]byte, string, error) {
	if strings.TrimSpace(s.BaseURL) == "" {
		return nil, "", fmt.Errorf("managed assignment source requires base url")
	}
	if strings.TrimSpace(s.KLIQID) == "" {
		return nil, "", fmt.Errorf("managed assignment source requires kliq id")
	}
	if s.Verifier == nil {
		return nil, "", fmt.Errorf("managed assignment source requires verifier")
	}
	url := strings.TrimRight(s.BaseURL, "/") + "/v1/kliq/assignments/" + s.KLIQID + "/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	if s.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.BearerToken)
	}
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", fmt.Errorf("assignment api returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var envelope signing.SignedEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, "", err
	}
	assignment, err := s.verifyAssignment(ctx, envelope)
	if err != nil {
		return nil, "", err
	}
	artifact, ok := domain.RuntimeBundleArtifact(assignment)
	if !ok {
		return nil, "", fmt.Errorf("assignment %q does not include runtime_bundle artifact", assignment.AssignmentID)
	}
	return append([]byte(nil), artifact.Envelope...), url + "#" + assignment.AssignmentID, nil
}

func (s ManagedAssignmentSource) verifyAssignment(ctx context.Context, envelope signing.SignedEnvelope) (domain.KLIQAssignment, error) {
	result, err := s.Verifier.Verify(ctx, envelope)
	if err != nil {
		return domain.KLIQAssignment{}, err
	}
	if !result.Valid {
		return domain.KLIQAssignment{}, fmt.Errorf("assignment signature invalid: %s", result.Error)
	}
	var assignment domain.KLIQAssignment
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	if err := decoder.Decode(&assignment); err != nil {
		return domain.KLIQAssignment{}, err
	}
	if assignment.TrustKeyID != "" && assignment.TrustKeyID != result.KeyID {
		return domain.KLIQAssignment{}, fmt.Errorf("assignment trust key %q does not match envelope key %q", assignment.TrustKeyID, result.KeyID)
	}
	assignment.SignatureValid = true
	if err := domain.ValidateAssignedArtifactDigests(assignment); err != nil {
		return domain.KLIQAssignment{}, err
	}
	if err := domain.ValidateKLIQAssignmentActivation(assignment, domain.KLIQAssignmentActivationContext{
		KLIQID:                  s.KLIQID,
		Environment:             s.Environment,
		Stage:                   s.Stage,
		Scope:                   s.Scope,
		TrustKeyID:              s.TrustKeyID,
		ActiveAssignmentVersion: s.ActiveAssignmentVersion,
	}); err != nil {
		return domain.KLIQAssignment{}, err
	}
	return assignment, nil
}
