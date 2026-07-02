// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	TypeSimulation = "simulation"

	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

var (
	ErrNotFound = errors.New("job not found")
	ErrNoJob    = errors.New("no job available")
)

type Store interface {
	Create(ctx context.Context, job *Job) error
	Enqueue(ctx context.Context, jobID string) error
	Dequeue(ctx context.Context) (string, error)
	Get(ctx context.Context, jobID string) (*Job, error)
	Update(ctx context.Context, job *Job) error
}

type Job struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Status    string          `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	CreatedBy string          `json:"created_by"`
	Payload   json.RawMessage `json:"payload"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type SimulationPayload struct {
	PolicyRepo         string `json:"policy_repo,omitempty"`
	PolicyFile         string `json:"policy_file,omitempty"`
	CoreRegistry       string `json:"core_registry,omitempty"`
	EnterpriseRegistry string `json:"enterprise_registry,omitempty"`
	OutputDir          string `json:"output_dir,omitempty"`
}

type SimulationResult struct {
	Kind     string                   `json:"kind"`
	Status   string                   `json:"status"`
	Policies []SimulationPolicyResult `json:"policies"`
}

type SimulationPolicyResult struct {
	PolicyID       string `json:"policy_id"`
	ReviewPath     string `json:"review_path"`
	ResolvedPath   string `json:"resolved_path"`
	ManifestPath   string `json:"manifest_path"`
	CoveragePath   string `json:"coverage_path"`
	SimulationPath string `json:"simulation_path"`
	ValidationPath string `json:"validation_path"`
	ResolvedSHA256 string `json:"resolved_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func NewJob(jobType, createdBy string, payload any) (*Job, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &Job{
		ID:        newID("job"),
		Type:      jobType,
		Status:    StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: createdBy,
		Payload:   data,
	}, nil
}

func (j *Job) SetStatus(status string) {
	j.Status = status
	j.UpdatedAt = time.Now().UTC()
}

func (j *Job) SetResult(result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	j.Result = data
	j.Error = ""
	j.SetStatus(StatusSucceeded)
	return nil
}

func (j *Job) SetError(err error) {
	j.Error = err.Error()
	j.SetStatus(StatusFailed)
}

func newID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s-%s", prefix, time.Now().UTC().Format("20060102T150405"), hex.EncodeToString(buf[:]))
}
