// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package jobs

import (
	"context"
	"encoding/json"
	"sync"
)

type MemoryStore struct {
	mu    sync.Mutex
	jobs  map[string]*Job
	queue []string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{jobs: map[string]*Job{}}
}

func (s *MemoryStore) Create(_ context.Context, job *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = cloneJob(job)
	return nil
}

func (s *MemoryStore) Enqueue(_ context.Context, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[jobID]; !ok {
		return ErrNotFound
	}
	s.queue = append(s.queue, jobID)
	return nil
}

func (s *MemoryStore) Dequeue(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return "", ErrNoJob
	}
	jobID := s.queue[0]
	s.queue = s.queue[1:]
	return jobID, nil
}

func (s *MemoryStore) Get(_ context.Context, jobID string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneJob(job), nil
}

func (s *MemoryStore) Update(_ context.Context, job *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[job.ID]; !ok {
		return ErrNotFound
	}
	s.jobs[job.ID] = cloneJob(job)
	return nil
}

func cloneJob(job *Job) *Job {
	if job == nil {
		return nil
	}
	data, _ := json.Marshal(job)
	var cloned Job
	_ = json.Unmarshal(data, &cloned)
	return &cloned
}
