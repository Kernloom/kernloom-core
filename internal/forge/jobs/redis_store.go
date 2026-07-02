// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	kredis "github.com/kernloom/kernloom-core/internal/storage/redis"
)

type RedisStore struct {
	Client kredis.Client
	Prefix string
	Queue  string
}

func NewRedisStore(addr string) *RedisStore {
	return &RedisStore{
		Client: kredis.Client{Addr: addr},
		Prefix: "kernloom",
		Queue:  "kernloom:jobs",
	}
}

func (s *RedisStore) Create(ctx context.Context, job *Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	_, err = s.Client.Do(ctx, "SET", s.key(job.ID), string(data))
	return err
}

func (s *RedisStore) Enqueue(ctx context.Context, jobID string) error {
	if _, err := s.Get(ctx, jobID); err != nil {
		return err
	}
	_, err := s.Client.Do(ctx, "RPUSH", s.queue(), jobID)
	return err
}

func (s *RedisStore) Dequeue(ctx context.Context) (string, error) {
	value, err := s.Client.Do(ctx, "LPOP", s.queue())
	if errors.Is(err, kredis.ErrNil) {
		return "", ErrNoJob
	}
	if err != nil {
		return "", err
	}
	if value.String == "" {
		return "", ErrNoJob
	}
	return value.String, nil
}

func (s *RedisStore) Get(ctx context.Context, jobID string) (*Job, error) {
	value, err := s.Client.Do(ctx, "GET", s.key(jobID))
	if errors.Is(err, kredis.ErrNil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var job Job
	if err := json.Unmarshal([]byte(value.String), &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *RedisStore) Update(ctx context.Context, job *Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	_, err = s.Client.Do(ctx, "SET", s.key(job.ID), string(data))
	return err
}

func (s *RedisStore) key(jobID string) string {
	prefix := s.Prefix
	if prefix == "" {
		prefix = "kernloom"
	}
	return fmt.Sprintf("%s:job:%s", prefix, jobID)
}

func (s *RedisStore) queue() string {
	if s.Queue != "" {
		return s.Queue
	}
	prefix := s.Prefix
	if prefix == "" {
		prefix = "kernloom"
	}
	return prefix + ":jobs"
}
