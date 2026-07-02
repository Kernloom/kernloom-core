// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package artifactstore

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/kernloom/kernloom-core/internal/core/artifact"
)

type MemoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{objects: map[string][]byte{}}
}

func (s *MemoryStore) Put(_ context.Context, art artifact.Artifact) (artifact.Ref, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sha256Bytes(art.Payload)
	uri := "memory://" + art.Metadata.ArtifactType + "/" + art.Metadata.ID + "-" + hash[7:] + ".json"
	if _, exists := s.objects[uri]; exists {
		if bytes.Equal(s.objects[uri], art.Payload) {
			return artifact.Ref{URI: uri, SHA256: hash}, nil
		}
		return artifact.Ref{}, fmt.Errorf("artifact already exists with different content: %s", uri)
	}
	s.objects[uri] = append([]byte(nil), art.Payload...)
	return artifact.Ref{URI: uri, SHA256: hash}, nil
}

func (s *MemoryStore) Get(_ context.Context, ref artifact.Ref) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[ref.URI]
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", ref.URI)
	}
	if sha256Bytes(data) != ref.SHA256 {
		return nil, fmt.Errorf("artifact hash mismatch for %s", ref.URI)
	}
	return append([]byte(nil), data...), nil
}

func (s *MemoryStore) Verify(ctx context.Context, ref artifact.Ref) error {
	_, err := s.Get(ctx, ref)
	return err
}
