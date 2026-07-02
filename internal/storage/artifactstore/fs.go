// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package artifactstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernloom/kernloom-core/internal/core/artifact"
)

type FSStore struct {
	Root        string
	Org         string
	Environment string
}

func NewFSStore(root, org, environment string) *FSStore {
	return &FSStore{Root: root, Org: org, Environment: environment}
}

func (s *FSStore) Put(_ context.Context, art artifact.Artifact) (artifact.Ref, error) {
	root := s.Root
	if root == "" {
		root = "/var/lib/kernloom/artifacts"
	}
	org := valueOrDefault(s.Org, "default-org")
	environment := valueOrDefault(s.Environment, "dev")
	sourceCommit := valueOrDefault(art.Metadata.SourceCommit, "uncommitted")
	hash := sha256Bytes(art.Payload)
	name := sanitize(art.Metadata.ID) + "-" + hash[7:] + ".json"
	rel := filepath.Join(sanitize(org), sanitize(environment), sanitize(art.Metadata.ArtifactType), sanitize(sourceCommit), name)
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return artifact.Ref{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return artifact.Ref{}, err
	}
	defer file.Close()
	if _, err := file.Write(art.Payload); err != nil {
		return artifact.Ref{}, err
	}
	return artifact.Ref{URI: "fs://" + path, SHA256: hash}, nil
}

func (s *FSStore) Get(_ context.Context, ref artifact.Ref) ([]byte, error) {
	if !strings.HasPrefix(ref.URI, "fs://") {
		return nil, fmt.Errorf("unsupported artifact ref %q", ref.URI)
	}
	path := strings.TrimPrefix(ref.URI, "fs://")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if sha256Bytes(data) != ref.SHA256 {
		return nil, fmt.Errorf("artifact hash mismatch for %s", ref.URI)
	}
	return data, nil
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func sanitize(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\\", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "..", "_")
	if value == "" {
		return "unknown"
	}
	return value
}
