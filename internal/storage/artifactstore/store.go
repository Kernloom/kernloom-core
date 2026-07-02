// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package artifactstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/kernloom/kernloom-core/internal/core/artifact"
)

type ArtifactStore interface {
	Put(ctx context.Context, artifact artifact.Artifact) (artifact.Ref, error)
	Get(ctx context.Context, ref artifact.Ref) ([]byte, error)
	Verify(ctx context.Context, ref artifact.Ref) error
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
