// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"context"
	"os"
)

type Source interface {
	Load(ctx context.Context) ([]byte, string, error)
}

type LocalFileSource struct {
	Path string
}

func (s LocalFileSource) Load(_ context.Context) ([]byte, string, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, "", err
	}
	return data, s.Path, nil
}
