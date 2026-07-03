// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))

func logInfo(message string, attrs ...any) {
	logger.Info(message, attrs...)
}

func logError(message string, attrs ...any) {
	logger.Error(message, attrs...)
}
