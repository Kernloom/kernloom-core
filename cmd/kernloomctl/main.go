// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"os"

	"github.com/kernloom/kernloom-core/internal/ctl"
)

func main() {
	ctl.Main("kernloomctl", os.Args[1:])
}
