// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"

	"github.com/kernloom/kernloom-core/internal/core/version"
)

func main() {
	fmt.Println(version.Binary("correlate"))
}
