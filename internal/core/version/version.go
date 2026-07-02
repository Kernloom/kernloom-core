// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package version

const Version = "v0.1.0-dev"

func Binary(name string) string {
	return name + " " + Version
}
