// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package artifact

import "time"

type Metadata struct {
	ID           string            `json:"id"`
	PolicyID     string            `json:"policy_id"`
	ArtifactType string            `json:"artifact_type"`
	KNI          string            `json:"kni_version"`
	SourcePath   string            `json:"source_path"`
	SourceCommit string            `json:"source_commit"`
	CreatedAt    time.Time         `json:"created_at"`
	Digests      map[string]string `json:"digests,omitempty"`
}

type Ref struct {
	URI    string `json:"uri"`
	SHA256 string `json:"sha256"`
}

type Artifact struct {
	Metadata Metadata `json:"metadata"`
	Payload  []byte   `json:"payload"`
}

func PlannedStatus(message string) Status {
	return Status{
		Status:  "planned",
		Phase:   "resolved_only",
		Message: message,
	}
}

type Status struct {
	Status  string `json:"status"`
	Phase   string `json:"phase"`
	Message string `json:"message"`
}
