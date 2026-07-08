// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/forge/validation"
)

type Options struct {
	Inventory        string
	OutputDir        string
	RequiredEvidence []string
	CI               validation.CIOptions
	Now              func() time.Time
}

type Result struct {
	Kind        string         `json:"kind"`
	Status      string         `json:"status"`
	RunID       string         `json:"run_id"`
	EvidenceDir string         `json:"evidence_dir"`
	Checks      []Check        `json:"checks"`
	Files       []EvidenceFile `json:"files"`
	Findings    []string       `json:"findings,omitempty"`
}

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type EvidenceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func Run(ctx context.Context, opts Options) (Result, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	runID := now().UTC().Format("20060102T150405Z")
	outputRoot := strings.TrimSpace(opts.OutputDir)
	if outputRoot == "" {
		outputRoot = filepath.Join("evidence", runID)
	}
	result := Result{
		Kind:        "LabE2EResult",
		Status:      "passed",
		RunID:       runID,
		EvidenceDir: outputRoot,
	}
	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return result, err
	}

	if strings.TrimSpace(opts.Inventory) == "" {
		result.fail("lab.inventory", "inventory path is required")
	} else if err := copyEvidenceFile(opts.Inventory, filepath.Join(outputRoot, "inventory.yaml")); err != nil {
		result.fail("lab.inventory", err.Error())
	} else {
		result.pass("lab.inventory", "inventory captured")
	}

	if _, err := registry.Load(opts.CI.CoreRegistry, opts.CI.EnterpriseRegistry); err != nil {
		result.fail("lab.registry", err.Error())
	} else {
		result.pass("lab.registry", "registry validation passed")
	}
	registryReport := map[string]any{
		"status":              checkStatus(result.Checks, "lab.registry"),
		"core_registry":       opts.CI.CoreRegistry,
		"enterprise_registry": opts.CI.EnterpriseRegistry,
	}
	if err := writeJSONFile(filepath.Join(outputRoot, "registry-validation.json"), registryReport); err != nil {
		return result, err
	}

	if strings.TrimSpace(opts.CI.Tenant) != "" || strings.TrimSpace(opts.CI.Repository) != "" {
		ciResult := validation.ValidateCI(opts.CI)
		if ciResult.Status != "passed" {
			result.fail("lab.ci_validation", "CI validation failed")
		} else {
			result.pass("lab.ci_validation", "CI validation passed")
		}
		if err := writeJSONFile(filepath.Join(outputRoot, "ci-validation.json"), ciResult); err != nil {
			return result, err
		}
	}

	for _, evidencePath := range opts.RequiredEvidence {
		evidencePath = strings.TrimSpace(evidencePath)
		if evidencePath == "" {
			continue
		}
		if _, err := os.Stat(evidencePath); err != nil {
			result.fail("lab.evidence_required", fmt.Sprintf("required evidence missing: %s", evidencePath))
			continue
		}
		result.pass("lab.evidence_required", "required evidence present: "+evidencePath)
	}

	if err := collectEvidenceFiles(outputRoot, &result); err != nil {
		return result, err
	}
	if err := writeChecksums(outputRoot, result.Files); err != nil {
		return result, err
	}
	if err := collectEvidenceFiles(outputRoot, &result); err != nil {
		return result, err
	}
	result.finalize()
	if err := writeJSONFile(filepath.Join(outputRoot, "evidence-bundle.json"), result); err != nil {
		return result, err
	}
	return result, ctx.Err()
}

func (r *Result) pass(id, message string) {
	r.Checks = append(r.Checks, Check{ID: id, Status: "passed", Message: message})
}

func (r *Result) fail(id, message string) {
	r.Checks = append(r.Checks, Check{ID: id, Status: "failed", Message: message})
	r.Findings = append(r.Findings, message)
}

func (r *Result) finalize() {
	r.Status = "passed"
	for _, check := range r.Checks {
		if check.Status != "passed" {
			r.Status = "failed"
			return
		}
	}
}

func copyEvidenceFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func collectEvidenceFiles(root string, result *Result) error {
	var files []EvidenceFile
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "evidence-bundle.json" {
			return nil
		}
		file, err := evidenceFile(path, rel)
		if err != nil {
			return err
		}
		files = append(files, file)
		return nil
	}); err != nil {
		return err
	}
	result.Files = files
	return nil
}

func evidenceFile(path, rel string) (EvidenceFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EvidenceFile{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return EvidenceFile{}, err
	}
	sum := sha256.Sum256(data)
	return EvidenceFile{
		Path:   filepath.ToSlash(rel),
		SHA256: hex.EncodeToString(sum[:]),
		Size:   info.Size(),
	}, nil
}

func writeChecksums(root string, files []EvidenceFile) error {
	var builder strings.Builder
	for _, file := range files {
		fmt.Fprintf(&builder, "%s  %s\n", file.SHA256, file.Path)
	}
	return os.WriteFile(filepath.Join(root, "checksums.txt"), []byte(builder.String()), 0o644)
}

func checkStatus(checks []Check, id string) string {
	for _, check := range checks {
		if check.ID == id {
			return check.Status
		}
	}
	return "unknown"
}
