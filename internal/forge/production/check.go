// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package production

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/forge/adapterverify"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
)

type CheckOptions struct {
	CoreRepo                             string
	AdapterVerifyEndpoint                string
	AdapterVerifyManifest                string
	AdapterVerifyAdapter                 string
	AdapterVerifyInsecure                bool
	AdapterVerifyCAPath                  string
	AdapterVerifyClientCertPath          string
	AdapterVerifyClientKeyPath           string
	AdapterVerifyTLSServerName           string
	AdapterVerifyServerCertificateSHA256 string
	AdapterVerifyTimeout                 time.Duration
}

type CheckResult struct {
	Kind           string                `json:"kind"`
	Status         string                `json:"status"`
	AdapterRuntime *adapterverify.Result `json:"adapter_runtime,omitempty"`
	Findings       []Finding             `json:"findings"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
}

func Check(opts CheckOptions) CheckResult {
	root := strings.TrimSpace(opts.CoreRepo)
	if root == "" {
		root = "."
	}
	result := CheckResult{Kind: "ProductionReadinessCheck", Status: "passed"}
	result.checkReleaseWorkflow(root)
	result.checkSecurityWorkflow(root)
	result.checkCIWorkflow(root)
	result.checkAdapterRuntime(opts)
	result.finalize()
	return result
}

func (r *CheckResult) checkAdapterRuntime(opts CheckOptions) {
	if strings.TrimSpace(opts.AdapterVerifyEndpoint) == "" {
		return
	}
	if strings.TrimSpace(opts.AdapterVerifyManifest) == "" {
		r.add("adapter_runtime_manifest_missing", "error", "adapter runtime verify requires --adapter-verify-manifest when --adapter-verify-endpoint is set", "")
		return
	}
	if opts.AdapterVerifyInsecure {
		r.add("adapter_runtime_insecure_transport", "error", "production adapter runtime verify forbids --adapter-verify-dev-insecure-transport", opts.AdapterVerifyManifest)
		return
	}
	if strings.TrimSpace(opts.AdapterVerifyServerCertificateSHA256) == "" {
		r.add("adapter_runtime_cert_pin_missing", "error", "production adapter runtime verify requires --adapter-verify-server-cert-sha256", opts.AdapterVerifyManifest)
		return
	}
	manifest, err := compiler.LoadAdapterManifestFile(opts.AdapterVerifyManifest)
	if err != nil {
		r.add("adapter_runtime_manifest_invalid", "error", err.Error(), opts.AdapterVerifyManifest)
		return
	}
	verify := adapterverify.Verify(context.Background(), adapterverify.Options{
		AdapterID:               opts.AdapterVerifyAdapter,
		Endpoint:                opts.AdapterVerifyEndpoint,
		Manifest:                manifest,
		DevInsecureTransport:    opts.AdapterVerifyInsecure,
		CAPath:                  opts.AdapterVerifyCAPath,
		ClientCertPath:          opts.AdapterVerifyClientCertPath,
		ClientKeyPath:           opts.AdapterVerifyClientKeyPath,
		TLSServerName:           opts.AdapterVerifyTLSServerName,
		ServerCertificateSHA256: opts.AdapterVerifyServerCertificateSHA256,
		Timeout:                 opts.AdapterVerifyTimeout,
	})
	r.AdapterRuntime = &verify
	if verify.Status != "passed" {
		message := "adapter runtime verify failed"
		if len(verify.Findings) > 0 {
			message = verify.Findings[0].Message
		}
		r.add("adapter_runtime_verify_failed", "error", message, opts.AdapterVerifyManifest)
	}
}

func (r *CheckResult) checkReleaseWorkflow(root string) {
	path := filepath.Join(root, ".github", "workflows", "release.yml")
	text, ok := r.readRequired(path, "release_workflow_missing", "release workflow is required")
	if !ok {
		return
	}
	r.requireContains(text, path, "release_sbom_missing", "release workflow must produce an SBOM", "sbom-action", "spdx")
	r.requireContains(text, path, "release_signature_missing", "release workflow must sign release artifacts or release evidence", "cosign", "sign-blob")
	r.requireContains(text, path, "release_checksum_missing", "release workflow must publish checksums", "sha256sum", "checksums")
	r.requireContains(text, path, "release_artifact_upload_missing", "release workflow must upload release evidence artifacts", "upload-artifact")
	r.requireContains(text, path, "release_klctl_missing", "release workflow must build and publish klctl", "bin/klctl")
}

func (r *CheckResult) checkSecurityWorkflow(root string) {
	path := filepath.Join(root, ".github", "workflows", "security.yml")
	text, ok := r.readRequired(path, "security_workflow_missing", "security workflow is required")
	if !ok {
		return
	}
	r.requireContains(text, path, "security_govulncheck_missing", "security workflow must run govulncheck", "govulncheck")
	r.requireContains(text, path, "security_trivy_missing", "security workflow must run Trivy filesystem scanning", "trivy")
	r.requireContains(text, path, "security_codeql_missing", "security workflow must run CodeQL", "codeql")
	r.requireContains(text, path, "security_sbom_missing", "security workflow must produce an SBOM", "sbom-action")
}

func (r *CheckResult) checkCIWorkflow(root string) {
	path := filepath.Join(root, ".github", "workflows", "ci.yml")
	text, ok := r.readRequired(path, "ci_workflow_missing", "CI workflow is required")
	if !ok {
		return
	}
	r.requireContains(text, path, "ci_go_test_missing", "CI workflow must run go test ./...", "go test ./...")
	r.requireContains(text, path, "ci_integration_test_missing", "CI workflow must run integration-tagged Postgres/Redis tests", "-tags integration", "KERNLOOM_TEST_POSTGRES_DSN", "KERNLOOM_TEST_REDIS_ADDR")
	r.requireContains(text, path, "ci_build_missing", "CI workflow must build release binaries", "make build")
	r.requireContains(text, path, "ci_klctl_validate_missing", "CI workflow must exercise klctl registry validation", "bin/klctl registry validate")
	r.requireContains(text, path, "ci_adapter_verify_gate_missing", "CI workflow must include optional klctl adapter verify gate", "bin/klctl adapter verify", "KERNLOOM_CI_ADAPTER_VERIFY_ENDPOINT")
}

func (r *CheckResult) readRequired(path, code, message string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		r.add(code, "error", message, path)
		return "", false
	}
	return strings.ToLower(string(data)), true
}

func (r *CheckResult) requireContains(text, path, code, message string, needles ...string) {
	for _, needle := range needles {
		if !strings.Contains(text, strings.ToLower(needle)) {
			r.add(code, "error", message, path)
			return
		}
	}
}

func (r *CheckResult) add(code, severity, message, path string) {
	r.Findings = append(r.Findings, Finding{Code: code, Severity: severity, Message: message, Path: path})
}

func (r *CheckResult) finalize() {
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Code == r.Findings[j].Code {
			return r.Findings[i].Message < r.Findings[j].Message
		}
		return r.Findings[i].Code < r.Findings[j].Code
	})
	for _, finding := range r.Findings {
		if finding.Severity == "error" {
			r.Status = "failed"
			return
		}
	}
	r.Status = "passed"
}
