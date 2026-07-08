// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package production

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionCheckPassesWithReleaseSecurityAndIntegrationEvidence(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "release.yml", "sbom-action spdx cosign sign-blob sha256sum checksums upload-artifact bin/klctl")
	writeWorkflow(t, root, "security.yml", "govulncheck trivy codeql sbom-action")
	writeWorkflow(t, root, "ci.yml", "go test ./... go test -tags integration KERNLOOM_TEST_POSTGRES_DSN KERNLOOM_TEST_REDIS_ADDR make build bin/klctl registry validate bin/klctl adapter verify KERNLOOM_CI_ADAPTER_VERIFY_ENDPOINT")

	result := Check(CheckOptions{CoreRepo: root})
	if result.Status != "passed" {
		t.Fatalf("expected passed production check, got %#v", result)
	}
}

func TestProductionCheckFailsWhenReleaseEvidenceIsMissing(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "release.yml", "sha256sum checksums upload-artifact")
	writeWorkflow(t, root, "security.yml", "govulncheck trivy codeql sbom-action")
	writeWorkflow(t, root, "ci.yml", "go test ./... go test -tags integration KERNLOOM_TEST_POSTGRES_DSN KERNLOOM_TEST_REDIS_ADDR make build bin/klctl registry validate bin/klctl adapter verify KERNLOOM_CI_ADAPTER_VERIFY_ENDPOINT")

	result := Check(CheckOptions{CoreRepo: root})
	if result.Status != "failed" || !hasFinding(result, "release_sbom_missing") || !hasFinding(result, "release_signature_missing") {
		t.Fatalf("expected release evidence findings, got %#v", result)
	}
}

func TestProductionCheckRejectsInsecureAdapterVerify(t *testing.T) {
	result := Check(CheckOptions{
		AdapterVerifyEndpoint: "127.0.0.1:18082",
		AdapterVerifyManifest: "adapter.manifest.yaml",
		AdapterVerifyInsecure: true,
	})
	if result.Status != "failed" || !hasFinding(result, "adapter_runtime_insecure_transport") {
		t.Fatalf("expected insecure adapter runtime finding, got %#v", result)
	}
}

func TestProductionCheckRequiresAdapterVerifyCertPin(t *testing.T) {
	result := Check(CheckOptions{
		AdapterVerifyEndpoint:       "adapter.example:443",
		AdapterVerifyManifest:       "adapter.manifest.yaml",
		AdapterVerifyCAPath:         "ca.pem",
		AdapterVerifyClientCertPath: "client.pem",
		AdapterVerifyClientKeyPath:  "client-key.pem",
	})
	if result.Status != "failed" || !hasFinding(result, "adapter_runtime_cert_pin_missing") {
		t.Fatalf("expected missing adapter cert pin finding, got %#v", result)
	}
}

func writeWorkflow(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, ".github", "workflows", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasFinding(result CheckResult, code string) bool {
	for _, finding := range result.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
