// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/core/version"
	"github.com/kernloom/kernloom-core/internal/forge/adapterverify"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/lab"
	"github.com/kernloom/kernloom-core/internal/forge/production"
	"github.com/kernloom/kernloom-core/internal/forge/validation"
	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
)

func Main(program string, args []string) {
	if program == "" {
		program = "klctl"
	}
	if len(args) > 1 && args[0] == "registry" && args[1] == "validate" {
		registryValidate(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "validate" && args[1] == "ci" {
		validateCI(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "production" && args[1] == "check" {
		productionCheck(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "adapter" && args[1] == "verify" {
		adapterVerify(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "lab" && args[1] == "e2e" {
		labE2E(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "baseline" && args[1] == "promote" {
		baselinePromote(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "trust-bundle" && args[1] == "rotate" {
		trustBundleRotate(program, args[2:])
		return
	}
	if len(args) > 1 && args[0] == "trust-bundle" && args[1] == "revoke" {
		trustBundleRevoke(program, args[2:])
		return
	}
	fmt.Println(version.Binary(program))
	fmt.Printf("usage: %s registry validate [--core-registry path] [--enterprise-registry path]\n", program)
	fmt.Printf("usage: %s validate ci [--tenant id] [--environment env] [--repo org/name] [--adapter-verify-endpoint host:port]\n", program)
	fmt.Printf("usage: %s production check [--core-repo path] [--adapter-verify-endpoint host:port --adapter-verify-manifest path]\n", program)
	fmt.Printf("usage: %s adapter verify --adapter id --endpoint host:port --manifest adapter.manifest.yaml\n", program)
	fmt.Printf("usage: %s lab e2e --inventory inventory/lab.yaml [--tenant id --environment env --repo org/name]\n", program)
	fmt.Printf("usage: %s baseline promote --state-db var/kliq/state.db --version-id id --approved-by user --reason text\n", program)
	fmt.Printf("usage: %s trust-bundle rotate --forge-url https://forge --key-id current --next-file next.json\n", program)
}

func registryValidate(program string, args []string) {
	fs := flag.NewFlagSet(program+" registry validate", flag.ExitOnError)
	coreRegistry := fs.String("core-registry", "../kernloom-core-registry", "path to core registry")
	enterpriseRegistry := fs.String("enterprise-registry", "", "optional path to enterprise registry")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	catalog, err := registry.Load(*coreRegistry, *enterpriseRegistry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf(
		"RegistryValidationReport: ok values=%d supplemental_catalogs=%d capabilities=%d compiler_rules=%d adapter_bindings=%d profiles=%d risk_recipes=%d guardrails=%d\n",
		len(catalog.Values),
		len(catalog.SupplementalCatalogs),
		len(catalog.Capabilities),
		len(catalog.CompilerRules),
		len(catalog.AdapterBindings),
		len(catalog.Profiles),
		len(catalog.RiskRecipes),
		len(catalog.Guardrails),
	)
}

func validateCI(program string, args []string) {
	fs := flag.NewFlagSet(program+" validate ci", flag.ExitOnError)
	opts := validation.CIOptions{}
	var changedPaths stringSliceFlag
	output := fs.String("output", "text", "output format: text or json")
	forgeURL := fs.String("forge-url", "", "optional Forge validation PDP URL; when set, validation runs centrally")
	token := fs.String("token", "", "bearer token for --forge-url; prefer --token-file or KERNLOOM_TOKEN outside local smoke tests")
	tokenFile := fs.String("token-file", "", "file containing bearer token for --forge-url")
	adapterVerifyEndpoint := fs.String("adapter-verify-endpoint", "", "optional adapter gRPC endpoint to verify with Describe")
	adapterVerifyManifest := fs.String("adapter-verify-manifest", "", "optional adapter manifest path override for runtime verification")
	adapterVerifyInsecure := fs.Bool("adapter-verify-dev-insecure-transport", false, "use plaintext gRPC for adapter runtime verification; dev/smoke only")
	adapterVerifyCA := fs.String("adapter-verify-ca", "", "adapter runtime verification mTLS CA bundle")
	adapterVerifyClientCert := fs.String("adapter-verify-client-cert", "", "adapter runtime verification mTLS client certificate")
	adapterVerifyClientKey := fs.String("adapter-verify-client-key", "", "adapter runtime verification mTLS client private key")
	adapterVerifyServerName := fs.String("adapter-verify-server-name", "", "TLS server name for adapter runtime verification")
	adapterVerifyTLSServerName := fs.String("adapter-verify-tls-server-name", "", "TLS server name for adapter runtime verification")
	adapterVerifyServerCertSHA256 := fs.String("adapter-verify-server-cert-sha256", "", "expected adapter runtime verification leaf certificate SHA-256 pin")
	adapterVerifyTimeout := fs.Duration("adapter-verify-timeout", 5*time.Second, "timeout for adapter runtime verification")
	fs.StringVar(&opts.PolicyRepo, "policy-repo", "../enterprise-kernloom-policies", "path to enterprise policy repository")
	fs.StringVar(&opts.CoreRegistry, "core-registry", "../kernloom-core-registry", "path to core registry")
	fs.StringVar(&opts.EnterpriseRegistry, "enterprise-registry", "../enterprise-kernloom-registry", "path to enterprise registry")
	fs.StringVar(&opts.Tenant, "tenant", "", "tenant id for the CI validation request")
	fs.StringVar(&opts.Environment, "environment", "", "environment id for the CI validation request")
	fs.StringVar(&opts.Provider, "provider", "", "git provider, for example github or gitlab")
	fs.StringVar(&opts.Repository, "repo", "", "repository identity, usually org/repo")
	fs.StringVar(&opts.Commit, "commit", "", "commit SHA being validated")
	fs.StringVar(&opts.PullRequest, "pull-request", "", "pull request id")
	fs.StringVar(&opts.BasePath, "base-path", "", "target config base path")
	fs.StringVar(&opts.TargetID, "target-id", "", "optional target id when repo/base-path is ambiguous")
	fs.Var(&changedPaths, "changed-path", "changed path relative to the target config repo; may be repeated")
	fs.StringVar(&opts.ConfigSnapshot, "config-snapshot", "", "optional local config checkout/snapshot root")
	fs.StringVar(&opts.OutputDir, "output-dir", "", "optional output directory for policy meaning compile artifacts")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.ChangedPaths = changedPaths
	opts.AdapterVerify = validation.AdapterVerifyOptions{
		Endpoint:                *adapterVerifyEndpoint,
		Manifest:                *adapterVerifyManifest,
		DevInsecureTransport:    *adapterVerifyInsecure,
		CAPath:                  *adapterVerifyCA,
		ClientCertPath:          *adapterVerifyClientCert,
		ClientKeyPath:           *adapterVerifyClientKey,
		TLSServerName:           firstNonEmpty(*adapterVerifyServerName, *adapterVerifyTLSServerName),
		ServerCertificateSHA256: *adapterVerifyServerCertSHA256,
		Timeout:                 *adapterVerifyTimeout,
	}
	result := validation.CIValidationResult{}
	if strings.TrimSpace(*forgeURL) != "" {
		remoteResult, err := validateCIRemote(context.Background(), *forgeURL, *token, *tokenFile, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		result = remoteResult
	} else {
		result = validation.ValidateCI(opts)
	}
	switch strings.ToLower(strings.TrimSpace(*output)) {
	case "json":
		printJSON(result)
	case "text", "":
		printCIValidationText(result)
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", *output)
		os.Exit(2)
	}
	if result.Status != "passed" {
		os.Exit(1)
	}
}

func validateCIRemote(ctx context.Context, forgeURL, token, tokenFile string, opts validation.CIOptions) (validation.CIValidationResult, error) {
	endpoint, err := neturl.JoinPath(strings.TrimSpace(forgeURL), "/v1/validation/ci")
	if err != nil {
		return validation.CIValidationResult{}, err
	}
	body, err := json.Marshal(map[string]any{
		"policy_repo":         opts.PolicyRepo,
		"core_registry":       opts.CoreRegistry,
		"enterprise_registry": opts.EnterpriseRegistry,
		"tenant":              opts.Tenant,
		"environment":         opts.Environment,
		"provider":            opts.Provider,
		"repository":          opts.Repository,
		"commit":              opts.Commit,
		"pull_request":        opts.PullRequest,
		"base_path":           opts.BasePath,
		"target_id":           opts.TargetID,
		"changed_paths":       opts.ChangedPaths,
		"config_snapshot":     opts.ConfigSnapshot,
		"output_dir":          opts.OutputDir,
		"adapter_verify":      opts.AdapterVerify,
	})
	if err != nil {
		return validation.CIValidationResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return validation.CIValidationResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := validationBearerToken(token, tokenFile)
	if err != nil {
		return validation.CIValidationResult{}, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return validation.CIValidationResult{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return validation.CIValidationResult{}, err
	}
	var result validation.CIValidationResult
	if err := json.Unmarshal(data, &result); err != nil {
		return validation.CIValidationResult{}, fmt.Errorf("forge validation response was not a CIValidationResult: status=%s body=%s", resp.Status, strings.TrimSpace(string(data)))
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 || resp.StatusCode == http.StatusUnprocessableEntity {
		return result, nil
	}
	return result, fmt.Errorf("forge validation failed before policy evaluation: status=%s", resp.Status)
}

func validationBearerToken(flagValue, filePath string) (string, error) {
	if strings.TrimSpace(filePath) != "" {
		data, err := os.ReadFile(strings.TrimSpace(filePath))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	if envValue := strings.TrimSpace(os.Getenv("KERNLOOM_TOKEN")); envValue != "" {
		return envValue, nil
	}
	return strings.TrimSpace(flagValue), nil
}

func postForgeJSON(ctx context.Context, forgeURL, endpointPath, token, tokenFile string, request any, response any) error {
	if strings.TrimSpace(forgeURL) == "" {
		return fmt.Errorf("--forge-url is required")
	}
	endpoint, err := neturl.JoinPath(strings.TrimSpace(forgeURL), endpointPath)
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := validationBearerToken(token, tokenFile)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if len(data) != 0 && response != nil {
		if err := json.Unmarshal(data, response); err != nil {
			return fmt.Errorf("forge response was not JSON: status=%s body=%s", resp.Status, strings.TrimSpace(string(data)))
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("forge request failed: status=%s body=%s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func loadTrustBundle(path string) (domain.TrustBundle, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return domain.TrustBundle{}, fmt.Errorf("--next-file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.TrustBundle{}, err
	}
	var bundle domain.TrustBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return domain.TrustBundle{}, err
	}
	if strings.TrimSpace(bundle.KeyID) == "" || strings.TrimSpace(bundle.PublicKey) == "" || strings.TrimSpace(bundle.Purpose) == "" {
		return domain.TrustBundle{}, fmt.Errorf("%s: trust bundle requires key_id, public_key and purpose", path)
	}
	return bundle, nil
}

func printOperatorResponse(output, label string, response map[string]any) {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		printJSON(response)
	case "text", "":
		status, _ := response["status"].(string)
		if status == "" {
			status = "accepted"
		}
		fmt.Printf("%s: %s\n", label, status)
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", output)
		os.Exit(2)
	}
}

func productionCheck(program string, args []string) {
	fs := flag.NewFlagSet(program+" production check", flag.ExitOnError)
	coreRepo := fs.String("core-repo", ".", "path to kernloom-core repository")
	output := fs.String("output", "text", "output format: text or json")
	adapterVerifyEndpoint := fs.String("adapter-verify-endpoint", "", "optional adapter gRPC endpoint to verify with Describe")
	adapterVerifyManifest := fs.String("adapter-verify-manifest", "", "adapter manifest path for runtime verification")
	adapterVerifyAdapter := fs.String("adapter-verify-adapter", "", "expected adapter id for runtime verification")
	adapterVerifyInsecure := fs.Bool("adapter-verify-dev-insecure-transport", false, "use plaintext gRPC for adapter runtime verification; dev/smoke only")
	adapterVerifyCA := fs.String("adapter-verify-ca", "", "adapter runtime verification mTLS CA bundle")
	adapterVerifyClientCert := fs.String("adapter-verify-client-cert", "", "adapter runtime verification mTLS client certificate")
	adapterVerifyClientKey := fs.String("adapter-verify-client-key", "", "adapter runtime verification mTLS client private key")
	adapterVerifyServerName := fs.String("adapter-verify-server-name", "", "TLS server name for adapter runtime verification")
	adapterVerifyTLSServerName := fs.String("adapter-verify-tls-server-name", "", "TLS server name for adapter runtime verification")
	adapterVerifyServerCertSHA256 := fs.String("adapter-verify-server-cert-sha256", "", "expected adapter runtime verification leaf certificate SHA-256 pin")
	adapterVerifyTimeout := fs.Duration("adapter-verify-timeout", 5*time.Second, "timeout for adapter runtime verification")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := production.Check(production.CheckOptions{
		CoreRepo:                             *coreRepo,
		AdapterVerifyEndpoint:                *adapterVerifyEndpoint,
		AdapterVerifyManifest:                *adapterVerifyManifest,
		AdapterVerifyAdapter:                 *adapterVerifyAdapter,
		AdapterVerifyInsecure:                *adapterVerifyInsecure,
		AdapterVerifyCAPath:                  *adapterVerifyCA,
		AdapterVerifyClientCertPath:          *adapterVerifyClientCert,
		AdapterVerifyClientKeyPath:           *adapterVerifyClientKey,
		AdapterVerifyTLSServerName:           firstNonEmpty(*adapterVerifyServerName, *adapterVerifyTLSServerName),
		AdapterVerifyServerCertificateSHA256: *adapterVerifyServerCertSHA256,
		AdapterVerifyTimeout:                 *adapterVerifyTimeout,
	})
	switch strings.ToLower(strings.TrimSpace(*output)) {
	case "json":
		printJSON(result)
	case "text", "":
		fmt.Printf("ProductionReadinessCheck: %s\n", result.Status)
		if result.AdapterRuntime != nil {
			fmt.Printf("adapter_runtime: %s adapter=%s endpoint=%s manifest_digest=%s\n",
				result.AdapterRuntime.Status,
				result.AdapterRuntime.AdapterID,
				result.AdapterRuntime.Endpoint,
				result.AdapterRuntime.ManifestDigest,
			)
		}
		for _, finding := range result.Findings {
			fmt.Printf("  [%s] %s: %s", finding.Severity, finding.Code, finding.Message)
			if finding.Path != "" {
				fmt.Printf(" path=%s", finding.Path)
			}
			fmt.Println()
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", *output)
		os.Exit(2)
	}
	if result.Status != "passed" {
		os.Exit(1)
	}
}

func adapterVerify(program string, args []string) {
	fs := flag.NewFlagSet(program+" adapter verify", flag.ExitOnError)
	adapterID := fs.String("adapter", "", "expected adapter id")
	endpoint := fs.String("endpoint", "", "adapter gRPC endpoint")
	manifestPath := fs.String("manifest", "", "adapter manifest path")
	output := fs.String("output", "text", "output format: text or json")
	devInsecure := fs.Bool("dev-insecure-transport", false, "use plaintext gRPC transport; dev/smoke only")
	adapterCA := fs.String("adapter-ca", "", "adapter mTLS CA bundle")
	adapterClientCert := fs.String("adapter-client-cert", "", "adapter mTLS client certificate")
	adapterClientKey := fs.String("adapter-client-key", "", "adapter mTLS client private key")
	adapterServerName := fs.String("adapter-server-name", "", "expected adapter TLS server name")
	adapterServerCertSHA256 := fs.String("adapter-server-cert-sha256", "", "expected adapter leaf certificate SHA-256 pin")
	tlsServerName := fs.String("tls-server-name", "", "TLS server name")
	timeout := fs.Duration("timeout", 5*time.Second, "adapter verification timeout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if strings.TrimSpace(*manifestPath) == "" {
		fmt.Fprintln(os.Stderr, "adapter verify requires --manifest")
		os.Exit(2)
	}
	manifest, err := compiler.LoadAdapterManifestFile(*manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result := adapterverify.Verify(context.Background(), adapterverify.Options{
		AdapterID:               *adapterID,
		Endpoint:                *endpoint,
		Manifest:                manifest,
		DevInsecureTransport:    *devInsecure,
		CAPath:                  *adapterCA,
		ClientCertPath:          *adapterClientCert,
		ClientKeyPath:           *adapterClientKey,
		TLSServerName:           firstNonEmpty(*adapterServerName, *tlsServerName),
		ServerCertificateSHA256: *adapterServerCertSHA256,
		Timeout:                 *timeout,
	})
	switch strings.ToLower(strings.TrimSpace(*output)) {
	case "json":
		printJSON(result)
	case "text", "":
		fmt.Printf("AdapterRuntimeVerifyResult: %s adapter=%s endpoint=%s manifest_digest=%s descriptor_manifest_digest=%s\n",
			result.Status,
			result.AdapterID,
			result.Endpoint,
			result.ManifestDigest,
			result.DescriptorDigest,
		)
		for _, finding := range result.Findings {
			fmt.Printf("  [error] %s: %s\n", finding.Code, finding.Message)
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", *output)
		os.Exit(2)
	}
	if result.Status != "passed" {
		os.Exit(1)
	}
}

func labE2E(program string, args []string) {
	fs := flag.NewFlagSet(program+" lab e2e", flag.ExitOnError)
	opts := validation.CIOptions{}
	var changedPaths stringSliceFlag
	var requiredEvidence stringSliceFlag
	inventory := fs.String("inventory", "", "lab inventory YAML path")
	evidenceDir := fs.String("evidence-dir", "", "evidence bundle output directory")
	output := fs.String("output", "text", "output format: text or json")
	adapterVerifyEndpoint := fs.String("adapter-verify-endpoint", "", "optional adapter gRPC endpoint to verify with Describe")
	adapterVerifyManifest := fs.String("adapter-verify-manifest", "", "optional adapter manifest path override for runtime verification")
	adapterVerifyInsecure := fs.Bool("adapter-verify-dev-insecure-transport", false, "use plaintext gRPC for adapter runtime verification; dev/smoke only")
	adapterVerifyCA := fs.String("adapter-verify-ca", "", "adapter runtime verification mTLS CA bundle")
	adapterVerifyClientCert := fs.String("adapter-verify-client-cert", "", "adapter runtime verification mTLS client certificate")
	adapterVerifyClientKey := fs.String("adapter-verify-client-key", "", "adapter runtime verification mTLS client private key")
	adapterVerifyServerName := fs.String("adapter-verify-server-name", "", "TLS server name for adapter runtime verification")
	adapterVerifyServerCertSHA256 := fs.String("adapter-verify-server-cert-sha256", "", "expected adapter runtime verification leaf certificate SHA-256 pin")
	adapterVerifyTimeout := fs.Duration("adapter-verify-timeout", 5*time.Second, "timeout for adapter runtime verification")
	fs.StringVar(&opts.PolicyRepo, "policy-repo", "../enterprise-kernloom-policies", "path to enterprise policy repository")
	fs.StringVar(&opts.CoreRegistry, "core-registry", "../kernloom-core-registry", "path to core registry")
	fs.StringVar(&opts.EnterpriseRegistry, "enterprise-registry", "../enterprise-kernloom-registry", "path to enterprise registry")
	fs.StringVar(&opts.Tenant, "tenant", "", "tenant id for the CI validation request")
	fs.StringVar(&opts.Environment, "environment", "", "environment id for the CI validation request")
	fs.StringVar(&opts.Provider, "provider", "", "git provider, for example github or gitlab")
	fs.StringVar(&opts.Repository, "repo", "", "repository identity, usually org/repo")
	fs.StringVar(&opts.Commit, "commit", "", "commit SHA being validated")
	fs.StringVar(&opts.PullRequest, "pull-request", "", "pull request id")
	fs.StringVar(&opts.BasePath, "base-path", "", "target config base path")
	fs.StringVar(&opts.TargetID, "target-id", "", "optional target id when repo/base-path is ambiguous")
	fs.Var(&changedPaths, "changed-path", "changed path relative to the target config repo; may be repeated")
	fs.Var(&requiredEvidence, "require-evidence", "required evidence file or directory; may be repeated")
	fs.StringVar(&opts.ConfigSnapshot, "config-snapshot", "", "optional local config checkout/snapshot root")
	fs.StringVar(&opts.OutputDir, "compile-output-dir", "", "optional output directory for policy meaning compile artifacts")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.ChangedPaths = changedPaths
	opts.AdapterVerify = validation.AdapterVerifyOptions{
		Endpoint:                *adapterVerifyEndpoint,
		Manifest:                *adapterVerifyManifest,
		DevInsecureTransport:    *adapterVerifyInsecure,
		CAPath:                  *adapterVerifyCA,
		ClientCertPath:          *adapterVerifyClientCert,
		ClientKeyPath:           *adapterVerifyClientKey,
		TLSServerName:           *adapterVerifyServerName,
		ServerCertificateSHA256: *adapterVerifyServerCertSHA256,
		Timeout:                 *adapterVerifyTimeout,
	}
	result, err := lab.Run(context.Background(), lab.Options{
		Inventory:        *inventory,
		OutputDir:        *evidenceDir,
		RequiredEvidence: requiredEvidence,
		CI:               opts,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch strings.ToLower(strings.TrimSpace(*output)) {
	case "json":
		printJSON(result)
	case "text", "":
		fmt.Printf("LabE2EResult: %s run_id=%s evidence_dir=%s\n", result.Status, result.RunID, result.EvidenceDir)
		for _, check := range result.Checks {
			fmt.Printf("  [%s] %s", check.Status, check.ID)
			if check.Message != "" {
				fmt.Printf(": %s", check.Message)
			}
			fmt.Println()
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", *output)
		os.Exit(2)
	}
	if result.Status != "passed" {
		os.Exit(1)
	}
}

func baselinePromote(program string, args []string) {
	fs := flag.NewFlagSet(program+" baseline promote", flag.ExitOnError)
	stateDB := fs.String("state-db", "", "KLIQ SQLite state database path")
	versionID := fs.String("version-id", "", "baseline version id")
	action := fs.String("action", baseline.PromotionActionPromote, "promotion action: promote, rollback or reject")
	previousVersionID := fs.String("previous-version-id", "", "previous baseline version id for rollback traceability")
	approvedBy := fs.String("approved-by", "", "approving operator identity")
	reason := fs.String("reason", "", "approval reason")
	decisionID := fs.String("decision-id", "", "optional promotion decision id")
	output := fs.String("output", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	now := time.Now().UTC()
	decision := baseline.PromotionDecision{
		DecisionID:        firstNonEmpty(*decisionID, "baseline_decision."+fmt.Sprint(now.UnixNano())),
		VersionID:         strings.TrimSpace(*versionID),
		PreviousVersionID: strings.TrimSpace(*previousVersionID),
		Action:            strings.TrimSpace(*action),
		ApprovedBy:        strings.TrimSpace(*approvedBy),
		ApprovedAt:        now,
		Reason:            strings.TrimSpace(*reason),
	}
	store, err := actionstate.OpenSQLite(*stateDB)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	response := map[string]any{"decision": decision}
	if decision.Action == baseline.PromotionActionReject {
		err = store.RejectBaselineVersion(context.Background(), decision)
		response["status"] = "rejected"
	} else {
		var active baseline.VersionRef
		active, err = store.PromoteBaselineVersion(context.Background(), decision)
		response["status"] = "promoted"
		response["active_version"] = active
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch strings.ToLower(strings.TrimSpace(*output)) {
	case "json":
		printJSON(response)
	case "text", "":
		fmt.Printf("BaselinePromotion: %s version=%s decision=%s\n", response["status"], decision.VersionID, decision.DecisionID)
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", *output)
		os.Exit(2)
	}
}

func trustBundleRotate(program string, args []string) {
	fs := flag.NewFlagSet(program+" trust-bundle rotate", flag.ExitOnError)
	forgeURL := fs.String("forge-url", "", "Forge API URL")
	token := fs.String("token", "", "bearer token; prefer --token-file or KERNLOOM_TOKEN outside local smoke tests")
	tokenFile := fs.String("token-file", "", "file containing bearer token")
	keyID := fs.String("key-id", "", "current trust bundle key id")
	nextFile := fs.String("next-file", "", "JSON file containing the next TrustBundle")
	reason := fs.String("reason", "", "rotation reason")
	output := fs.String("output", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	next, err := loadTrustBundle(*nextFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var response map[string]any
	path := "/v1/kliq/trust-bundles/" + strings.TrimSpace(*keyID) + "/rotate"
	if err := postForgeJSON(context.Background(), *forgeURL, path, *token, *tokenFile, map[string]any{
		"next":   next,
		"reason": strings.TrimSpace(*reason),
	}, &response); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printOperatorResponse(*output, "TrustBundleRotation", response)
}

func trustBundleRevoke(program string, args []string) {
	fs := flag.NewFlagSet(program+" trust-bundle revoke", flag.ExitOnError)
	forgeURL := fs.String("forge-url", "", "Forge API URL")
	token := fs.String("token", "", "bearer token; prefer --token-file or KERNLOOM_TOKEN outside local smoke tests")
	tokenFile := fs.String("token-file", "", "file containing bearer token")
	keyID := fs.String("key-id", "", "trust bundle key id")
	reason := fs.String("reason", "", "revocation reason")
	output := fs.String("output", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var response map[string]any
	path := "/v1/kliq/trust-bundles/" + strings.TrimSpace(*keyID) + "/revoke"
	if err := postForgeJSON(context.Background(), *forgeURL, path, *token, *tokenFile, map[string]any{
		"reason": strings.TrimSpace(*reason),
	}, &response); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printOperatorResponse(*output, "TrustBundleRevocation", response)
}

func printCIValidationText(result validation.CIValidationResult) {
	fmt.Printf("CIValidationResult: %s\n", result.Status)
	if result.Target != nil {
		fmt.Printf("target: %s tenant=%s environment=%s adapter=%s repo_ref=%s base_path=%s\n",
			result.Target.ID,
			result.Target.Tenant,
			result.Target.Environment,
			result.Target.Adapter,
			result.Target.RepoRef,
			result.Target.BasePath,
		)
	}
	if result.AdapterRuntime != nil {
		fmt.Printf("adapter_runtime: %s adapter=%s endpoint=%s manifest_digest=%s\n",
			result.AdapterRuntime.Status,
			result.AdapterRuntime.AdapterID,
			result.AdapterRuntime.Endpoint,
			result.AdapterRuntime.ManifestDigest,
		)
	}
	if result.Compile != nil {
		fmt.Printf("compile: %s policies=%d output_dir=%s\n", result.Compile.Status, result.Compile.Policies, result.Compile.OutputDir)
	}
	if len(result.Bindings) > 0 {
		fmt.Println("bindings:")
		for _, binding := range result.Bindings {
			fmt.Printf("  %s action=%s capability=%s selector=%s\n", binding.BindingID, binding.ActionID, binding.Capability, binding.SelectorType)
		}
	}
	if len(result.Findings) > 0 {
		fmt.Println("findings:")
		for _, finding := range result.Findings {
			scope := ""
			if finding.TargetID != "" {
				scope += " target=" + finding.TargetID
			}
			if finding.BindingID != "" {
				scope += " binding=" + finding.BindingID
			}
			fmt.Printf("  [%s] %s%s: %s\n", finding.Severity, finding.Code, scope, finding.Message)
		}
	}
}

func printJSON(value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}
