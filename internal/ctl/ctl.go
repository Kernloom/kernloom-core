// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package ctl

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/registry"
	"github.com/kernloom/kernloom-core/internal/core/version"
	"github.com/kernloom/kernloom-core/internal/forge/adapterverify"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/production"
	"github.com/kernloom/kernloom-core/internal/forge/validation"
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
	fmt.Println(version.Binary(program))
	fmt.Printf("usage: %s registry validate [--core-registry path] [--enterprise-registry path]\n", program)
	fmt.Printf("usage: %s validate ci [--tenant id] [--environment env] [--repo org/name] [--adapter-verify-endpoint host:port]\n", program)
	fmt.Printf("usage: %s production check [--core-repo path] [--adapter-verify-endpoint host:port --adapter-verify-manifest path]\n", program)
	fmt.Printf("usage: %s adapter verify --adapter id --endpoint host:port --manifest adapter.manifest.yaml\n", program)
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
	result := validation.ValidateCI(opts)
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
