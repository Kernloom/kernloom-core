// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
	"github.com/kernloom/kernloom-core/internal/core/version"
	forgeapi "github.com/kernloom/kernloom-core/internal/forge/api"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
	"github.com/kernloom/kernloom-core/internal/forge/management"
	"github.com/kernloom/kernloom-core/internal/storage/artifactstore"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))

func main() {
	if len(os.Args) > 1 && os.Args[1] == "compile" {
		compile(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "api" {
		api(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		migrate(os.Args[2:])
		return
	}
	fmt.Println(version.Binary("forge"))
	fmt.Println("usage: forge compile [--policy-repo path] [--policy-file path] [--core-registry path] [--enterprise-registry path] [--output-dir path] [--artifact-store-root path] [--signing dev-local|none]")
	fmt.Println("usage: forge api [--addr :8080] [--queue redis|memory] [--redis-addr 127.0.0.1:6379]")
	fmt.Println("usage: forge migrate --management-postgres-dsn postgres://...")
}

func compile(args []string) {
	fs := flag.NewFlagSet("forge compile", flag.ExitOnError)
	opts := compiler.Options{}
	fs.StringVar(&opts.PolicyRepo, "policy-repo", "../enterprise-kernloom-policies", "path to enterprise policy repository")
	fs.StringVar(&opts.PolicyFile, "policy-file", "", "optional single KNI intent file to compile")
	fs.StringVar(&opts.CoreRegistry, "core-registry", "../kernloom-core-registry", "path to core registry repository")
	fs.StringVar(&opts.EnterpriseRegistry, "enterprise-registry", "../enterprise-kernloom-registry", "path to enterprise registry repository")
	fs.StringVar(&opts.OutputDir, "output-dir", "", "output directory; defaults to policy repo generated directory")
	fs.StringVar(&opts.ArtifactStoreRoot, "artifact-store-root", "", "fs artifact store root; defaults to output dir artifact-store")
	fs.StringVar(&opts.ArtifactStoreOrg, "artifact-store-org", "kernloom", "artifact store organization path segment")
	fs.StringVar(&opts.ArtifactStoreEnvironment, "artifact-store-env", "dev", "artifact store environment path segment")
	fs.StringVar(&opts.SigningMode, "signing", compiler.SigningModeDevLocal, "artifact signing mode: dev-local or none")
	fs.StringVar(&opts.SigningKeyPath, "signing-key", "", "dev-local signing key path; defaults to output dir keys/dev-local.ed25519.json")
	fs.StringVar(&opts.SigningKeyID, "signing-key-id", "dev-local", "key id to place in signed envelopes")
	fs.StringVar(&opts.CorrelationID, "correlation-id", "", "correlation id to embed in build manifest and artifacts; defaults to a deterministic local-dev id")
	fs.DurationVar(&opts.SignatureTTL, "signature-ttl", 24*time.Hour, "signed artifact validity duration")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results, err := compiler.Compile(opts)
	if err != nil {
		logger.Error("forge_compile_failed", "error", err.Error(), "correlation_id", opts.CorrelationID)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logger.Info("forge_compile_complete", "policies", len(results), "correlation_id", opts.CorrelationID)
	for _, result := range results {
		fmt.Printf("%s\n", result.PolicyID)
		fmt.Printf("  review: %s\n", result.ReviewPath)
		fmt.Printf("  resolved: %s\n", result.ResolvedPath)
		fmt.Printf("  runtime_bundle: %s\n", result.RuntimeBundlePath)
		if result.RuntimeBundleSignedPath != "" {
			fmt.Printf("  signed_runtime_bundle: %s\n", result.RuntimeBundleSignedPath)
		}
		fmt.Printf("  manifest: %s\n", result.ManifestPath)
		if result.ManifestSignedPath != "" {
			fmt.Printf("  signed_manifest: %s\n", result.ManifestSignedPath)
			fmt.Printf("  signed_manifest_ref: %s %s\n", result.ManifestSignedArtifactRef.URI, result.ManifestSignedArtifactRef.SHA256)
		}
	}
}

func migrate(args []string) {
	fs := flag.NewFlagSet("forge migrate", flag.ExitOnError)
	managementPostgresDSN := fs.String("management-postgres-dsn", "", "Postgres DSN for KLIQ management migrations")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *managementPostgresDSN == "" {
		fmt.Fprintln(os.Stderr, "forge migrate requires --management-postgres-dsn")
		os.Exit(2)
	}
	store, err := management.OpenPostgres(context.Background(), *managementPostgresDSN)
	if err != nil {
		logger.Error("forge_migrate_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := store.Close(); err != nil {
		logger.Error("forge_migrate_close_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logger.Info("forge_migrate_complete", "management_store", "postgres")
	fmt.Println("forge management migrations applied")
}

func api(args []string) {
	fs := flag.NewFlagSet("forge api", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "HTTP listen address")
	queueKind := fs.String("queue", "redis", "job queue backend: redis or memory")
	redisAddr := fs.String("redis-addr", "127.0.0.1:6379", "Redis address")
	enableDevTokens := fs.Bool("dev-tokens", false, "enable local dev token provider")
	oidcIssuer := fs.String("oidc-issuer", "", "expected JWT issuer")
	oidcAudience := fs.String("oidc-audience", "", "expected JWT audience")
	oidcHMACSecret := fs.String("oidc-hmac-secret", "", "HS256 secret for local OIDC/OAuth2 JWT verification")
	oidcRSAPublicKey := fs.String("oidc-rsa-public-key", "", "PEM-encoded RSA public key for RS256 OIDC/OAuth2 JWT verification")
	managementSigningKey := fs.String("management-signing-key", "./var/kernloom/forge/management.ed25519.json", "dev-local signing key for KLIQ assignments")
	managementStoreKind := fs.String("management-store", "postgres", "KLIQ management store backend: postgres or memory")
	managementPostgresDSN := fs.String("management-postgres-dsn", "", "Postgres DSN for KLIQ management store")
	devManagement := fs.Bool("dev-management", false, "enable explicit dev-only in-memory management store and manual assignment API")
	devSeedManagementTrust := fs.Bool("dev-seed-management-trust", false, "explicitly seed missing management trust bundle from the dev-local signer; never use in production")
	kliqServiceTokenSecret := fs.String("kliq-service-token-secret", "", "dev-only HMAC secret for KLIQ service tokens; requires --dev-allow-cli-kliq-service-token-secret")
	kliqServiceTokenSecretFile := fs.String("kliq-service-token-secret-file", "", "file containing HMAC secret for KLIQ service tokens")
	devAllowCLIKLIQServiceTokenSecret := fs.Bool("dev-allow-cli-kliq-service-token-secret", false, "allow KLIQ service-token HMAC secret via argv; dev/risk-accepted only")
	artifactStoreRoot := fs.String("artifact-store-root", "../enterprise-kernloom-policies/generated/artifact-store", "fs artifact store root for approved Forge artifacts")
	artifactStoreOrg := fs.String("artifact-store-org", "kernloom", "artifact store organization path segment")
	artifactStoreEnvironment := fs.String("artifact-store-env", "dev", "artifact store environment path segment")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := jobStore(*queueKind, *redisAddr)
	if err != nil {
		logger.Error("forge_job_store_failed", "queue", *queueKind, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	authenticator, err := authenticator(*enableDevTokens, *oidcIssuer, *oidcAudience, *oidcHMACSecret, *oidcRSAPublicKey)
	if err != nil {
		logger.Error("forge_authenticator_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *enableDevTokens {
		logger.Warn("forge_dev_tokens_enabled", "message", "local dev bearer tokens are enabled; do not use this mode for production")
	}
	if len(authenticator) == 0 {
		fmt.Fprintln(os.Stderr, "forge api requires at least one auth provider")
		os.Exit(2)
	}
	managementSigner, err := signing.LoadOrCreateDevLocalSigner(*managementSigningKey, "forge-management-dev-local")
	if err != nil {
		logger.Error("forge_management_signer_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	managementBackend, err := managementStore(*managementStoreKind, *managementPostgresDSN, *devManagement)
	if err != nil {
		logger.Error("forge_management_store_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := validateOrSeedManagementTrustBundle(managementBackend, managementSigner, *devSeedManagementTrust); err != nil {
		logger.Error("forge_management_trust_bundle_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *devSeedManagementTrust {
		logger.Warn("forge_management_trust_seed_enabled", "message", "management trust bootstrap from local signer is explicit dev-only behavior")
	}
	authenticator = append(authenticator, authn.KLIQIdentityTokenVerifier{Store: managementBackend})
	var kliqService *authn.KLIQServiceTokenIssuer
	kliqSecret, err := loadKLIQServiceTokenSecret(*kliqServiceTokenSecret, *kliqServiceTokenSecretFile, *devAllowCLIKLIQServiceTokenSecret)
	if err != nil {
		logger.Error("forge_kliq_service_token_secret_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(kliqSecret) != 0 {
		kliqService = &authn.KLIQServiceTokenIssuer{Secret: kliqSecret}
	}
	if kliqService != nil {
		authenticator = append(authenticator, kliqService)
	}
	server := forgeapi.Server{
		Authenticator:  authenticator,
		Store:          store,
		Management:     managementBackend,
		ManagementSign: managementSigner,
		Artifacts:      artifactstore.NewFSStore(*artifactStoreRoot, *artifactStoreOrg, *artifactStoreEnvironment),
		KLIQService:    kliqService,
		DevManagement:  *devManagement,
	}
	logger.Info("forge_api_starting", "addr", *addr, "queue", *queueKind)
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		logger.Error("forge_api_failed", "addr", *addr, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadKLIQServiceTokenSecret(flagValue, filePath string, allowCLI bool) ([]byte, error) {
	flagValue = strings.TrimSpace(flagValue)
	filePath = strings.TrimSpace(filePath)
	envValue := strings.TrimSpace(os.Getenv("KERNLOOM_KLIQ_SERVICE_TOKEN_SECRET"))
	if flagValue != "" && !allowCLI {
		return nil, fmt.Errorf("--kliq-service-token-secret exposes secrets via process argv; use --kliq-service-token-secret-file or KERNLOOM_KLIQ_SERVICE_TOKEN_SECRET, or pass --dev-allow-cli-kliq-service-token-secret for local smoke tests")
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimSpace(string(data))), nil
	}
	if envValue != "" {
		return []byte(envValue), nil
	}
	if flagValue != "" {
		return []byte(flagValue), nil
	}
	return nil, nil
}

func authenticator(enableDevTokens bool, issuer, audience, hmacSecret, rsaPublicKeyPath string) (authn.Chain, error) {
	var chain authn.Chain
	if enableDevTokens {
		chain = append(chain, authn.DevTokenVerifier{})
	}
	if hmacSecret != "" || rsaPublicKeyPath != "" {
		publicKey, err := loadRSAPublicKey(rsaPublicKeyPath)
		if err != nil {
			return nil, err
		}
		chain = append(chain, authn.JWTVerifier{
			Issuer:       issuer,
			Audience:     audience,
			HMACSecret:   []byte(hmacSecret),
			RSAPublicKey: publicKey,
		})
	}
	return chain, nil
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("%s: PEM block is not an RSA public key", path)
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid RSA public key: %w", path, err)
	}
	return key, nil
}

func jobStore(kind, redisAddr string) (jobs.Store, error) {
	switch kind {
	case "memory":
		return jobs.NewMemoryStore(), nil
	case "redis":
		return jobs.NewRedisStore(redisAddr), nil
	default:
		return nil, fmt.Errorf("unsupported queue %q", kind)
	}
}

func managementStore(kind, postgresDSN string, devManagement bool) (management.Store, error) {
	switch kind {
	case "memory":
		if !devManagement {
			return nil, fmt.Errorf("memory management store requires --dev-management")
		}
		logger.Warn("forge_management_memory_store_enabled", "message", "in-memory KLIQ management is dev/smoke-test only")
		return management.NewMemoryStore(), nil
	case "postgres":
		return management.OpenPostgres(context.Background(), postgresDSN)
	default:
		return nil, fmt.Errorf("unsupported management store %q", kind)
	}
}

func validateOrSeedManagementTrustBundle(store management.Store, signer *signing.DevLocalSigner, allowDevSeed bool) error {
	if signer == nil {
		return nil
	}
	publicKey := base64.StdEncoding.EncodeToString(signer.PublicKey)
	existing, err := store.TrustBundle(context.Background(), signer.KeyID)
	if err == nil {
		if existing.PublicKey != publicKey {
			return fmt.Errorf("existing management trust bundle %q public key does not match signing key", signer.KeyID)
		}
		if existing.Purpose != "assignment_verification" {
			return fmt.Errorf("existing management trust bundle %q has purpose %q, expected assignment_verification", signer.KeyID, existing.Purpose)
		}
		if existing.Status != "active" && existing.Status != "previous" {
			return fmt.Errorf("existing management trust bundle %q is %q", signer.KeyID, existing.Status)
		}
		if !existing.ExpiresAt.IsZero() && !time.Now().UTC().Before(existing.ExpiresAt.UTC()) {
			return fmt.Errorf("existing management trust bundle %q is expired", signer.KeyID)
		}
		return nil
	}
	if err != nil && !errors.Is(err, management.ErrNotFound) {
		return err
	}
	if !allowDevSeed {
		return fmt.Errorf("management trust bundle %q is not provisioned; use explicit trust provisioning or --dev-seed-management-trust for local smoke tests", signer.KeyID)
	}
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	return store.SaveTrustBundle(context.Background(), domain.TrustBundle{
		KeyID:     signer.KeyID,
		PublicKey: publicKey,
		Purpose:   "assignment_verification",
		Status:    "active",
		ExpiresAt: expiresAt,
		Issuer:    "forge-management-dev-local",
	})
}
