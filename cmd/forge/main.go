// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/kernloom/kernloom-core/internal/api/authn"
	"github.com/kernloom/kernloom-core/internal/core/version"
	forgeapi "github.com/kernloom/kernloom-core/internal/forge/api"
	"github.com/kernloom/kernloom-core/internal/forge/compiler"
	"github.com/kernloom/kernloom-core/internal/forge/jobs"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "compile" {
		compile(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "api" {
		api(os.Args[2:])
		return
	}
	fmt.Println(version.Binary("forge"))
	fmt.Println("usage: forge compile [--policy-repo path] [--policy-file path] [--core-registry path] [--enterprise-registry path] [--output-dir path]")
	fmt.Println("usage: forge api [--addr :8080] [--queue redis|memory] [--redis-addr 127.0.0.1:6379]")
}

func compile(args []string) {
	fs := flag.NewFlagSet("forge compile", flag.ExitOnError)
	opts := compiler.Options{}
	fs.StringVar(&opts.PolicyRepo, "policy-repo", "../enterprise-kernloom-policies", "path to enterprise policy repository")
	fs.StringVar(&opts.PolicyFile, "policy-file", "", "optional single KNI intent file to compile")
	fs.StringVar(&opts.CoreRegistry, "core-registry", "../kernloom-core-registry", "path to core registry repository")
	fs.StringVar(&opts.EnterpriseRegistry, "enterprise-registry", "../enterprise-kernloom-registry", "path to enterprise registry repository")
	fs.StringVar(&opts.OutputDir, "output-dir", "", "output directory; defaults to policy repo generated directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results, err := compiler.Compile(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, result := range results {
		fmt.Printf("%s\n", result.PolicyID)
		fmt.Printf("  review: %s\n", result.ReviewPath)
		fmt.Printf("  resolved: %s\n", result.ResolvedPath)
		fmt.Printf("  manifest: %s\n", result.ManifestPath)
	}
}

func api(args []string) {
	fs := flag.NewFlagSet("forge api", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "HTTP listen address")
	queueKind := fs.String("queue", "redis", "job queue backend: redis or memory")
	redisAddr := fs.String("redis-addr", "127.0.0.1:6379", "Redis address")
	enableDevTokens := fs.Bool("dev-tokens", true, "enable local dev token provider")
	oidcIssuer := fs.String("oidc-issuer", "", "expected JWT issuer")
	oidcAudience := fs.String("oidc-audience", "", "expected JWT audience")
	oidcHMACSecret := fs.String("oidc-hmac-secret", "", "HS256 secret for local OIDC/OAuth2 JWT verification")
	oidcRSAPublicKey := fs.String("oidc-rsa-public-key", "", "PEM-encoded RSA public key for RS256 OIDC/OAuth2 JWT verification")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := jobStore(*queueKind, *redisAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	authenticator, err := authenticator(*enableDevTokens, *oidcIssuer, *oidcAudience, *oidcHMACSecret, *oidcRSAPublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(authenticator) == 0 {
		fmt.Fprintln(os.Stderr, "forge api requires at least one auth provider")
		os.Exit(2)
	}
	server := forgeapi.Server{
		Authenticator: authenticator,
		Store:         store,
	}
	fmt.Printf("forge api listening on %s with %s queue\n", *addr, *queueKind)
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
