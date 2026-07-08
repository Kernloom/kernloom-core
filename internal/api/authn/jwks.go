// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package authn

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type RSAPublicKeyProvider interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

type RefreshingJWKSOptions struct {
	URL                string
	Client             *http.Client
	RefreshInterval    time.Duration
	MinRefreshInterval time.Duration
	Now                func() time.Time
}

type RefreshingJWKS struct {
	url                string
	client             *http.Client
	refreshInterval    time.Duration
	minRefreshInterval time.Duration
	now                func() time.Time

	refreshMu sync.Mutex
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	etag      string
	modified  string
	lastFetch time.Time
	lastOK    time.Time
	lastErr   error
}

func LoadJWKS(ctx context.Context, jwksURL string) (map[string]*rsa.PublicKey, error) {
	jwksURL = strings.TrimSpace(jwksURL)
	if jwksURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("jwks fetch failed: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseJWKS(data)
}

func NewRefreshingJWKS(ctx context.Context, opts RefreshingJWKSOptions) (*RefreshingJWKS, error) {
	opts.URL = strings.TrimSpace(opts.URL)
	if opts.URL == "" {
		return nil, fmt.Errorf("jwks url is required")
	}
	refreshInterval := opts.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = 10 * time.Minute
	}
	minRefreshInterval := opts.MinRefreshInterval
	if minRefreshInterval <= 0 {
		minRefreshInterval = 30 * time.Second
	}
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	jwks := &RefreshingJWKS{
		url:                opts.URL,
		client:             client,
		refreshInterval:    refreshInterval,
		minRefreshInterval: minRefreshInterval,
		now:                now,
		keys:               map[string]*rsa.PublicKey{},
	}
	if err := jwks.Refresh(ctx); err != nil {
		return nil, err
	}
	return jwks, nil
}

func (j *RefreshingJWKS) Start(ctx context.Context) {
	if j == nil || j.refreshInterval <= 0 {
		return
	}
	go func() {
		for {
			timer := time.NewTimer(j.currentRefreshInterval())
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				_ = j.Refresh(ctx)
			}
		}
	}()
}

func (j *RefreshingJWKS) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	key, err := j.cachedKey(kid)
	if err == nil {
		return key, nil
	}
	if j.canRefreshForKeyMiss() {
		if refreshErr := j.Refresh(ctx); refreshErr != nil {
			return nil, fmt.Errorf("%w; jwks refresh failed: %v", err, refreshErr)
		}
	}
	return j.cachedKey(kid)
}

func (j *RefreshingJWKS) Refresh(ctx context.Context) error {
	if j == nil {
		return fmt.Errorf("jwks provider is nil")
	}
	j.refreshMu.Lock()
	defer j.refreshMu.Unlock()

	j.mu.RLock()
	etag := j.etag
	modified := j.modified
	j.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		j.recordFetchError(err)
		return err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if modified != "" {
		req.Header.Set("If-Modified-Since", modified)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		j.recordFetchError(err)
		return err
	}
	defer resp.Body.Close()

	now := j.now().UTC()
	if resp.StatusCode == http.StatusNotModified {
		j.mu.Lock()
		j.lastFetch = now
		j.lastOK = now
		j.lastErr = nil
		j.mu.Unlock()
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("jwks fetch failed: %s", resp.Status)
		j.recordFetchError(err)
		return err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		j.recordFetchError(err)
		return err
	}
	keys, err := ParseJWKS(data)
	if err != nil {
		j.recordFetchError(err)
		return err
	}
	j.mu.Lock()
	j.keys = keys
	j.etag = strings.TrimSpace(resp.Header.Get("ETag"))
	j.modified = strings.TrimSpace(resp.Header.Get("Last-Modified"))
	j.refreshInterval = refreshIntervalFromHeaders(resp.Header, j.refreshInterval)
	j.lastFetch = now
	j.lastOK = now
	j.lastErr = nil
	j.mu.Unlock()
	return nil
}

func (j *RefreshingJWKS) cachedKey(kid string) (*rsa.PublicKey, error) {
	kid = strings.TrimSpace(kid)
	j.mu.RLock()
	defer j.mu.RUnlock()
	if len(j.keys) == 0 {
		if j.lastErr != nil {
			return nil, j.lastErr
		}
		return nil, ErrUnauthenticated
	}
	if kid != "" {
		key, ok := j.keys[kid]
		if !ok || key == nil {
			return nil, fmt.Errorf("jwt kid %q is not trusted", kid)
		}
		return key, nil
	}
	if len(j.keys) == 1 {
		for _, key := range j.keys {
			if key != nil {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("jwt kid is required when multiple JWKS keys are configured")
}

func (j *RefreshingJWKS) canRefreshForKeyMiss() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if len(j.keys) == 0 {
		return true
	}
	return j.now().UTC().Sub(j.lastFetch) >= j.minRefreshInterval
}

func (j *RefreshingJWKS) recordFetchError(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lastFetch = j.now().UTC()
	j.lastErr = err
}

func (j *RefreshingJWKS) currentRefreshInterval() time.Duration {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.refreshInterval <= 0 {
		return 10 * time.Minute
	}
	return j.refreshInterval
}

func ParseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for index, key := range doc.Keys {
		if strings.ToUpper(strings.TrimSpace(key.Kty)) != "RSA" {
			continue
		}
		if strings.TrimSpace(key.Use) != "" && strings.TrimSpace(key.Use) != "sig" {
			continue
		}
		if strings.TrimSpace(key.Alg) != "" && strings.TrimSpace(key.Alg) != "RS256" {
			continue
		}
		publicKey, err := parseJWKRSAKey(key)
		if err != nil {
			return nil, fmt.Errorf("jwks key %q invalid: %w", key.Kid, err)
		}
		kid := strings.TrimSpace(key.Kid)
		if kid == "" {
			kid = fmt.Sprintf("jwks.key.%d", index)
		}
		if _, exists := keys[kid]; exists {
			return nil, fmt.Errorf("duplicate jwks kid %q", kid)
		}
		keys[kid] = publicKey
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks contains no usable RS256 signing keys")
	}
	return keys, nil
}

func refreshIntervalFromHeaders(header http.Header, fallback time.Duration) time.Duration {
	cacheControl := header.Get("Cache-Control")
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "max-age=") {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
		if err != nil || seconds <= 0 {
			continue
		}
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func parseJWKRSAKey(key jwkKey) (*rsa.PublicKey, error) {
	if strings.TrimSpace(key.N) == "" || strings.TrimSpace(key.E) == "" {
		return nil, fmt.Errorf("missing modulus or exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	exponent := int(new(big.Int).SetBytes(eBytes).Int64())
	if exponent < 3 {
		return nil, fmt.Errorf("invalid rsa exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: exponent,
	}, nil
}
