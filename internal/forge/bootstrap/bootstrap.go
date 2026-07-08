// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bootstrap

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Forge ForgeConfig `yaml:"forge" json:"forge"`
}

type ForgeConfig struct {
	Bootstrap Root `yaml:"bootstrap" json:"bootstrap"`
}

type Root struct {
	EnterpriseRegistryRepo string        `yaml:"enterprise_registry_repo" json:"enterprise_registry_repo"`
	EnterpriseRegistryRef  string        `yaml:"enterprise_registry_ref" json:"enterprise_registry_ref"`
	CredentialRef          string        `yaml:"credential_ref" json:"credential_ref"`
	TrustAnchors           []TrustAnchor `yaml:"trust_anchors" json:"trust_anchors"`
}

type TrustAnchor struct {
	KeyID   string `yaml:"key_id" json:"key_id"`
	Purpose string `yaml:"purpose" json:"purpose"`
}

func Load(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, fmt.Errorf("bootstrap config path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	root := c.Forge.Bootstrap
	if strings.TrimSpace(root.EnterpriseRegistryRepo) == "" {
		return fmt.Errorf("bootstrap_registry_missing: enterprise_registry_repo is required")
	}
	if strings.TrimSpace(root.EnterpriseRegistryRef) == "" {
		return fmt.Errorf("bootstrap_registry_missing: enterprise_registry_ref is required")
	}
	if strings.TrimSpace(root.CredentialRef) == "" {
		return fmt.Errorf("bootstrap_credential_unavailable: credential_ref is required")
	}
	if len(root.TrustAnchors) == 0 {
		return fmt.Errorf("bootstrap_registry_untrusted: at least one trust anchor is required")
	}
	for _, anchor := range root.TrustAnchors {
		if strings.TrimSpace(anchor.KeyID) == "" {
			return fmt.Errorf("bootstrap_registry_untrusted: trust anchor key_id is required")
		}
		if strings.TrimSpace(anchor.Purpose) == "" {
			return fmt.Errorf("bootstrap_registry_untrusted: trust anchor purpose is required")
		}
	}
	return nil
}
