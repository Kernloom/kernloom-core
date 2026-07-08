// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler

import (
	"fmt"
	"strings"

	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
)

type AdapterRuntimeDescribe struct {
	ManifestDigest string
	Descriptor     *adapterv1.AdapterDescriptor
}

func ValidateAdapterRuntimeDescribe(manifest AdapterManifest, describe AdapterRuntimeDescribe) error {
	desc := describe.Descriptor
	if desc == nil {
		return fmt.Errorf("adapter_runtime_describe_invalid: descriptor is required")
	}
	if err := adapterv1.ValidateDescriptor(desc); err != nil {
		return fmt.Errorf("adapter_runtime_describe_invalid: %w", err)
	}
	manifestDigest := strings.TrimSpace(describe.ManifestDigest)
	if manifestDigest == "" {
		manifestDigest = strings.TrimSpace(desc.GetManifestDigest())
	}
	if manifestDigest == "" {
		return fmt.Errorf("adapter_runtime_describe_invalid: adapter %q did not report manifest digest", manifest.AdapterID)
	}
	if strings.TrimSpace(manifest.Digest) == "" {
		return fmt.Errorf("adapter_runtime_describe_invalid: manifest %q has no digest", manifest.AdapterID)
	}
	if manifestDigest != manifest.Digest {
		return fmt.Errorf("adapter_runtime_describe_invalid: adapter %q manifest digest mismatch: describe=%s manifest=%s", manifest.AdapterID, manifestDigest, manifest.Digest)
	}
	if desc.GetAdapterId() != manifest.AdapterID {
		return fmt.Errorf("adapter_runtime_describe_invalid: descriptor adapter_id %q does not match manifest adapter_id %q", desc.GetAdapterId(), manifest.AdapterID)
	}
	if desc.GetProtocolVersion() != manifest.ProtocolVersion {
		return fmt.Errorf("adapter_runtime_describe_invalid: adapter %q protocol_version %q does not match manifest protocol_version %q", manifest.AdapterID, desc.GetProtocolVersion(), manifest.ProtocolVersion)
	}

	descriptorCapabilities := map[string]*adapterv1.CapabilityDescriptor{}
	for _, capability := range desc.GetCapabilities() {
		descriptorCapabilities[capability.GetId()] = capability
	}
	descriptorPrivileges := map[string]bool{}
	for _, privilege := range desc.GetPrivileges() {
		descriptorPrivileges[privilege.GetId()] = true
	}
	for _, capability := range manifest.Capabilities {
		if capability.ImplementationStatus != "implemented" {
			continue
		}
		descriptorCapability, ok := descriptorCapabilities[capability.CapabilityID]
		if !ok {
			return fmt.Errorf("adapter_runtime_describe_invalid: adapter %q descriptor omits implemented capability %q", manifest.AdapterID, capability.CapabilityID)
		}
		descriptorActions := append([]string{}, descriptorCapability.GetActions()...)
		descriptorActions = append(descriptorActions, descriptorCapability.GetRuntimeActions()...)
		for _, action := range capability.SupportedActions {
			if !containsString(descriptorActions, action) {
				return fmt.Errorf("adapter_runtime_describe_invalid: adapter %q descriptor capability %q omits manifest action %q", manifest.AdapterID, capability.CapabilityID, action)
			}
		}
		for _, privilege := range capability.RequiredPrivileges {
			if !descriptorPrivileges[privilege] {
				return fmt.Errorf("adapter_runtime_describe_invalid: adapter %q descriptor omits manifest privilege %q for capability %q", manifest.AdapterID, privilege, capability.CapabilityID)
			}
		}
	}
	return nil
}
