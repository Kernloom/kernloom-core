// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bindings

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Store struct {
	PolicyRepo                 string
	EnterpriseRegistry         string
	RepositoryBindingsPath     string
	RepositoryBindingsDigest   string
	PolicySourcesPath          string
	PolicySourcesDigest        string
	CanonicalActionsPath       string
	CanonicalActionsDigest     string
	Repositories               []RepositoryBinding
	PolicySources              []PolicySource
	CanonicalActions           []CanonicalAction
	Targets                    []TargetInventory
	ActionBindingFiles         []ActionBindingFile
	ResourceFiles              []ResourceFile
	ProofRequirementFiles      []ProofRequirementFile
	repositoryByRef            map[string]RepositoryBinding
	canonicalActionByID        map[string]CanonicalAction
	resourceByTenantEnvID      map[string]ResourceFile
	proofByTenantEnvResourceID map[string]ProofRequirementFile
}

type RepositoryBinding struct {
	ID            string `yaml:"id" json:"id"`
	Type          string `yaml:"type,omitempty" json:"type,omitempty"`
	Provider      string `yaml:"provider,omitempty" json:"provider,omitempty"`
	Org           string `yaml:"org,omitempty" json:"org,omitempty"`
	Repo          string `yaml:"repo,omitempty" json:"repo,omitempty"`
	DefaultBranch string `yaml:"default_branch,omitempty" json:"default_branch,omitempty"`
	OwnerTeam     string `yaml:"owner_team,omitempty" json:"owner_team,omitempty"`
	Visibility    string `yaml:"visibility,omitempty" json:"visibility,omitempty"`
}

type CanonicalAction struct {
	ID               string   `yaml:"id" json:"id"`
	Type             string   `yaml:"type" json:"type"`
	Sensitivity      string   `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
	Owner            string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	Description      string   `yaml:"description,omitempty" json:"description,omitempty"`
	RequiredControls []string `yaml:"required_controls,omitempty" json:"required_controls,omitempty"`
	RequiredEvents   []string `yaml:"required_events,omitempty" json:"required_events,omitempty"`
}

type PolicySource struct {
	ID               string          `yaml:"id" json:"id"`
	Type             string          `yaml:"type" json:"type"`
	RepoRef          string          `yaml:"repo_ref" json:"repo_ref"`
	TenantScope      string          `yaml:"tenant_scope" json:"tenant_scope"`
	EnvironmentScope string          `yaml:"environment_scope" json:"environment_scope"`
	ResourceScope    []string        `yaml:"resource_scope,omitempty" json:"resource_scope,omitempty"`
	TargetScope      []string        `yaml:"target_scope,omitempty" json:"target_scope,omitempty"`
	Visibility       string          `yaml:"visibility,omitempty" json:"visibility,omitempty"`
	Owner            string          `yaml:"owner,omitempty" json:"owner,omitempty"`
	PolicyPaths      []string        `yaml:"policy_paths,omitempty" json:"policy_paths,omitempty"`
	PolicyMeanings   []PolicyMeaning `yaml:"policy_meanings,omitempty" json:"policy_meanings,omitempty"`
}

type PolicyMeaning struct {
	PolicyPath       string   `yaml:"policy_path" json:"policy_path"`
	CanonicalActions []string `yaml:"canonical_actions,omitempty" json:"canonical_actions,omitempty"`
	ActionTypes      []string `yaml:"action_types,omitempty" json:"action_types,omitempty"`
}

type ResolvedPolicySource struct {
	Source      PolicySource      `json:"source"`
	Repository  RepositoryBinding `json:"repository"`
	PolicyFiles []PolicyFileRef   `json:"policy_files,omitempty"`
}

type PolicyFileRef struct {
	Path    string `json:"path"`
	RelPath string `json:"rel_path"`
	Digest  string `json:"digest"`
}

type TargetInventory struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Target Target `yaml:"target" json:"target"`
}

type Target struct {
	ID                 string            `yaml:"id" json:"id"`
	Tenant             string            `yaml:"tenant" json:"tenant"`
	Environment        string            `yaml:"environment" json:"environment"`
	Type               string            `yaml:"type" json:"type"`
	Adapter            string            `yaml:"adapter" json:"adapter"`
	AdapterVersion     string            `yaml:"adapter_version,omitempty" json:"adapter_version,omitempty"`
	Capabilities       []string          `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	ValidationProfiles []string          `yaml:"validation_profiles,omitempty" json:"validation_profiles,omitempty"`
	ConfigBackend      TargetSource      `yaml:"config_backend,omitempty" json:"config_backend,omitempty"`
	ValidationSource   TargetSource      `yaml:"validation_source,omitempty" json:"validation_source,omitempty"`
	Runtime            TargetRuntime     `yaml:"runtime,omitempty" json:"runtime,omitempty"`
	Ownership          map[string]string `yaml:"ownership,omitempty" json:"ownership,omitempty"`
}

type TargetSource struct {
	Mode           string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	RepoRef        string   `yaml:"repo_ref,omitempty" json:"repo_ref,omitempty"`
	Branch         string   `yaml:"branch,omitempty" json:"branch,omitempty"`
	BasePath       string   `yaml:"base_path,omitempty" json:"base_path,omitempty"`
	ProposalMode   string   `yaml:"proposal_mode,omitempty" json:"proposal_mode,omitempty"`
	ProtectedPaths []string `yaml:"protected_paths,omitempty" json:"protected_paths,omitempty"`
	CredentialRef  string   `yaml:"credential_ref,omitempty" json:"credential_ref,omitempty"`
}

type TargetRuntime struct {
	KLIQRef string `yaml:"kliq_ref,omitempty" json:"kliq_ref,omitempty"`
}

type ResourceFile struct {
	Path     string   `json:"path"`
	Digest   string   `json:"digest"`
	Resource Resource `yaml:"resource" json:"resource"`
}

type ProofRequirementFile struct {
	Path              string            `json:"path"`
	Digest            string            `json:"digest"`
	ProofRequirements ProofRequirements `yaml:"proof_requirements" json:"proof_requirements"`
}

type ProofRequirements struct {
	Tenant       string             `yaml:"tenant" json:"tenant"`
	Environment  string             `yaml:"environment" json:"environment"`
	Resource     string             `yaml:"resource" json:"resource"`
	Requirements []ProofRequirement `yaml:"requirements,omitempty" json:"requirements,omitempty"`
}

type ProofRequirement struct {
	ID       string   `yaml:"id" json:"id"`
	Evidence []string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type Resource struct {
	ID          string `yaml:"id" json:"id"`
	Tenant      string `yaml:"tenant" json:"tenant"`
	Environment string `yaml:"environment" json:"environment"`
	Type        string `yaml:"type,omitempty" json:"type,omitempty"`
	Owner       string `yaml:"owner,omitempty" json:"owner,omitempty"`
}

type ActionBindingFile struct {
	Path        string           `json:"path"`
	Digest      string           `json:"digest"`
	Application Application      `yaml:"application" json:"application"`
	Actions     []BusinessAction `yaml:"actions" json:"actions"`
}

type Application struct {
	ID          string `yaml:"id" json:"id"`
	Tenant      string `yaml:"tenant" json:"tenant"`
	Environment string `yaml:"environment" json:"environment"`
}

type BusinessAction struct {
	ID              string          `yaml:"id" json:"id"`
	CanonicalAction string          `yaml:"canonical_action" json:"canonical_action"`
	Type            string          `yaml:"type" json:"type"`
	Sensitivity     string          `yaml:"sensitivity" json:"sensitivity"`
	Description     string          `yaml:"description,omitempty" json:"description,omitempty"`
	Bindings        []ActionBinding `yaml:"bindings,omitempty" json:"bindings,omitempty"`
	Approval        Approval        `yaml:"approval,omitempty" json:"approval,omitempty"`
}

type ActionBinding struct {
	ID         string         `yaml:"id" json:"id"`
	TargetRef  string         `yaml:"target_ref" json:"target_ref"`
	Capability string         `yaml:"capability" json:"capability"`
	Selector   map[string]any `yaml:"selector,omitempty" json:"selector,omitempty"`
	Controls   []string       `yaml:"controls,omitempty" json:"controls,omitempty"`
	Issuance   map[string]any `yaml:"issuance,omitempty" json:"issuance,omitempty"`
	Proof      Proof          `yaml:"proof,omitempty" json:"proof,omitempty"`
	Approval   Approval       `yaml:"approval,omitempty" json:"approval,omitempty"`
}

type Proof struct {
	ExpectedEvents []string `yaml:"expected_events,omitempty" json:"expected_events,omitempty"`
}

type Approval struct {
	Status     string `yaml:"status,omitempty" json:"status,omitempty"`
	ApprovedBy string `yaml:"approved_by,omitempty" json:"approved_by,omitempty"`
	ApprovedAt string `yaml:"approved_at,omitempty" json:"approved_at,omitempty"`
}

type ResolvedTarget struct {
	Repository    RepositoryBinding      `json:"repository"`
	Target        TargetInventory        `json:"target"`
	Bindings      []ResolvedBinding      `json:"bindings"`
	PolicySources []ResolvedPolicySource `json:"policy_sources"`
}

type ResolvedBinding struct {
	File              ActionBindingFile     `json:"file"`
	Action            BusinessAction        `json:"action"`
	Binding           ActionBinding         `json:"binding"`
	Target            TargetInventory       `json:"target"`
	TargetPath        string                `json:"target_path"`
	Resource          *ResourceFile         `json:"resource,omitempty"`
	ProofRequirements *ProofRequirementFile `json:"proof_requirements,omitempty"`
	ResourceRef       string                `json:"resource_ref,omitempty"`
	ActionURN         string                `json:"action_urn,omitempty"`
}

type CIRequest struct {
	Tenant       string
	Environment  string
	Provider     string
	Repository   string
	BasePath     string
	TargetID     string
	ChangedPaths []string
}

func Load(policyRepo, enterpriseRegistry string) (Store, error) {
	store := Store{PolicyRepo: policyRepo, EnterpriseRegistry: enterpriseRegistry}
	repositoryBindingsPath := filepath.Join(enterpriseRegistry, "bindings", "repository_bindings.yaml")
	repositories, repositoryBindingsDigest, err := loadRepositoryBindings(repositoryBindingsPath)
	if err != nil {
		return Store{}, err
	}
	canonicalActionsPath := filepath.Join(enterpriseRegistry, "enterprise", "canonical_actions.yaml")
	canonicalActions, canonicalActionsDigest, err := loadCanonicalActions(canonicalActionsPath)
	if err != nil {
		return Store{}, err
	}
	policySourcesPath := filepath.Join(enterpriseRegistry, "bindings", "policy_sources.yaml")
	policySources, policySourcesDigest, err := loadPolicySources(policySourcesPath)
	if err != nil {
		return Store{}, err
	}
	store.RepositoryBindingsPath = absPath(repositoryBindingsPath)
	store.RepositoryBindingsDigest = repositoryBindingsDigest
	store.CanonicalActionsPath = absPath(canonicalActionsPath)
	store.CanonicalActionsDigest = canonicalActionsDigest
	store.PolicySourcesPath = absPath(policySourcesPath)
	store.PolicySourcesDigest = policySourcesDigest
	store.Repositories = repositories
	store.CanonicalActions = canonicalActions
	store.PolicySources = policySources
	store.indexRepositories()
	store.indexCanonicalActions()
	if err := store.validatePolicySources(); err != nil {
		return Store{}, err
	}
	if err := store.loadTenantFiles(); err != nil {
		return Store{}, err
	}
	store.indexTenantFiles()
	return store, nil
}

func (s Store) ResolveCIRequest(req CIRequest) (ResolvedTarget, error) {
	repo, ok := s.repositoryByIdentity(req.Provider, req.Repository)
	if !ok {
		return ResolvedTarget{}, codedError("repo_not_registered", "repository %q is not registered", req.Repository)
	}
	targets := s.targetsForRepo(req.Tenant, req.Environment, repo.ID, req.BasePath, req.TargetID)
	switch len(targets) {
	case 0:
		return ResolvedTarget{}, codedError("validation_target_not_found", "no target matches tenant=%q environment=%q repo_ref=%q base_path=%q target_id=%q", req.Tenant, req.Environment, repo.ID, req.BasePath, req.TargetID)
	case 1:
	default:
		return ResolvedTarget{}, codedError("ambiguous_validation_target", "repository %q base_path %q maps to %d targets; pass --target-id", req.Repository, req.BasePath, len(targets))
	}
	target := targets[0]
	bindings, err := s.bindingsForTarget(target)
	if err != nil {
		return ResolvedTarget{}, err
	}
	policySources, err := s.policySourcesForTarget(repo, target, bindings)
	if err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{Repository: repo, Target: target, Bindings: bindings, PolicySources: policySources}, nil
}

func (s Store) PolicyFiles(sources []ResolvedPolicySource) []PolicyFileRef {
	seen := map[string]bool{}
	var files []PolicyFileRef
	for _, source := range sources {
		if source.Source.Type != "policy_repo" {
			continue
		}
		for _, file := range source.PolicyFiles {
			if seen[file.Path] {
				continue
			}
			seen[file.Path] = true
			files = append(files, file)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].RelPath < files[j].RelPath
	})
	return files
}

func (s *Store) indexRepositories() {
	s.repositoryByRef = map[string]RepositoryBinding{}
	for _, repo := range s.Repositories {
		s.repositoryByRef[repo.ID] = repo
	}
}

func (s *Store) indexCanonicalActions() {
	s.canonicalActionByID = map[string]CanonicalAction{}
	for _, action := range s.CanonicalActions {
		s.canonicalActionByID[action.ID] = action
	}
}

func (s *Store) indexTenantFiles() {
	s.resourceByTenantEnvID = map[string]ResourceFile{}
	for _, resource := range s.ResourceFiles {
		s.resourceByTenantEnvID[tenantEnvID(resource.Resource.Tenant, resource.Resource.Environment, resource.Resource.ID)] = resource
	}
	s.proofByTenantEnvResourceID = map[string]ProofRequirementFile{}
	for _, proof := range s.ProofRequirementFiles {
		s.proofByTenantEnvResourceID[tenantEnvID(proof.ProofRequirements.Tenant, proof.ProofRequirements.Environment, proof.ProofRequirements.Resource)] = proof
	}
}

func (s Store) CanonicalAction(id string) (CanonicalAction, bool) {
	id = strings.TrimSpace(id)
	if s.canonicalActionByID != nil {
		action, ok := s.canonicalActionByID[id]
		return action, ok
	}
	for _, action := range s.CanonicalActions {
		if strings.TrimSpace(action.ID) == id {
			return action, true
		}
	}
	return CanonicalAction{}, false
}

func (s Store) repositoryByIdentity(provider, repository string) (RepositoryBinding, bool) {
	provider = strings.TrimSpace(provider)
	repository = strings.Trim(strings.TrimSpace(repository), "/")
	for _, repo := range s.Repositories {
		if provider != "" && repo.Provider != "" && provider != repo.Provider {
			continue
		}
		if repository == repo.ID || repository == repo.Repo || repository == repo.Org+"/"+repo.Repo {
			return repo, true
		}
	}
	return RepositoryBinding{}, false
}

func (s Store) targetsForRepo(tenant, environment, repoRef, basePath, targetID string) []TargetInventory {
	var matches []TargetInventory
	for _, target := range s.Targets {
		if tenant != "" && target.Target.Tenant != tenant {
			continue
		}
		if environment != "" && target.Target.Environment != environment {
			continue
		}
		if targetID != "" && target.Target.ID != targetID {
			continue
		}
		if target.Target.ValidationSource.RepoRef != repoRef {
			continue
		}
		if basePath != "" && cleanRel(target.Target.ValidationSource.BasePath) != cleanRel(basePath) {
			continue
		}
		matches = append(matches, target)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Target.ID < matches[j].Target.ID
	})
	return matches
}

func (s Store) bindingsForTarget(target TargetInventory) ([]ResolvedBinding, error) {
	var resolved []ResolvedBinding
	for _, file := range s.ActionBindingFiles {
		if file.Application.Tenant != target.Target.Tenant || file.Application.Environment != target.Target.Environment {
			continue
		}
		for _, action := range file.Actions {
			if isSensitive(action.Sensitivity) && len(action.Bindings) == 0 {
				return nil, codedError("missing_action_binding", "sensitive action %q has no approved bindings", action.ID)
			}
			for _, binding := range action.Bindings {
				targetPath, err := s.resolveTargetRef(file, binding.TargetRef)
				if err != nil {
					return nil, err
				}
				if targetPath != target.Path {
					continue
				}
				resource := s.resourceForApplication(file.Application)
				proofRequirements := s.proofRequirementsForApplication(file.Application)
				resourceRef := URNForResource(file.Application.Tenant, file.Application.Environment, file.Application.ID)
				resolved = append(resolved, ResolvedBinding{
					File:              file,
					Action:            action,
					Binding:           binding,
					Target:            target,
					TargetPath:        targetPath,
					Resource:          resource,
					ProofRequirements: proofRequirements,
					ResourceRef:       resourceRef,
					ActionURN:         URNForAction(file.Application.Tenant, file.Application.Environment, file.Application.ID, action.ID),
				})
			}
		}
	}
	if len(resolved) == 0 {
		return nil, codedError("missing_action_binding", "target %q has no action bindings", target.Target.ID)
	}
	sort.Slice(resolved, func(i, j int) bool {
		if resolved[i].Action.ID == resolved[j].Action.ID {
			return resolved[i].Binding.ID < resolved[j].Binding.ID
		}
		return resolved[i].Action.ID < resolved[j].Action.ID
	})
	return resolved, nil
}

func (s Store) resourceForApplication(application Application) *ResourceFile {
	resource, ok := s.resourceByTenantEnvID[tenantEnvID(application.Tenant, application.Environment, application.ID)]
	if !ok {
		return nil
	}
	return &resource
}

func (s Store) proofRequirementsForApplication(application Application) *ProofRequirementFile {
	proof, ok := s.proofByTenantEnvResourceID[tenantEnvID(application.Tenant, application.Environment, application.ID)]
	if !ok {
		return nil
	}
	return &proof
}

func (s Store) policySourcesForTarget(requestRepo RepositoryBinding, target TargetInventory, resolvedBindings []ResolvedBinding) ([]ResolvedPolicySource, error) {
	var resolved []ResolvedPolicySource
	matchedConfigSource := false
	matchedPolicySource := false
	for _, source := range s.PolicySources {
		if !sourceMatchesScope(source, target, resolvedBindings) {
			continue
		}
		repo, ok := s.repositoryByRef[source.RepoRef]
		if !ok {
			return nil, codedError("policy_source_unavailable", "policy source %q references unknown repo_ref %q", source.ID, source.RepoRef)
		}
		if !visibilityAllowed(source, requestRepo, repo) {
			return nil, codedError("visibility_denied", "policy source %q has unsupported visibility %q for CI resolution", source.ID, source.Visibility)
		}
		switch source.Type {
		case "config_repo":
			if source.RepoRef != target.Target.ValidationSource.RepoRef {
				continue
			}
			matchedConfigSource = true
			resolved = append(resolved, ResolvedPolicySource{Source: source, Repository: repo})
		case "policy_repo":
			files, err := s.resolvePolicyFiles(source)
			if err != nil {
				return nil, err
			}
			if len(files) == 0 {
				return nil, codedError("policy_source_unavailable", "policy source %q does not include policy_paths", source.ID)
			}
			matchedPolicySource = true
			resolved = append(resolved, ResolvedPolicySource{Source: source, Repository: repo, PolicyFiles: files})
		default:
			return nil, codedError("policy_source_unavailable", "policy source %q has unsupported type %q", source.ID, source.Type)
		}
	}
	if !matchedConfigSource {
		return nil, codedError("policy_source_unavailable", "no config_repo policy source matches target %q repo_ref %q", target.Target.ID, target.Target.ValidationSource.RepoRef)
	}
	if !matchedPolicySource {
		return nil, codedError("policy_source_unavailable", "no policy_repo source matches target %q", target.Target.ID)
	}
	sort.Slice(resolved, func(i, j int) bool {
		return resolved[i].Source.ID < resolved[j].Source.ID
	})
	return resolved, nil
}

func (s Store) resolvePolicyFiles(source PolicySource) ([]PolicyFileRef, error) {
	var files []PolicyFileRef
	for _, relPath := range source.PolicyPaths {
		relPath = cleanRel(relPath)
		if relPath == "" {
			continue
		}
		path := filepath.Join(s.PolicyRepo, filepath.FromSlash(relPath))
		digest, err := fileSHA256Strict(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, codedError("policy_source_unavailable", "policy source %q references missing policy file %q", source.ID, relPath)
			}
			return nil, err
		}
		if digest == "sha256:unavailable" {
			return nil, codedError("source_digest_missing", "policy source %q cannot digest policy file %q", source.ID, relPath)
		}
		files = append(files, PolicyFileRef{Path: absPath(path), RelPath: relPath, Digest: digest})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].RelPath < files[j].RelPath
	})
	return files, nil
}

func (s Store) resolveTargetRef(file ActionBindingFile, targetRef string) (string, error) {
	targetRef = filepath.Clean(strings.TrimSpace(targetRef))
	if targetRef == "." || targetRef == "" {
		return "", codedError("validation_target_not_found", "%s: empty target_ref", file.Path)
	}
	candidates := []string{
		filepath.Join(s.PolicyRepo, "tenants", file.Application.Tenant, targetRef),
		filepath.Join(filepath.Dir(file.Path), targetRef),
	}
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		for _, target := range s.Targets {
			if target.Path == abs {
				return abs, nil
			}
		}
	}
	return "", codedError("validation_target_not_found", "%s: target_ref %q does not resolve to a target inventory", file.Path, targetRef)
}

func (s *Store) loadTenantFiles() error {
	root := filepath.Join(s.PolicyRepo, "tenants")
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch entry.Name() {
		case "resource.yaml":
			resource, err := loadResource(path)
			if err != nil {
				return err
			}
			s.ResourceFiles = append(s.ResourceFiles, resource)
		case "action-bindings.yaml":
			bindings, err := loadActionBindings(path)
			if err != nil {
				return err
			}
			s.ActionBindingFiles = append(s.ActionBindingFiles, bindings)
		case "proof-requirements.yaml":
			proofRequirements, err := loadProofRequirements(path)
			if err != nil {
				return err
			}
			s.ProofRequirementFiles = append(s.ProofRequirementFiles, proofRequirements)
		default:
			if strings.HasPrefix(filepath.ToSlash(path), filepath.ToSlash(root)+"/") && strings.Contains(filepath.ToSlash(path), "/targets/") && strings.HasSuffix(path, ".yaml") {
				target, err := loadTarget(path)
				if err != nil {
					return err
				}
				s.Targets = append(s.Targets, target)
			}
		}
		return nil
	})
}

func loadRepositoryBindings(path string) ([]RepositoryBinding, string, error) {
	var doc struct {
		Repositories []RepositoryBinding `yaml:"repositories"`
		Spec         struct {
			Repositories []RepositoryBinding `yaml:"repositories"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, "", err
	}
	repositories := doc.Repositories
	if len(repositories) == 0 {
		repositories = doc.Spec.Repositories
	}
	seen := map[string]bool{}
	for i, repo := range repositories {
		if strings.TrimSpace(repo.ID) == "" {
			return nil, "", fmt.Errorf("%s: repository binding %d missing id", path, i)
		}
		if strings.TrimSpace(repo.Repo) == "" {
			return nil, "", fmt.Errorf("%s: repository binding %q missing repo", path, repo.ID)
		}
		if seen[repo.ID] {
			return nil, "", fmt.Errorf("%s: duplicate repository binding %q", path, repo.ID)
		}
		seen[repo.ID] = true
	}
	return repositories, fileSHA256(path), nil
}

func loadPolicySources(path string) ([]PolicySource, string, error) {
	var doc struct {
		PolicySources []PolicySource `yaml:"policy_sources"`
		Spec          struct {
			PolicySources []PolicySource `yaml:"policy_sources"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		return nil, "", err
	}
	sources := doc.PolicySources
	if len(sources) == 0 {
		sources = doc.Spec.PolicySources
	}
	seen := map[string]bool{}
	for i, source := range sources {
		if strings.TrimSpace(source.ID) == "" {
			return nil, "", fmt.Errorf("%s: policy source %d missing id", path, i)
		}
		if strings.TrimSpace(source.Type) == "" {
			return nil, "", fmt.Errorf("%s: policy source %q missing type", path, source.ID)
		}
		if strings.TrimSpace(source.RepoRef) == "" {
			return nil, "", fmt.Errorf("%s: policy source %q missing repo_ref", path, source.ID)
		}
		if strings.TrimSpace(source.TenantScope) == "" {
			return nil, "", fmt.Errorf("%s: policy source %q missing tenant_scope", path, source.ID)
		}
		if strings.TrimSpace(source.EnvironmentScope) == "" {
			return nil, "", fmt.Errorf("%s: policy source %q missing environment_scope", path, source.ID)
		}
		if seen[source.ID] {
			return nil, "", fmt.Errorf("%s: duplicate policy source %q", path, source.ID)
		}
		seen[source.ID] = true
	}
	if len(sources) == 0 {
		return nil, "", fmt.Errorf("%s: at least one policy source is required", path)
	}
	return sources, fileSHA256(path), nil
}

func loadCanonicalActions(path string) ([]CanonicalAction, string, error) {
	var doc struct {
		Actions []CanonicalAction `yaml:"actions"`
		Spec    struct {
			Actions []CanonicalAction `yaml:"actions"`
		} `yaml:"spec"`
	}
	if err := readYAML(path, &doc); err != nil {
		if os.IsNotExist(err) {
			return nil, "", codedError("canonical_action_catalog_unavailable", "canonical action catalog %q is required", path)
		}
		return nil, "", err
	}
	actions := doc.Actions
	if len(actions) == 0 {
		actions = doc.Spec.Actions
	}
	if len(actions) == 0 {
		return nil, "", fmt.Errorf("%s: at least one canonical action is required", path)
	}
	seen := map[string]bool{}
	for i, action := range actions {
		action.ID = strings.TrimSpace(action.ID)
		action.Type = strings.TrimSpace(action.Type)
		if action.ID == "" {
			return nil, "", fmt.Errorf("%s: canonical action %d missing id", path, i)
		}
		if !strings.HasPrefix(action.ID, "kernloom_action.") {
			return nil, "", fmt.Errorf("%s: canonical action %q must use prefix %q", path, action.ID, "kernloom_action.")
		}
		if action.Type == "" {
			return nil, "", fmt.Errorf("%s: canonical action %q missing type", path, action.ID)
		}
		if seen[action.ID] {
			return nil, "", fmt.Errorf("%s: duplicate canonical action %q", path, action.ID)
		}
		seen[action.ID] = true
		actions[i] = action
	}
	return actions, fileSHA256(path), nil
}

func (s Store) validatePolicySources() error {
	for _, source := range s.PolicySources {
		if _, ok := s.repositoryByRef[source.RepoRef]; !ok {
			return codedError("policy_source_unavailable", "policy source %q references unknown repo_ref %q", source.ID, source.RepoRef)
		}
		switch source.Type {
		case "policy_repo":
			if len(source.PolicyPaths) == 0 {
				return codedError("policy_source_unavailable", "policy source %q has no policy_paths", source.ID)
			}
			policyPaths := map[string]bool{}
			for _, path := range source.PolicyPaths {
				policyPaths[cleanRel(path)] = true
			}
			for i, meaning := range source.PolicyMeanings {
				policyPath := cleanRel(meaning.PolicyPath)
				if policyPath == "" {
					return codedError("policy_source_unavailable", "policy source %q policy_meanings[%d] missing policy_path", source.ID, i)
				}
				if !policyPaths[policyPath] {
					return codedError("policy_source_unavailable", "policy source %q policy_meanings[%d] references policy_path %q outside policy_paths", source.ID, i, policyPath)
				}
				if len(meaning.CanonicalActions) == 0 && len(meaning.ActionTypes) == 0 {
					return codedError("policy_source_unavailable", "policy source %q policy_meanings[%d] requires canonical_actions or action_types", source.ID, i)
				}
			}
		case "config_repo":
		default:
			return codedError("policy_source_unavailable", "policy source %q has unsupported type %q", source.ID, source.Type)
		}
		if source.Visibility != "" && !containsString([]string{"restricted", "platform_team", "app_team", "public"}, source.Visibility) {
			return codedError("visibility_denied", "policy source %q has unsupported visibility %q", source.ID, source.Visibility)
		}
	}
	return nil
}

func loadTarget(path string) (TargetInventory, error) {
	var target TargetInventory
	if err := readYAML(path, &target); err != nil {
		return TargetInventory{}, err
	}
	target.Path = absPath(path)
	target.Digest = fileSHA256(path)
	if err := validateTarget(target); err != nil {
		return TargetInventory{}, err
	}
	return target, nil
}

func validateTarget(target TargetInventory) error {
	path := target.Path
	if target.Target.ID == "" {
		return fmt.Errorf("%s: target.id is required", path)
	}
	if target.Target.Tenant == "" || target.Target.Environment == "" {
		return fmt.Errorf("%s: target tenant and environment are required", path)
	}
	if target.Target.Adapter == "" {
		return fmt.Errorf("%s: target.adapter is required", path)
	}
	if target.Target.ValidationSource.RepoRef == "" {
		return fmt.Errorf("%s: target.validation_source.repo_ref is required", path)
	}
	if target.Target.ValidationSource.BasePath == "" {
		return fmt.Errorf("%s: target.validation_source.base_path is required", path)
	}
	return nil
}

func loadResource(path string) (ResourceFile, error) {
	var resource ResourceFile
	if err := readYAML(path, &resource); err != nil {
		return ResourceFile{}, err
	}
	resource.Path = absPath(path)
	resource.Digest = fileSHA256(path)
	if resource.Resource.ID == "" {
		return ResourceFile{}, fmt.Errorf("%s: resource.id is required", resource.Path)
	}
	return resource, nil
}

func loadProofRequirements(path string) (ProofRequirementFile, error) {
	var proofRequirements ProofRequirementFile
	if err := readYAML(path, &proofRequirements); err != nil {
		return ProofRequirementFile{}, err
	}
	proofRequirements.Path = absPath(path)
	proofRequirements.Digest = fileSHA256(path)
	if proofRequirements.ProofRequirements.Tenant == "" || proofRequirements.ProofRequirements.Environment == "" || proofRequirements.ProofRequirements.Resource == "" {
		return ProofRequirementFile{}, fmt.Errorf("%s: proof_requirements tenant, environment and resource are required", proofRequirements.Path)
	}
	return proofRequirements, nil
}

func loadActionBindings(path string) (ActionBindingFile, error) {
	var bindings ActionBindingFile
	if err := readYAML(path, &bindings); err != nil {
		return ActionBindingFile{}, err
	}
	bindings.Path = absPath(path)
	bindings.Digest = fileSHA256(path)
	if bindings.Application.ID == "" || bindings.Application.Tenant == "" || bindings.Application.Environment == "" {
		return ActionBindingFile{}, fmt.Errorf("%s: application id, tenant and environment are required", bindings.Path)
	}
	for i, action := range bindings.Actions {
		if action.ID == "" {
			return ActionBindingFile{}, fmt.Errorf("%s: action %d requires id", bindings.Path, i)
		}
		if isSensitive(action.Sensitivity) && len(action.Bindings) == 0 {
			return ActionBindingFile{}, codedError("missing_action_binding", "%s: sensitive action %q has no bindings", bindings.Path, action.ID)
		}
		for j, binding := range action.Bindings {
			if binding.ID == "" {
				return ActionBindingFile{}, fmt.Errorf("%s: action %q binding %d missing id", bindings.Path, action.ID, j)
			}
			if binding.TargetRef == "" {
				return ActionBindingFile{}, fmt.Errorf("%s: action %q binding %q missing target_ref", bindings.Path, action.ID, binding.ID)
			}
		}
	}
	return bindings, nil
}

func sourceMatchesScope(source PolicySource, target TargetInventory, resolvedBindings []ResolvedBinding) bool {
	if !scopeMatches(source.TenantScope, target.Target.Tenant) {
		return false
	}
	if !scopeMatches(source.EnvironmentScope, target.Target.Environment) {
		return false
	}
	if len(source.TargetScope) > 0 && !sliceScopeMatches(source.TargetScope, target.Target.ID) {
		return false
	}
	if len(source.ResourceScope) == 0 || sliceScopeMatches(source.ResourceScope, "*") {
		return true
	}
	for _, binding := range resolvedBindings {
		if sliceScopeMatches(source.ResourceScope, binding.File.Application.ID) {
			return true
		}
	}
	return false
}

func scopeMatches(scope, value string) bool {
	scope = strings.TrimSpace(scope)
	value = strings.TrimSpace(value)
	return scope == "*" || scope == value
}

func sliceScopeMatches(scopes []string, value string) bool {
	for _, scope := range scopes {
		if scopeMatches(scope, value) {
			return true
		}
	}
	return false
}

func visibilityAllowed(source PolicySource, requestRepo, sourceRepo RepositoryBinding) bool {
	switch strings.TrimSpace(source.Visibility) {
	case "", "restricted", "platform_team", "public":
		return true
	case "app_team":
		return source.RepoRef == requestRepo.ID || (sourceRepo.OwnerTeam != "" && sourceRepo.OwnerTeam == requestRepo.OwnerTeam)
	default:
		return false
	}
}

func selectorType(selector map[string]any) string {
	value, ok := selector["type"]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func tenantEnvID(tenant, environment, id string) string {
	return strings.TrimSpace(tenant) + "\x00" + strings.TrimSpace(environment) + "\x00" + strings.TrimSpace(id)
}

func URNForTarget(tenant, environment, targetID string) string {
	return "urn:kernloom:target:" + strings.TrimSpace(tenant) + ":" + strings.TrimSpace(environment) + ":" + strings.TrimSpace(targetID)
}

func URNForResource(tenant, environment, resourceID string) string {
	return "urn:kernloom:resource:" + strings.TrimSpace(tenant) + ":" + strings.TrimSpace(environment) + ":" + strings.TrimSpace(resourceID)
}

func URNForAction(tenant, environment, resourceID, actionID string) string {
	return "urn:kernloom:action:" + strings.TrimSpace(tenant) + ":" + strings.TrimSpace(environment) + ":" + strings.TrimSpace(resourceID) + ":" + strings.TrimSpace(actionID)
}

func isSensitive(sensitivity string) bool {
	switch strings.ToLower(strings.TrimSpace(sensitivity)) {
	case "medium", "high", "critical", "sensitive":
		return true
	default:
		return false
	}
}

func codedError(code, format string, args ...any) error {
	return Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

type Error struct {
	Code    string
	Message string
}

func (e Error) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

func readYAML(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func cleanRel(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(path))
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "sha256:unavailable"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func fileSHA256Strict(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

func containsString(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, value := range values {
		if strings.TrimSpace(value) == needle {
			return true
		}
	}
	return false
}
