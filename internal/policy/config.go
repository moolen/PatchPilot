package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cron "github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

const (
	FileName = ".patchpilot.yaml"

	VerificationModeAppend  = "append"
	VerificationModeReplace = "replace"

	HookWhenAlways  = "always"
	HookWhenSuccess = "success"
	HookWhenFailure = "failure"

	RegistryAuthAuto   = "auto"
	RegistryAuthNone   = "none"
	RegistryAuthBearer = "bearer"

	DockerPatchAuto     = "auto"
	DockerPatchDisabled = "disabled"

	GoRuntimePatchDisabled  = "disabled"
	GoRuntimePatchToolchain = "toolchain"
	GoRuntimePatchMinimum   = "minimum"

	ArtifactsTargetsCommandModeReplace = "replace"
	ArtifactsTargetsCommandModeAppend  = "append"
	DefaultArtifactsTargetsTimeout     = "2m"

	ScanCronDisabled    = "disabled"
	DefaultScanCron     = "0 0 * * *"
	DefaultScanTimezone = "UTC"

	LoadModeMerge    = "merge"
	LoadModeOverride = "override"

	DefaultAgentRemediationPromptsMaxBytes = 32 * 1024
)

type Config struct {
	Version       int                 `yaml:"version"`
	PreExecution  PreExecutionPolicy  `yaml:"pre_execution"`
	Verification  VerificationPolicy  `yaml:"verification"`
	PostExecution PostExecutionPolicy `yaml:"post_execution"`
	Exclude       ExcludePolicy       `yaml:"exclude"`
	Scan          ScanPolicy          `yaml:"scan"`
	Registry      RegistryPolicy      `yaml:"registry"`
	Docker        DockerPolicy        `yaml:"docker"`
	Go            GoPolicy            `yaml:"go"`
	Artifacts     ArtifactsPolicy     `yaml:"artifacts"`
	Agent         AgentPolicy         `yaml:"agent"`
}

type AgentPolicy struct {
	RemediationPrompts AgentRemediationPromptsPolicy `yaml:"remediation_prompts"`
}

type AgentRemediationPromptsPolicy struct {
	All                []string                             `yaml:"all"`
	BaselineScanRepair AgentBaselineScanRepairPromptsPolicy `yaml:"baseline_scan_repair"`
	FixVulnerabilities AgentFixVulnerabilitiesPromptsPolicy `yaml:"fix_vulnerabilities"`
}

type AgentBaselineScanRepairPromptsPolicy struct {
	All                  []string `yaml:"all"`
	GenerateBaselineSBOM []string `yaml:"generate_baseline_sbom"`
	ScanBaseline         []string `yaml:"scan_baseline"`
}

type AgentFixVulnerabilitiesPromptsPolicy struct {
	All                      []string `yaml:"all"`
	DeterministicFixFailed   []string `yaml:"deterministic_fix_failed"`
	ValidationFailed         []string `yaml:"validation_failed"`
	VulnerabilitiesRemaining []string `yaml:"vulnerabilities_remaining"`
	VerificationRegressed    []string `yaml:"verification_regressed"`
}

type GoPolicy struct {
	Patching GoPatchingPolicy `yaml:"patching"`
}

type GoPatchingPolicy struct {
	Runtime string `yaml:"runtime"`
}

type VerificationPolicy struct {
	Mode     string          `yaml:"mode"`
	Commands []CommandPolicy `yaml:"commands"`
}

type CommandPolicy struct {
	Name    string `yaml:"name"`
	Run     string `yaml:"run"`
	Timeout string `yaml:"timeout"`
}

type PostExecutionPolicy struct {
	Commands []HookPolicy `yaml:"commands"`
}

type PreExecutionPolicy struct {
	Commands []PreHookPolicy `yaml:"commands"`
}

type PreHookPolicy struct {
	Name        string `yaml:"name"`
	Run         string `yaml:"run"`
	Timeout     string `yaml:"timeout"`
	FailOnError bool   `yaml:"fail_on_error"`
}

type HookPolicy struct {
	Name        string `yaml:"name"`
	Run         string `yaml:"run"`
	When        string `yaml:"when"`
	FailOnError bool   `yaml:"fail_on_error"`
}

type ExcludePolicy struct {
	CVEs            []string                `yaml:"cves"`
	CVERules        []VulnerabilitySelector `yaml:"cve_rules"`
	Vulnerabilities []VulnerabilitySelector `yaml:"vulnerabilities"`
}

type VulnerabilitySelector struct {
	ID        string `yaml:"id"`
	Package   string `yaml:"package"`
	Ecosystem string `yaml:"ecosystem"`
	Path      string `yaml:"path"`
	Reason    string `yaml:"reason"`
	Owner     string `yaml:"owner"`
	ExpiresAt string `yaml:"expires_at"`
}

var policyNowFunc = time.Now

type ScanPolicy struct {
	SkipPaths []string `yaml:"skip_paths"`
	Cron      string   `yaml:"cron"`
	Timezone  string   `yaml:"timezone"`
}

type RegistryPolicy struct {
	Cache RegistryCachePolicy `yaml:"cache"`
	Auth  RegistryAuthPolicy  `yaml:"auth"`
}

type RegistryCachePolicy struct {
	Dir string `yaml:"dir"`
	TTL string `yaml:"ttl"`
}

type RegistryAuthPolicy struct {
	Mode     string `yaml:"mode"`
	TokenEnv string `yaml:"token_env"`
}

type DockerPolicy struct {
	AllowedBaseImages    []string             `yaml:"allowed_base_images"`
	DisallowedBaseImages []string             `yaml:"disallowed_base_images"`
	Patching             DockerPatchingPolicy `yaml:"patching"`
}

type DockerPatchingPolicy struct {
	BaseImages string `yaml:"base_images"`
	OSPackages string `yaml:"os_packages"`
}

type ArtifactsPolicy struct {
	Targets        []ArtifactTargetPolicy        `yaml:"targets"`
	TargetsCommand ArtifactsTargetsCommandPolicy `yaml:"targets_command"`
}

type ArtifactTargetPolicy struct {
	ID         string              `yaml:"id"`
	Dockerfile string              `yaml:"dockerfile"`
	Context    string              `yaml:"context"`
	Image      ArtifactImagePolicy `yaml:"image"`
	Build      ArtifactBuildPolicy `yaml:"build"`
	Scan       ArtifactScanPolicy  `yaml:"scan"`
}

type ArtifactImagePolicy struct {
	Tag string `yaml:"tag"`
}

type ArtifactBuildPolicy struct {
	Run     string `yaml:"run"`
	Timeout string `yaml:"timeout"`
}

type ArtifactScanPolicy struct {
	Enabled *bool `yaml:"enabled"`
}

func (policy ArtifactScanPolicy) EnabledOrDefault() bool {
	return policy.Enabled == nil || *policy.Enabled
}

type ArtifactsTargetsCommandPolicy struct {
	Run         string `yaml:"run"`
	Timeout     string `yaml:"timeout"`
	Mode        string `yaml:"mode"`
	FailOnError *bool  `yaml:"fail_on_error"`
}

func (policy ArtifactsTargetsCommandPolicy) FailOnErrorOrDefault() bool {
	return policy.FailOnError == nil || *policy.FailOnError
}

type LoadOptions struct {
	CentralPath   string
	Mode          string
	UntrustedRepo bool
}

type ParseOptions struct {
	UntrustedRepo bool
}

func Default() *Config {
	return &Config{
		Version: 1,
		Verification: VerificationPolicy{
			Mode: VerificationModeAppend,
		},
		Scan: ScanPolicy{
			Cron:     DefaultScanCron,
			Timezone: DefaultScanTimezone,
		},
		Registry: RegistryPolicy{
			Auth: RegistryAuthPolicy{
				Mode: RegistryAuthAuto,
			},
		},
		Docker: DockerPolicy{
			Patching: DockerPatchingPolicy{
				BaseImages: DockerPatchAuto,
				OSPackages: DockerPatchAuto,
			},
		},
		Go: GoPolicy{
			Patching: GoPatchingPolicy{
				Runtime: GoRuntimePatchMinimum,
			},
		},
	}
}

func Load(repo, overridePath string) (*Config, error) {
	return LoadWithOptions(repo, LoadOptions{
		CentralPath: overridePath,
		Mode:        LoadModeMerge,
	})
}

func ParseYAML(data []byte) (*Config, error) {
	return ParseYAMLWithOptions(data, ParseOptions{})
}

func ParseYAMLWithOptions(data []byte, options ParseOptions) (*Config, error) {
	if len(data) == 0 {
		return Default(), nil
	}
	if options.UntrustedRepo {
		sanitized, err := sanitizeUntrustedRepoPolicyBytes(FileName, data)
		if err != nil {
			return nil, err
		}
		data = sanitized
	}
	return decodePolicyBytes(FileName, data)
}

func LoadWithOptions(repo string, options LoadOptions) (*Config, error) {
	repoPath, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}
	repoPolicyPath := filepath.Join(repoPath, FileName)

	mode := normalizeLower(options.Mode)
	if mode == "" {
		mode = LoadModeMerge
	}
	if mode != LoadModeMerge && mode != LoadModeOverride {
		return nil, fmt.Errorf("invalid policy load mode %q (expected %q or %q)", mode, LoadModeMerge, LoadModeOverride)
	}

	centralPath := strings.TrimSpace(options.CentralPath)
	if centralPath == "" {
		return loadSingle(repoPolicyPath, false, options.UntrustedRepo)
	}
	centralPath, err = normalizePolicyPath(centralPath)
	if err != nil {
		return nil, err
	}

	// Avoid double-loading when the supplied central file points to the same in-repo policy path.
	if cleanComparablePath(centralPath) == cleanComparablePath(repoPolicyPath) {
		return loadSingle(repoPolicyPath, true, options.UntrustedRepo)
	}

	centralData, err := readPolicyBytes(centralPath, true)
	if err != nil {
		return nil, err
	}
	repoData, repoExists, err := readOptionalPolicyBytes(repoPolicyPath)
	if err != nil {
		return nil, err
	}

	if mode == LoadModeOverride {
		if repoExists {
			if options.UntrustedRepo {
				repoData, err = sanitizeUntrustedRepoPolicyBytes(repoPolicyPath, repoData)
				if err != nil {
					return nil, err
				}
			}
			return decodePolicyBytes(repoPolicyPath, repoData)
		}
		return decodePolicyBytes(centralPath, centralData)
	}
	if !repoExists {
		return decodePolicyBytes(centralPath, centralData)
	}

	mergedBytes, err := mergePolicyBytes(centralPath, centralData, repoPolicyPath, repoData, options.UntrustedRepo)
	if err != nil {
		return nil, err
	}
	return decodePolicyBytes(centralPath+" + "+repoPolicyPath, mergedBytes)
}

func loadSingle(path string, required bool, untrustedRepo bool) (*Config, error) {
	data, err := readPolicyBytes(path, required)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return Default(), nil
	}
	if untrustedRepo {
		data, err = sanitizeUntrustedRepoPolicyBytes(path, data)
		if err != nil {
			return nil, err
		}
	}
	return decodePolicyBytes(path, data)
}

func normalizePolicyPath(path string) (string, error) {
	path = filepath.Clean(path)
	if filepath.IsAbs(path) {
		return path, nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve policy path: %w", err)
	}
	return absPath, nil
}

func cleanComparablePath(path string) string {
	return filepath.Clean(path)
}

func readPolicyBytes(path string, required bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil, nil
		}
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}
	return data, nil
}

func readOptionalPolicyBytes(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read policy file %s: %w", path, err)
	}
	return data, true, nil
}

func decodePolicyBytes(path string, data []byte) (*Config, error) {
	cfg := Default()
	migrated, migrateErr := migrateLegacyPolicyYAML(data)
	if migrateErr != nil {
		return nil, fmt.Errorf("migrate policy file %s: %w", path, migrateErr)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(migrated))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode policy file %s: %w", path, err)
	}
	if err := normalizeAndValidate(cfg); err != nil {
		return nil, fmt.Errorf("validate policy file %s: %w", path, err)
	}
	return cfg, nil
}

func mergePolicyBytes(centralPath string, centralData []byte, repoPath string, repoData []byte, untrustedRepo bool) ([]byte, error) {
	centralMap, err := decodePolicyMap(centralPath, centralData)
	if err != nil {
		return nil, err
	}
	repoMap, err := decodePolicyMap(repoPath, repoData)
	if err != nil {
		return nil, err
	}
	if untrustedRepo {
		repoMap = sanitizeUntrustedRepoPolicyMap(repoMap)
	}
	merged := mergePolicyMap(centralMap, repoMap)
	data, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("merge policy files %s and %s: %w", centralPath, repoPath, err)
	}
	return data, nil
}

func decodePolicyMap(path string, data []byte) (map[string]any, error) {
	migrated, err := migrateLegacyPolicyYAML(data)
	if err != nil {
		return nil, fmt.Errorf("migrate policy file %s: %w", path, err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(migrated, &root); err != nil {
		return nil, fmt.Errorf("decode policy file %s: %w", path, err)
	}
	if root == nil {
		return map[string]any{}, nil
	}
	return root, nil
}

func mergePolicyMap(base, overlay map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	result := make(map[string]any, len(base))
	for key, value := range base {
		result[key] = clonePolicyValue(value)
	}
	for key, value := range overlay {
		existing, found := result[key]
		if !found {
			result[key] = clonePolicyValue(value)
			continue
		}
		result[key] = mergePolicyValue(existing, value)
	}
	return result
}

func mergePolicyValue(base, overlay any) any {
	baseMap, baseIsMap := base.(map[string]any)
	overlayMap, overlayIsMap := overlay.(map[string]any)
	if baseIsMap && overlayIsMap {
		return mergePolicyMap(baseMap, overlayMap)
	}
	baseList, baseIsList := base.([]any)
	overlayList, overlayIsList := overlay.([]any)
	if baseIsList && overlayIsList {
		merged := make([]any, 0, len(baseList))
		for _, item := range baseList {
			merged = append(merged, clonePolicyValue(item))
		}
		for _, item := range overlayList {
			merged = append(merged, clonePolicyValue(item))
		}
		return merged
	}
	return clonePolicyValue(overlay)
}

func clonePolicyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		copied := make(map[string]any, len(typed))
		for key, item := range typed {
			copied[key] = clonePolicyValue(item)
		}
		return copied
	case []any:
		copied := make([]any, 0, len(typed))
		for _, item := range typed {
			copied = append(copied, clonePolicyValue(item))
		}
		return copied
	default:
		return typed
	}
}

func sanitizeUntrustedRepoPolicyBytes(path string, data []byte) ([]byte, error) {
	root, err := decodePolicyMap(path, data)
	if err != nil {
		return nil, err
	}
	root = sanitizeUntrustedRepoPolicyMap(root)
	sanitized, err := yaml.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("sanitize policy file %s: %w", path, err)
	}
	return sanitized, nil
}

func sanitizeUntrustedRepoPolicyMap(root map[string]any) map[string]any {
	if root == nil {
		return map[string]any{}
	}
	sanitized, ok := clonePolicyValue(root).(map[string]any)
	if !ok {
		return map[string]any{}
	}

	// Repo-local policy is treated as untrusted in GitHub App mode. Keep only declarative
	// controls and strip any sections that can execute commands or read operator secrets.
	delete(sanitized, "pre_execution")
	delete(sanitized, "verification")
	delete(sanitized, "post_execution")
	delete(sanitized, "registry")
	delete(sanitized, "artifacts")
	delete(sanitized, "agent")

	return sanitized
}

func migrateLegacyPolicyYAML(data []byte) ([]byte, error) {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if root == nil {
		return data, nil
	}

	changed := false

	if _, ok := root["postExecution"]; ok {
		if _, exists := root["post_execution"]; !exists {
			root["post_execution"] = root["postExecution"]
		}
		delete(root, "postExecution")
		changed = true
	}

	if verificationMode, ok := root["verificationMode"]; ok {
		verification, _ := mapValue(root["verification"])
		if verification == nil {
			verification = map[string]any{}
		}
		if _, exists := verification["mode"]; !exists {
			verification["mode"] = verificationMode
		}
		root["verification"] = verification
		delete(root, "verificationMode")
		changed = true
	}

	if topLevelSkip, ok := root["skip_paths"]; ok {
		scan, _ := mapValue(root["scan"])
		if scan == nil {
			scan = map[string]any{}
		}
		if _, exists := scan["skip_paths"]; !exists {
			scan["skip_paths"] = topLevelSkip
		}
		root["scan"] = scan
		delete(root, "skip_paths")
		changed = true
	}

	if excludes, ok := root["excludes"]; ok {
		if _, exists := root["exclude"]; !exists {
			root["exclude"] = excludes
		}
		delete(root, "excludes")
		changed = true
	}

	if rawVerification, ok := root["verification"]; ok {
		verification, _ := mapValue(rawVerification)
		if verification != nil {
			if rawCommands, ok := verification["commands"]; ok {
				commands, ok := rawCommands.([]any)
				if ok {
					for _, item := range commands {
						commandMap, ok := item.(map[string]any)
						if !ok {
							continue
						}
						if run, exists := commandMap["command"]; exists {
							if _, hasRun := commandMap["run"]; !hasRun {
								commandMap["run"] = run
							}
							delete(commandMap, "command")
							changed = true
						}
					}
				}
			}
		}
	}

	if version, ok := root["version"]; ok {
		switch typed := version.(type) {
		case int:
			if typed == 0 {
				root["version"] = 1
				changed = true
			}
		case int64:
			if typed == 0 {
				root["version"] = 1
				changed = true
			}
		case float64:
			if typed == 0 {
				root["version"] = 1
				changed = true
			}
		}
	}

	if !changed {
		return data, nil
	}
	return yaml.Marshal(root)
}

func mapValue(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func normalizeAndValidate(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported version %d (expected 1)", cfg.Version)
	}

	for index := range cfg.PreExecution.Commands {
		hook := &cfg.PreExecution.Commands[index]
		hook.Name = strings.TrimSpace(hook.Name)
		hook.Run = strings.TrimSpace(hook.Run)
		hook.Timeout = strings.TrimSpace(hook.Timeout)
		if hook.Run == "" {
			return fmt.Errorf("pre_execution.commands[%d].run must not be empty", index)
		}
		if hook.Name == "" {
			hook.Name = fmt.Sprintf("pre-hook-%d", index+1)
		}
		if hook.Timeout != "" {
			parsed, err := time.ParseDuration(hook.Timeout)
			if err != nil {
				return fmt.Errorf("pre_execution.commands[%d].timeout is invalid: %w", index, err)
			}
			if parsed <= 0 {
				return fmt.Errorf("pre_execution.commands[%d].timeout must be > 0", index)
			}
		}
	}

	cfg.Verification.Mode = normalizeLower(cfg.Verification.Mode)
	if cfg.Verification.Mode == "" {
		cfg.Verification.Mode = VerificationModeAppend
	}
	if cfg.Verification.Mode != VerificationModeAppend && cfg.Verification.Mode != VerificationModeReplace {
		return fmt.Errorf("verification.mode must be %q or %q", VerificationModeAppend, VerificationModeReplace)
	}
	for index := range cfg.Verification.Commands {
		cmd := &cfg.Verification.Commands[index]
		cmd.Run = strings.TrimSpace(cmd.Run)
		cmd.Name = strings.TrimSpace(cmd.Name)
		if cmd.Run == "" {
			return fmt.Errorf("verification.commands[%d].run must not be empty", index)
		}
		if cmd.Name == "" {
			cmd.Name = fmt.Sprintf("custom-%d", index+1)
		}
		cmd.Timeout = strings.TrimSpace(cmd.Timeout)
		if cmd.Timeout != "" {
			parsed, err := time.ParseDuration(cmd.Timeout)
			if err != nil {
				return fmt.Errorf("verification.commands[%d].timeout is invalid: %w", index, err)
			}
			if parsed <= 0 {
				return fmt.Errorf("verification.commands[%d].timeout must be > 0", index)
			}
		}
	}

	for index := range cfg.PostExecution.Commands {
		hook := &cfg.PostExecution.Commands[index]
		hook.Name = strings.TrimSpace(hook.Name)
		hook.Run = strings.TrimSpace(hook.Run)
		hook.When = normalizeLower(hook.When)
		if hook.Run == "" {
			return fmt.Errorf("post_execution.commands[%d].run must not be empty", index)
		}
		if hook.Name == "" {
			hook.Name = fmt.Sprintf("hook-%d", index+1)
		}
		if hook.When == "" {
			hook.When = HookWhenAlways
		}
		if hook.When != HookWhenAlways && hook.When != HookWhenSuccess && hook.When != HookWhenFailure {
			return fmt.Errorf("post_execution.commands[%d].when must be %q, %q, or %q", index, HookWhenAlways, HookWhenSuccess, HookWhenFailure)
		}
	}

	cfg.Exclude.CVEs = dedupeNonEmpty(cfg.Exclude.CVEs)
	if err := normalizeSelectors(cfg.Exclude.CVERules, "exclude.cve_rules"); err != nil {
		return err
	}
	cfg.Exclude.CVERules = dedupeSelectors(cfg.Exclude.CVERules)
	if err := normalizeSelectors(cfg.Exclude.Vulnerabilities, "exclude.vulnerabilities"); err != nil {
		return err
	}
	cfg.Exclude.Vulnerabilities = dedupeSelectors(cfg.Exclude.Vulnerabilities)

	cfg.Scan.SkipPaths = dedupeNonEmptyPaths(cfg.Scan.SkipPaths)
	cfg.Scan.Cron = strings.TrimSpace(cfg.Scan.Cron)
	if cfg.Scan.Cron == "" {
		cfg.Scan.Cron = DefaultScanCron
	}
	cfg.Scan.Timezone = strings.TrimSpace(cfg.Scan.Timezone)
	if cfg.Scan.Timezone == "" {
		cfg.Scan.Timezone = DefaultScanTimezone
	}
	if !strings.EqualFold(cfg.Scan.Cron, ScanCronDisabled) {
		if _, err := cron.ParseStandard(cfg.Scan.Cron); err != nil {
			return fmt.Errorf("scan.cron is invalid: %w", err)
		}
		if _, err := time.LoadLocation(cfg.Scan.Timezone); err != nil {
			return fmt.Errorf("scan.timezone is invalid: %w", err)
		}
	} else {
		cfg.Scan.Cron = ScanCronDisabled
	}

	cfg.Registry.Auth.Mode = normalizeLower(cfg.Registry.Auth.Mode)
	if cfg.Registry.Auth.Mode == "" {
		cfg.Registry.Auth.Mode = RegistryAuthAuto
	}
	if cfg.Registry.Auth.Mode != RegistryAuthAuto && cfg.Registry.Auth.Mode != RegistryAuthNone && cfg.Registry.Auth.Mode != RegistryAuthBearer {
		return fmt.Errorf("registry.auth.mode must be %q, %q, or %q", RegistryAuthAuto, RegistryAuthNone, RegistryAuthBearer)
	}
	cfg.Registry.Auth.TokenEnv = strings.TrimSpace(cfg.Registry.Auth.TokenEnv)
	if cfg.Registry.Auth.Mode == RegistryAuthBearer && cfg.Registry.Auth.TokenEnv == "" {
		return errors.New("registry.auth.token_env must be set when registry.auth.mode is bearer")
	}
	cfg.Registry.Cache.Dir = strings.TrimSpace(cfg.Registry.Cache.Dir)
	cfg.Registry.Cache.TTL = strings.TrimSpace(cfg.Registry.Cache.TTL)
	if cfg.Registry.Cache.TTL != "" {
		ttl, err := time.ParseDuration(cfg.Registry.Cache.TTL)
		if err != nil {
			return fmt.Errorf("registry.cache.ttl is invalid: %w", err)
		}
		if ttl <= 0 {
			return errors.New("registry.cache.ttl must be > 0")
		}
	}

	cfg.Docker.AllowedBaseImages = dedupeNonEmpty(cfg.Docker.AllowedBaseImages)
	cfg.Docker.DisallowedBaseImages = dedupeNonEmpty(cfg.Docker.DisallowedBaseImages)
	cfg.Docker.Patching.BaseImages = normalizeLower(cfg.Docker.Patching.BaseImages)
	if cfg.Docker.Patching.BaseImages == "" {
		cfg.Docker.Patching.BaseImages = DockerPatchAuto
	}
	if cfg.Docker.Patching.BaseImages != DockerPatchAuto && cfg.Docker.Patching.BaseImages != DockerPatchDisabled {
		return fmt.Errorf("docker.patching.base_images must be %q or %q", DockerPatchAuto, DockerPatchDisabled)
	}
	cfg.Docker.Patching.OSPackages = normalizeLower(cfg.Docker.Patching.OSPackages)
	if cfg.Docker.Patching.OSPackages == "" {
		cfg.Docker.Patching.OSPackages = DockerPatchAuto
	}
	if cfg.Docker.Patching.OSPackages != DockerPatchAuto && cfg.Docker.Patching.OSPackages != DockerPatchDisabled {
		return fmt.Errorf("docker.patching.os_packages must be %q or %q", DockerPatchAuto, DockerPatchDisabled)
	}

	cfg.Go.Patching.Runtime = normalizeLower(cfg.Go.Patching.Runtime)
	if cfg.Go.Patching.Runtime == "" {
		cfg.Go.Patching.Runtime = GoRuntimePatchMinimum
	}
	if cfg.Go.Patching.Runtime != GoRuntimePatchDisabled && cfg.Go.Patching.Runtime != GoRuntimePatchToolchain && cfg.Go.Patching.Runtime != GoRuntimePatchMinimum {
		return fmt.Errorf("go.patching.runtime must be %q, %q, or %q", GoRuntimePatchDisabled, GoRuntimePatchToolchain, GoRuntimePatchMinimum)
	}

	if err := normalizeArtifactTargets(cfg.Artifacts.Targets, "artifacts.targets"); err != nil {
		return err
	}

	cfg.Artifacts.TargetsCommand.Run = strings.TrimSpace(cfg.Artifacts.TargetsCommand.Run)
	cfg.Artifacts.TargetsCommand.Mode = normalizeLower(cfg.Artifacts.TargetsCommand.Mode)
	if cfg.Artifacts.TargetsCommand.Mode == "" {
		cfg.Artifacts.TargetsCommand.Mode = ArtifactsTargetsCommandModeReplace
	}
	if cfg.Artifacts.TargetsCommand.Mode != ArtifactsTargetsCommandModeReplace && cfg.Artifacts.TargetsCommand.Mode != ArtifactsTargetsCommandModeAppend {
		return fmt.Errorf(
			"artifacts.targets_command.mode must be %q or %q",
			ArtifactsTargetsCommandModeReplace,
			ArtifactsTargetsCommandModeAppend,
		)
	}

	cfg.Artifacts.TargetsCommand.Timeout = strings.TrimSpace(cfg.Artifacts.TargetsCommand.Timeout)
	if cfg.Artifacts.TargetsCommand.Timeout == "" {
		cfg.Artifacts.TargetsCommand.Timeout = DefaultArtifactsTargetsTimeout
	}
	timeout, err := time.ParseDuration(cfg.Artifacts.TargetsCommand.Timeout)
	if err != nil {
		return fmt.Errorf("artifacts.targets_command.timeout is invalid: %w", err)
	}
	if timeout <= 0 {
		return fmt.Errorf("artifacts.targets_command.timeout must be > 0")
	}

	var promptBytes int
	var errPrompt error
	cfg.Agent.RemediationPrompts.All, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.All,
		"agent.remediation_prompts.all",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.BaselineScanRepair.All, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.BaselineScanRepair.All,
		"agent.remediation_prompts.baseline_scan_repair.all",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.BaselineScanRepair.GenerateBaselineSBOM, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.BaselineScanRepair.GenerateBaselineSBOM,
		"agent.remediation_prompts.baseline_scan_repair.generate_baseline_sbom",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.BaselineScanRepair.ScanBaseline, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.BaselineScanRepair.ScanBaseline,
		"agent.remediation_prompts.baseline_scan_repair.scan_baseline",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.FixVulnerabilities.All, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.FixVulnerabilities.All,
		"agent.remediation_prompts.fix_vulnerabilities.all",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.FixVulnerabilities.DeterministicFixFailed, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.FixVulnerabilities.DeterministicFixFailed,
		"agent.remediation_prompts.fix_vulnerabilities.deterministic_fix_failed",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.FixVulnerabilities.ValidationFailed, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.FixVulnerabilities.ValidationFailed,
		"agent.remediation_prompts.fix_vulnerabilities.validation_failed",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.FixVulnerabilities.VulnerabilitiesRemaining, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.FixVulnerabilities.VulnerabilitiesRemaining,
		"agent.remediation_prompts.fix_vulnerabilities.vulnerabilities_remaining",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}
	cfg.Agent.RemediationPrompts.FixVulnerabilities.VerificationRegressed, promptBytes, errPrompt = normalizePromptList(
		cfg.Agent.RemediationPrompts.FixVulnerabilities.VerificationRegressed,
		"agent.remediation_prompts.fix_vulnerabilities.verification_regressed",
		promptBytes,
	)
	if errPrompt != nil {
		return errPrompt
	}

	return nil
}

func NormalizeArtifactTargets(targets []ArtifactTargetPolicy) ([]ArtifactTargetPolicy, error) {
	normalized := append([]ArtifactTargetPolicy(nil), targets...)
	if err := normalizeArtifactTargets(normalized, "artifacts.targets"); err != nil {
		return nil, err
	}
	return normalized, nil
}

func normalizeArtifactTargets(targets []ArtifactTargetPolicy, field string) error {
	for index := range targets {
		target := &targets[index]
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			target.ID = fmt.Sprintf("target-%d", index+1)
		}

		target.Dockerfile = cleanRelativePath(target.Dockerfile)
		if target.Dockerfile == "" {
			return fmt.Errorf("%s[%d].dockerfile must not be empty", field, index)
		}

		explicitRepoRootContext := isExplicitRepoRootArtifactContext(target.Context)
		target.Context = cleanRelativePath(target.Context)
		if target.Context == "" {
			if explicitRepoRootContext {
				target.Context = "."
			} else {
				target.Context = cleanRelativePath(filepath.Dir(target.Dockerfile))
			}
		}

		target.Image.Tag = strings.TrimSpace(target.Image.Tag)
		if target.Image.Tag == "" {
			return fmt.Errorf("%s[%d].image.tag must not be empty", field, index)
		}

		target.Build.Run = strings.TrimSpace(target.Build.Run)
		if target.Build.Run == "" {
			return fmt.Errorf("%s[%d].build.run must not be empty", field, index)
		}
		target.Build.Timeout = strings.TrimSpace(target.Build.Timeout)
		if target.Build.Timeout == "" {
			target.Build.Timeout = "30m"
		}
		timeout, err := time.ParseDuration(target.Build.Timeout)
		if err != nil {
			return fmt.Errorf("%s[%d].build.timeout is invalid: %w", field, index, err)
		}
		if timeout <= 0 {
			return fmt.Errorf("%s[%d].build.timeout must be > 0", field, index)
		}
	}
	return nil
}

func isExplicitRepoRootArtifactContext(value string) bool {
	trimmed := filepath.ToSlash(strings.TrimSpace(value))
	if trimmed == "" {
		return false
	}
	return strings.TrimRight(trimmed, "/") == "."
}

func (cfg *Config) ResolveScanSchedule() (cron.Schedule, *time.Location, bool, error) {
	if cfg == nil {
		return nil, nil, false, errors.New("config is nil")
	}
	spec := strings.TrimSpace(cfg.Scan.Cron)
	if spec == "" {
		spec = DefaultScanCron
	}
	if strings.EqualFold(spec, ScanCronDisabled) {
		return nil, nil, false, nil
	}
	locationName := strings.TrimSpace(cfg.Scan.Timezone)
	if locationName == "" {
		locationName = DefaultScanTimezone
	}
	location, err := time.LoadLocation(locationName)
	if err != nil {
		return nil, nil, false, fmt.Errorf("load scan timezone: %w", err)
	}
	schedule, err := cron.ParseStandard(spec)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse scan cron: %w", err)
	}
	return schedule, location, true, nil
}

func normalizeSelectors(selectors []VulnerabilitySelector, field string) error {
	now := policyNowFunc().UTC()
	for index := range selectors {
		selector := &selectors[index]
		selector.ID = strings.TrimSpace(selector.ID)
		selector.Package = strings.TrimSpace(selector.Package)
		selector.Ecosystem = strings.TrimSpace(selector.Ecosystem)
		selector.Path = cleanRelativePath(selector.Path)
		selector.Reason = strings.TrimSpace(selector.Reason)
		selector.Owner = strings.TrimSpace(selector.Owner)
		selector.ExpiresAt = strings.TrimSpace(selector.ExpiresAt)
		if selector.ID == "" {
			return fmt.Errorf("%s[%d].id must not be empty", field, index)
		}
		if selector.ExpiresAt == "" {
			continue
		}
		expiry, err := parseSelectorExpiry(selector.ExpiresAt)
		if err != nil {
			return fmt.Errorf("%s[%d].expires_at is invalid: %w", field, index, err)
		}
		if now.After(expiry) {
			return fmt.Errorf("%s[%d] is expired (expires_at=%s)", field, index, selector.ExpiresAt)
		}
	}
	return nil
}

func parseSelectorExpiry(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("empty")
	}
	dateOnly, dateErr := time.Parse("2006-01-02", value)
	if dateErr == nil {
		return time.Date(dateOnly.Year(), dateOnly.Month(), dateOnly.Day(), 23, 59, 59, 0, time.UTC), nil
	}
	timestamp, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return timestamp.UTC(), nil
}

func dedupeSelectors(values []VulnerabilitySelector) []VulnerabilitySelector {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]VulnerabilitySelector{}
	for _, selector := range values {
		key := strings.Join([]string{
			selector.ID,
			selector.Package,
			selector.Ecosystem,
			selector.Path,
			selector.Reason,
			selector.Owner,
			selector.ExpiresAt,
		}, "|")
		seen[key] = selector
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]VulnerabilitySelector, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func normalizeLower(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func dedupeNonEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizePromptList(values []string, field string, totalBytes int) ([]string, int, error) {
	if len(values) == 0 {
		return nil, totalBytes, nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		totalBytes += len(value)
		if totalBytes > DefaultAgentRemediationPromptsMaxBytes {
			return nil, totalBytes, fmt.Errorf(
				"agent.remediation_prompts payload exceeds %d bytes after normalization (failed at %s)",
				DefaultAgentRemediationPromptsMaxBytes,
				field,
			)
		}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, totalBytes, nil
	}
	return result, totalBytes, nil
}

func cleanRelativePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = filepath.ToSlash(path)
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSpace(path)
	if path == "." {
		return ""
	}
	return path
}

func dedupeNonEmptyPaths(paths []string) []string {
	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		path = cleanRelativePath(path)
		if path == "" {
			continue
		}
		cleaned = append(cleaned, path)
	}
	return dedupeNonEmpty(cleaned)
}
