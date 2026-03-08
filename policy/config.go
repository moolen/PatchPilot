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
)

type Config struct {
	Version       int                 `yaml:"version"`
	Verification  VerificationPolicy  `yaml:"verification"`
	PostExecution PostExecutionPolicy `yaml:"post_execution"`
	Exclude       ExcludePolicy       `yaml:"exclude"`
	Scan          ScanPolicy          `yaml:"scan"`
	Registry      RegistryPolicy      `yaml:"registry"`
	Docker        DockerPolicy        `yaml:"docker"`
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

type HookPolicy struct {
	Name        string `yaml:"name"`
	Run         string `yaml:"run"`
	When        string `yaml:"when"`
	FailOnError bool   `yaml:"fail_on_error"`
}

type ExcludePolicy struct {
	CVEs            []string                `yaml:"cves"`
	Vulnerabilities []VulnerabilitySelector `yaml:"vulnerabilities"`
}

type VulnerabilitySelector struct {
	ID        string `yaml:"id"`
	Package   string `yaml:"package"`
	Ecosystem string `yaml:"ecosystem"`
	Path      string `yaml:"path"`
}

type ScanPolicy struct {
	SkipPaths []string `yaml:"skip_paths"`
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

func Default() *Config {
	return &Config{
		Version: 1,
		Verification: VerificationPolicy{
			Mode: VerificationModeAppend,
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
	}
}

func Load(repo, overridePath string) (*Config, error) {
	cfg := Default()
	path := strings.TrimSpace(overridePath)
	required := path != ""
	if path == "" {
		path = filepath.Join(repo, FileName)
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve policy path: %w", err)
		}
		path = absPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return cfg, nil
		}
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}

	migrated, migrateErr := migrateLegacyPolicyYAML(data)
	if migrateErr != nil {
		return nil, fmt.Errorf("migrate policy file %s: %w", path, migrateErr)
	}
	data = migrated

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode policy file %s: %w", path, err)
	}
	if err := normalizeAndValidate(cfg); err != nil {
		return nil, fmt.Errorf("validate policy file %s: %w", path, err)
	}
	return cfg, nil
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
	for index := range cfg.Exclude.Vulnerabilities {
		selector := &cfg.Exclude.Vulnerabilities[index]
		selector.ID = strings.TrimSpace(selector.ID)
		selector.Package = strings.TrimSpace(selector.Package)
		selector.Ecosystem = strings.TrimSpace(selector.Ecosystem)
		selector.Path = cleanRelativePath(selector.Path)
		if selector.ID == "" {
			return fmt.Errorf("exclude.vulnerabilities[%d].id must not be empty", index)
		}
	}

	cfg.Scan.SkipPaths = dedupeNonEmptyPaths(cfg.Scan.SkipPaths)

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

	return nil
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
