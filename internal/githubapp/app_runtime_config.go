package githubapp

import (
	"fmt"
	"os"
	"strings"

	"github.com/moolen/patchpilot/internal/agent/prompts"
	"github.com/moolen/patchpilot/internal/policy"
	"gopkg.in/yaml.v3"
)

const defaultMaxCIAttempts = 3

type AppRuntimeConfig struct {
	Repositories map[string]AppRepositoryRuntimeConfig `yaml:"repositories"`
	Remediation  AppRemediationRuntimeConfig           `yaml:"remediation"`
}

type AppRepositoryRuntimeConfig struct {
	ImageRepository string   `yaml:"image_repository"`
	Dockerfiles     []string `yaml:"dockerfiles"`
}

type AppRemediationRuntimeConfig struct {
	MaxCIAttempts int                     `yaml:"max_ci_attempts"`
	Prompts       AppRemediationPromptSet `yaml:"prompts"`
}

type AppRemediationPromptSet struct {
	ContainerOSPatching []policy.AgentRemediationPromptPolicy `yaml:"container_os_patching"`
	CIFailureAssessment []policy.AgentRemediationPromptPolicy `yaml:"ci_failure_assessment"`
	CIFailureRepair     []policy.AgentRemediationPromptPolicy `yaml:"ci_failure_repair"`
}

func LoadAppRuntimeConfig(path string) (*AppRuntimeConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &AppRuntimeConfig{
			Repositories: map[string]AppRepositoryRuntimeConfig{},
			Remediation: AppRemediationRuntimeConfig{
				MaxCIAttempts: defaultMaxCIAttempts,
			},
		}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read app runtime config: %w", err)
	}

	var cfg AppRuntimeConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode app runtime config: %w", err)
	}
	if cfg.Repositories == nil {
		cfg.Repositories = map[string]AppRepositoryRuntimeConfig{}
	}
	if cfg.Remediation.MaxCIAttempts <= 0 {
		cfg.Remediation.MaxCIAttempts = defaultMaxCIAttempts
	}
	if err := validateAppRuntimeConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateAppRuntimeConfig(cfg *AppRuntimeConfig) error {
	if cfg == nil {
		return fmt.Errorf("app runtime config is nil")
	}
	for repoKey, entry := range cfg.Repositories {
		normalized := normalizeRepoName(repoKey)
		if normalized == "" {
			return fmt.Errorf("repositories.%q must be a repository full name", repoKey)
		}
		entry.ImageRepository = strings.TrimSpace(entry.ImageRepository)
		if entry.ImageRepository == "" {
			return fmt.Errorf("repositories.%q.image_repository must not be empty", repoKey)
		}
		cleanDockerfiles := make([]string, 0, len(entry.Dockerfiles))
		for _, dockerfile := range entry.Dockerfiles {
			dockerfile = strings.TrimSpace(dockerfile)
			if dockerfile == "" {
				continue
			}
			cleanDockerfiles = append(cleanDockerfiles, dockerfile)
		}
		entry.Dockerfiles = cleanDockerfiles
		if normalized != repoKey {
			delete(cfg.Repositories, repoKey)
		}
		cfg.Repositories[normalized] = entry
	}
	for _, promptList := range [][]policy.AgentRemediationPromptPolicy{
		cfg.Remediation.Prompts.ContainerOSPatching,
		cfg.Remediation.Prompts.CIFailureAssessment,
		cfg.Remediation.Prompts.CIFailureRepair,
	} {
		for _, prompt := range promptList {
			mode := strings.TrimSpace(prompt.Mode)
			switch mode {
			case policy.PromptModeExtend, policy.PromptModeReplace:
			default:
				return fmt.Errorf("invalid remediation prompt mode %q", mode)
			}
			if err := prompts.ValidateRemediationTemplate(strings.TrimSpace(prompt.Template)); err != nil {
				return fmt.Errorf("invalid remediation prompt template: %w", err)
			}
		}
	}
	return nil
}

func (cfg *AppRuntimeConfig) RepositoryConfig(repoKey string) (AppRepositoryRuntimeConfig, bool) {
	if cfg == nil {
		return AppRepositoryRuntimeConfig{}, false
	}
	entry, ok := cfg.Repositories[normalizeRepoName(repoKey)]
	return entry, ok
}
