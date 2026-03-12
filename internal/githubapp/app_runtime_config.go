package githubapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moolen/patchpilot/internal/agent/prompts"
	"github.com/moolen/patchpilot/internal/policy"
	"gopkg.in/yaml.v3"
)

const defaultMaxCIAttempts = 3

type AppRuntimeConfig struct {
	OCI         AppRuntimeOCIConfig         `yaml:"oci"`
	Remediation AppRemediationRuntimeConfig `yaml:"remediation"`
	repoMapping map[string]AppOCIMappingSpec
}

type AppRuntimeOCIConfig struct {
	Mappings []AppOCIMappingSpec `yaml:"mappings"`
}

type AppOCIMappingSpec struct {
	Repo   string                        `yaml:"repo"`
	Images []policy.OCIExternalImageSpec `yaml:"images"`
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
		return defaultAppRuntimeConfig(), nil
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
	if cfg.OCI.Mappings == nil {
		cfg.OCI.Mappings = []AppOCIMappingSpec{}
	}
	if cfg.Remediation.MaxCIAttempts <= 0 {
		cfg.Remediation.MaxCIAttempts = defaultMaxCIAttempts
	}
	if err := validateAppRuntimeConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func defaultAppRuntimeConfig() *AppRuntimeConfig {
	return &AppRuntimeConfig{
		OCI: AppRuntimeOCIConfig{
			Mappings: []AppOCIMappingSpec{},
		},
		Remediation: AppRemediationRuntimeConfig{
			MaxCIAttempts: defaultMaxCIAttempts,
		},
		repoMapping: map[string]AppOCIMappingSpec{},
	}
}

func validateAppRuntimeConfig(cfg *AppRuntimeConfig) error {
	if cfg == nil {
		return fmt.Errorf("app runtime config is nil")
	}

	normalizedMappings := make([]AppOCIMappingSpec, 0, len(cfg.OCI.Mappings))
	repoMapping := make(map[string]AppOCIMappingSpec, len(cfg.OCI.Mappings))
	for index, mapping := range cfg.OCI.Mappings {
		repoKey := strings.TrimSpace(mapping.Repo)
		if containsRuntimeWildcard(repoKey) {
			return fmt.Errorf("oci.mappings[%d].repo must be an exact owner/repo match (wildcards are not allowed)", index)
		}
		normalizedRepo := normalizeRepoName(repoKey)
		if normalizedRepo == "" {
			return fmt.Errorf("oci.mappings[%d].repo must be a repository full name", index)
		}
		if _, exists := repoMapping[normalizedRepo]; exists {
			return fmt.Errorf("oci.mappings[%d].repo duplicates %q", index, normalizedRepo)
		}

		cleanImages := make([]policy.OCIExternalImageSpec, 0, len(mapping.Images))
		for imageIndex, image := range mapping.Images {
			image.Source = strings.TrimSpace(image.Source)
			if image.Source == "" {
				return fmt.Errorf("oci.mappings[%d].images[%d].source must not be empty", index, imageIndex)
			}
			dockerfiles := make([]string, 0, len(image.Dockerfiles))
			seenDockerfiles := map[string]struct{}{}
			for dockerfileIndex, dockerfile := range image.Dockerfiles {
				dockerfile = filepath.ToSlash(strings.TrimSpace(dockerfile))
				if dockerfile == "" {
					return fmt.Errorf("oci.mappings[%d].images[%d].dockerfiles[%d] must not be empty", index, imageIndex, dockerfileIndex)
				}
				if _, exists := seenDockerfiles[dockerfile]; exists {
					continue
				}
				seenDockerfiles[dockerfile] = struct{}{}
				dockerfiles = append(dockerfiles, dockerfile)
			}
			if len(dockerfiles) == 0 {
				return fmt.Errorf("oci.mappings[%d].images[%d].dockerfiles must not be empty", index, imageIndex)
			}
			image.Dockerfiles = dockerfiles
			image.Tag = strings.TrimSpace(image.Tag)
			if image.Tag == "" {
				image.Tag = policy.OCITagStrategyLatestSemver
			}
			cleanImages = append(cleanImages, image)
		}

		mapping.Repo = normalizedRepo
		mapping.Images = cleanImages
		normalizedMappings = append(normalizedMappings, mapping)
		repoMapping[normalizedRepo] = mapping
	}
	cfg.OCI.Mappings = normalizedMappings
	cfg.repoMapping = repoMapping

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

func (cfg *AppRuntimeConfig) RepositoryMapping(repoKey string) (AppOCIMappingSpec, bool) {
	if cfg == nil || cfg.repoMapping == nil {
		return AppOCIMappingSpec{}, false
	}
	entry, ok := cfg.repoMapping[normalizeRepoName(repoKey)]
	return entry, ok
}

func containsRuntimeWildcard(value string) bool {
	return strings.ContainsAny(value, "*?[]")
}
