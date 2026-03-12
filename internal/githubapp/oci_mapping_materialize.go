package githubapp

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func (service *Service) materializeRepositoryOCIMapping(repoPath, repoKey string) (string, error) {
	runtimeCfg := service.runtimeSnapshot()
	if runtimeCfg == nil {
		return "", nil
	}
	mapping, ok := runtimeCfg.RepositoryMapping(repoKey)
	if !ok || len(mapping.Images) == 0 {
		return "", nil
	}

	payload := struct {
		OCI struct {
			Mappings []AppOCIMappingSpec `yaml:"mappings"`
		} `yaml:"oci"`
	}{}
	payload.OCI.Mappings = []AppOCIMappingSpec{mapping}

	data, err := yaml.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal runtime OCI mapping: %w", err)
	}

	stateDir := filepath.Join(repoPath, ".patchpilot")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return "", fmt.Errorf("create runtime mapping dir: %w", err)
	}
	path := filepath.Join(stateDir, "runtime-oci-mapping.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write runtime OCI mapping: %w", err)
	}
	return path, nil
}
