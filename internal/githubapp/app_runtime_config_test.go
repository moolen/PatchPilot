package githubapp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppRuntimeConfigDefaultsWithoutFile(t *testing.T) {
	cfg, err := LoadAppRuntimeConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Remediation.MaxCIAttempts != defaultMaxCIAttempts {
		t.Fatalf("MaxCIAttempts = %d, want %d", cfg.Remediation.MaxCIAttempts, defaultMaxCIAttempts)
	}
	if len(cfg.Repositories) != 0 {
		t.Fatalf("Repositories = %#v, want empty", cfg.Repositories)
	}
}

func TestLoadAppRuntimeConfigParsesRepositoriesAndPrompts(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "app-config.yaml")
	content := `repositories:
  Acme/Demo:
    image_repository: ghcr.io/example/demo
    dockerfiles:
      - Dockerfile
remediation:
  max_ci_attempts: 5
  prompts:
    ci_failure_assessment:
      - mode: extend
        template: |
          Return JSON only.
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write app config: %v", err)
	}
	cfg, err := LoadAppRuntimeConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Remediation.MaxCIAttempts != 5 {
		t.Fatalf("MaxCIAttempts = %d, want 5", cfg.Remediation.MaxCIAttempts)
	}
	entry, ok := cfg.RepositoryConfig("acme/demo")
	if !ok {
		t.Fatalf("expected normalized repository entry")
	}
	if entry.ImageRepository != "ghcr.io/example/demo" {
		t.Fatalf("ImageRepository = %q", entry.ImageRepository)
	}
	if len(cfg.Remediation.Prompts.CIFailureAssessment) != 1 {
		t.Fatalf("CIFailureAssessment = %#v", cfg.Remediation.Prompts.CIFailureAssessment)
	}
}

func TestLoadAppRuntimeConfigRejectsInvalidPromptMode(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "app-config.yaml")
	content := `repositories:
  acme/demo:
    image_repository: ghcr.io/example/demo
remediation:
  prompts:
    ci_failure_assessment:
      - mode: invalid
        template: |
          Return JSON only.
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write app config: %v", err)
	}
	if _, err := LoadAppRuntimeConfig(path); err == nil {
		t.Fatalf("expected invalid prompt mode error")
	}
}
