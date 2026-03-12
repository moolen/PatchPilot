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
	if len(cfg.OCI.Mappings) != 0 {
		t.Fatalf("Mappings = %#v, want empty", cfg.OCI.Mappings)
	}
}

func TestLoadAppRuntimeConfigParsesMappingsAndPrompts(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "app-config.yaml")
	content := `oci:
  mappings:
    - repo: Acme/Demo
      images:
        - source: ghcr.io/example/demo
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
	entry, ok := cfg.RepositoryMapping("acme/demo")
	if !ok {
		t.Fatalf("expected normalized mapping entry")
	}
	if entry.Repo != "acme/demo" {
		t.Fatalf("Repo = %q", entry.Repo)
	}
	if len(entry.Images) != 1 || entry.Images[0].Source != "ghcr.io/example/demo" {
		t.Fatalf("Images = %#v", entry.Images)
	}
	if len(cfg.Remediation.Prompts.CIFailureAssessment) != 1 {
		t.Fatalf("CIFailureAssessment = %#v", cfg.Remediation.Prompts.CIFailureAssessment)
	}
}

func TestLoadAppRuntimeConfigRejectsWildcardRepo(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "app-config.yaml")
	content := `oci:
  mappings:
    - repo: acme/*
      images:
        - source: ghcr.io/example/demo
          dockerfiles: [Dockerfile]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write app config: %v", err)
	}
	if _, err := LoadAppRuntimeConfig(path); err == nil {
		t.Fatalf("expected wildcard repo validation error")
	}
}

func TestLoadAppRuntimeConfigRejectsInvalidPromptMode(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "app-config.yaml")
	content := `remediation:
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
