package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingPolicyReturnsDefaults(t *testing.T) {
	repo := t.TempDir()
	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("expected version 1, got %d", cfg.Version)
	}
	if cfg.Verification.Mode != VerificationModeAppend {
		t.Fatalf("expected verification append mode, got %q", cfg.Verification.Mode)
	}
	if cfg.Registry.Auth.Mode != RegistryAuthAuto {
		t.Fatalf("expected registry auth auto mode, got %q", cfg.Registry.Auth.Mode)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	if err := os.WriteFile(path, []byte("version: 1\nunknown: value\n"), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadNormalizesAndValidatesConfig(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
verification:
  mode: REPLACE
  commands:
    - run: "make verify"
      timeout: 2m
post_execution:
  commands:
    - run: "echo done"
exclude:
  cves: ["CVE-1", "CVE-1", ""]
  vulnerabilities:
    - id: GHSA-1
      package: openssl
      ecosystem: deb
      path: ./images/Dockerfile
scan:
  skip_paths: ["vendor", "./vendor", "  "]
registry:
  cache:
    ttl: 30m
  auth:
    mode: bearer
    token_env: REGISTRY_TOKEN
docker:
  patching:
    base_images: disabled
    os_packages: auto
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Verification.Mode != VerificationModeReplace {
		t.Fatalf("expected replace mode, got %q", cfg.Verification.Mode)
	}
	if len(cfg.Verification.Commands) != 1 || cfg.Verification.Commands[0].Name == "" {
		t.Fatalf("expected command default name, got %#v", cfg.Verification.Commands)
	}
	if len(cfg.PostExecution.Commands) != 1 || cfg.PostExecution.Commands[0].When != HookWhenAlways {
		t.Fatalf("expected post command defaults, got %#v", cfg.PostExecution.Commands)
	}
	if len(cfg.Exclude.CVEs) != 1 || cfg.Exclude.CVEs[0] != "CVE-1" {
		t.Fatalf("unexpected cve excludes: %#v", cfg.Exclude.CVEs)
	}
	if len(cfg.Scan.SkipPaths) != 1 || cfg.Scan.SkipPaths[0] != "vendor" {
		t.Fatalf("unexpected skip paths: %#v", cfg.Scan.SkipPaths)
	}
	if cfg.Docker.Patching.BaseImages != DockerPatchDisabled {
		t.Fatalf("unexpected docker base patch mode: %q", cfg.Docker.Patching.BaseImages)
	}
}

func TestLoadRejectsBearerWithoutTokenEnv(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
registry:
  auth:
    mode: bearer
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "token_env") {
		t.Fatalf("unexpected error: %v", err)
	}
}
