package policy

import (
	"fmt"
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
	if cfg.Registry.Auth.Mode != RegistryAuthAuto {
		t.Fatalf("expected registry auth auto mode, got %q", cfg.Registry.Auth.Mode)
	}
	if cfg.Go.Patching.Runtime != GoRuntimePatchMinimum {
		t.Fatalf("expected go runtime patch mode %q, got %q", GoRuntimePatchMinimum, cfg.Go.Patching.Runtime)
	}
	if cfg.Scan.Cron != DefaultScanCron {
		t.Fatalf("expected default scan cron %q, got %q", DefaultScanCron, cfg.Scan.Cron)
	}
	if cfg.Scan.Timezone != DefaultScanTimezone {
		t.Fatalf("expected default scan timezone %q, got %q", DefaultScanTimezone, cfg.Scan.Timezone)
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
exclude:
  cves: ["CVE-1", "CVE-1", ""]
  vulnerabilities:
    - id: GHSA-1
      package: openssl
      ecosystem: deb
      path: ./images/Dockerfile
scan:
  cron: "0 3 * * *"
  timezone: Europe/Berlin
  skip_paths: ["vendor", "./vendor", "  "]
registry:
  cache:
    ttl: 30m
  auth:
    mode: bearer
    token_env: REGISTRY_TOKEN
oci:
  policies:
    - name: platform-go
      source: registry.internal/platform/go-base
      tags:
        deny: [".*-debug$", ".*-debug$"]
        semver:
          - range: [">=1.21.1 <1.22.0"]
            includePrerelease: false
        allow: ["^v?\\d+\\.\\d+\\.\\d+-alpine$", "^v?\\d+\\.\\d+\\.\\d+-alpine$"]
  external_images:
    - source: ghcr.io/example/app
      dockerfiles: ["./images/Dockerfile", "./images/Dockerfile"]
go:
  patching:
    runtime: toolchain
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: "  org-wide guidance  "
      - mode: extend
        template: "org-wide guidance"
    baseline_scan_repair:
      scan_baseline:
        - mode: extend
          template: "fix baseline scanner setup"
    fix_vulnerabilities:
      deterministic_fix_failed:
        - mode: extend
          template: "when deterministic engines fail, prefer minimal lockfile diffs"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Exclude.CVEs) != 1 || cfg.Exclude.CVEs[0] != "CVE-1" {
		t.Fatalf("unexpected cve excludes: %#v", cfg.Exclude.CVEs)
	}
	if len(cfg.Scan.SkipPaths) != 1 || cfg.Scan.SkipPaths[0] != "vendor" {
		t.Fatalf("unexpected skip paths: %#v", cfg.Scan.SkipPaths)
	}
	if cfg.Scan.Cron != "0 3 * * *" {
		t.Fatalf("unexpected scan cron: %q", cfg.Scan.Cron)
	}
	if cfg.Scan.Timezone != "Europe/Berlin" {
		t.Fatalf("unexpected scan timezone: %q", cfg.Scan.Timezone)
	}
	if len(cfg.OCI.Policies) != 1 {
		t.Fatalf("unexpected OCI policies: %#v", cfg.OCI.Policies)
	}
	if cfg.OCI.Policies[0].Source != "registry.internal/platform/go-base" {
		t.Fatalf("unexpected OCI policy source: %#v", cfg.OCI.Policies[0])
	}
	if len(cfg.OCI.Policies[0].Tags.Deny) != 1 || cfg.OCI.Policies[0].Tags.Deny[0] != ".*-debug$" {
		t.Fatalf("unexpected OCI policy deny patterns: %#v", cfg.OCI.Policies[0].Tags.Deny)
	}
	if len(cfg.OCI.Policies[0].Tags.Semver) != 1 || len(cfg.OCI.Policies[0].Tags.Semver[0].Range) != 1 || cfg.OCI.Policies[0].Tags.Semver[0].Range[0] != ">=1.21.1 <1.22.0" {
		t.Fatalf("unexpected OCI semver config: %#v", cfg.OCI.Policies[0].Tags.Semver)
	}
	if len(cfg.OCI.Policies[0].Tags.Allow) != 1 || cfg.OCI.Policies[0].Tags.Allow[0] != "^v?\\d+\\.\\d+\\.\\d+-alpine$" {
		t.Fatalf("unexpected OCI allow patterns: %#v", cfg.OCI.Policies[0].Tags.Allow)
	}
	if len(cfg.OCI.ExternalImages) != 1 || len(cfg.OCI.ExternalImages[0].Dockerfiles) != 1 || cfg.OCI.ExternalImages[0].Dockerfiles[0] != "images/Dockerfile" {
		t.Fatalf("unexpected OCI external images: %#v", cfg.OCI.ExternalImages)
	}
	if cfg.Go.Patching.Runtime != GoRuntimePatchToolchain {
		t.Fatalf("unexpected go runtime patch mode: %q", cfg.Go.Patching.Runtime)
	}
	if len(cfg.Agent.RemediationPrompts.All) != 1 || cfg.Agent.RemediationPrompts.All[0].Template != "org-wide guidance" || cfg.Agent.RemediationPrompts.All[0].Mode != PromptModeExtend {
		t.Fatalf("unexpected normalized agent all prompts: %#v", cfg.Agent.RemediationPrompts.All)
	}
	if len(cfg.Agent.RemediationPrompts.BaselineScanRepair.ScanBaseline) != 1 {
		t.Fatalf("unexpected baseline scan prompts: %#v", cfg.Agent.RemediationPrompts.BaselineScanRepair.ScanBaseline)
	}
	if len(cfg.Agent.RemediationPrompts.FixVulnerabilities.DeterministicFixFailed) != 1 {
		t.Fatalf("unexpected deterministic fix prompts: %#v", cfg.Agent.RemediationPrompts.FixVulnerabilities.DeterministicFixFailed)
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

func TestLoadMigratesLegacyFields(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
postExecution:
  commands:
    - run: "echo done"
verificationMode: replace
verification:
  commands:
    - name: smoke
      command: "make verify"
skip_paths:
  - examples/**
excludes:
  cves:
    - CVE-123
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Scan.SkipPaths) != 1 || cfg.Scan.SkipPaths[0] != "examples/**" {
		t.Fatalf("expected migrated scan.skip_paths, got %#v", cfg.Scan.SkipPaths)
	}
	if len(cfg.Exclude.CVEs) != 1 || cfg.Exclude.CVEs[0] != "CVE-123" {
		t.Fatalf("expected migrated exclude section, got %#v", cfg.Exclude.CVEs)
	}
}

func TestSchemaJSONIncludesExpectedKeys(t *testing.T) {
	schema := string(SchemaJSON())
	for _, expected := range []string{
		`"$schema"`,
		`"PatchPilot Policy"`,
		`"skip_paths"`,
		`"cron"`,
		`"timezone"`,
		`"expires_at"`,
		`"cve_rules"`,
		`"go"`,
		`"runtime"`,
		`"oci"`,
		`"policies"`,
		`"external_images"`,
		`"dockerfiles"`,
		`"source"`,
		`"includePrerelease"`,
		`"agent"`,
		`"remediation_prompts"`,
		`"fix_vulnerabilities"`,
	} {
		if !strings.Contains(schema, expected) {
			t.Fatalf("expected schema to contain %q, got:\n%s", expected, schema)
		}
	}
}

func TestLoadRejectsOversizedAgentRemediationPrompts(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	oversized := strings.Repeat("x", DefaultAgentRemediationPromptsMaxBytes+1)
	content := fmt.Sprintf(`version: 1
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: %q
`, oversized)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected oversized remediation prompt validation error")
	}
	if !strings.Contains(err.Error(), "agent.remediation_prompts payload exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidAgentRemediationPromptTemplate(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: "{{ .MissingVariable }}"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected invalid remediation prompt template error")
	}
	if !strings.Contains(err.Error(), "agent.remediation_prompts.all[].template is invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadWithOptionsMergeAppendsAgentRemediationPromptsInOrder(t *testing.T) {
	repo := t.TempDir()
	repoPolicyPath := filepath.Join(repo, FileName)
	repoPolicy := `version: 1
agent:
  remediation_prompts:
    all:
      - mode: replace
        template: "repo: {{ .PromptSoFar }}"
`
	if err := os.WriteFile(repoPolicyPath, []byte(repoPolicy), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}

	centralPath := filepath.Join(t.TempDir(), "central.yaml")
	centralPolicy := `version: 1
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: "central"
`
	if err := os.WriteFile(centralPath, []byte(centralPolicy), 0o644); err != nil {
		t.Fatalf("write central policy: %v", err)
	}

	cfg, err := LoadWithOptions(repo, LoadOptions{
		CentralPath: centralPath,
		Mode:        LoadModeMerge,
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}

	if len(cfg.Agent.RemediationPrompts.All) != 2 {
		t.Fatalf("expected merged remediation prompts, got %#v", cfg.Agent.RemediationPrompts.All)
	}
	if cfg.Agent.RemediationPrompts.All[0].Template != "central" || cfg.Agent.RemediationPrompts.All[1].Template != "repo: {{ .PromptSoFar }}" {
		t.Fatalf("unexpected merged remediation prompt order: %#v", cfg.Agent.RemediationPrompts.All)
	}
}

func TestLoadRejectsExpiredExcludeWaiver(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
exclude:
  vulnerabilities:
    - id: GHSA-expired
      package: demo
      ecosystem: npm
      expires_at: 2001-01-01
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected expired waiver validation error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidScanCron(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
scan:
  cron: tomorrow
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected invalid scan cron error")
	}
	if !strings.Contains(err.Error(), "scan.cron") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidScanTimezone(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
scan:
  cron: "0 3 * * *"
  timezone: Mars/Olympus
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected invalid scan timezone error")
	}
	if !strings.Contains(err.Error(), "scan.timezone") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigResolveScanScheduleSupportsDisabled(t *testing.T) {
	cfg := Default()
	cfg.Scan.Cron = ScanCronDisabled

	schedule, location, enabled, err := cfg.ResolveScanSchedule()
	if err != nil {
		t.Fatalf("ResolveScanSchedule returned error: %v", err)
	}
	if enabled {
		t.Fatal("expected disabled schedule")
	}
	if schedule != nil {
		t.Fatal("expected nil schedule for disabled cron")
	}
	if location != nil {
		t.Fatal("expected nil location for disabled cron")
	}
}

func TestLoadWithOptionsMergeModeMergesCentralAndRepoPolicy(t *testing.T) {
	repo := t.TempDir()
	repoPolicyPath := filepath.Join(repo, FileName)
	repoPolicy := `version: 1
exclude:
  cves:
    - CVE-REPO
scan:
  skip_paths:
    - repo/**
registry:
  auth:
    mode: none
`
	if err := os.WriteFile(repoPolicyPath, []byte(repoPolicy), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}

	centralDir := t.TempDir()
	centralPath := filepath.Join(centralDir, "central.yaml")
	centralPolicy := `version: 1
exclude:
  cves:
    - CVE-CENTRAL
scan:
  skip_paths:
    - central/**
registry:
  auth:
    mode: bearer
    token_env: CENTRAL_TOKEN
oci:
  policies:
    - source: ghcr.io/example/*
`
	if err := os.WriteFile(centralPath, []byte(centralPolicy), 0o644); err != nil {
		t.Fatalf("write central policy: %v", err)
	}

	cfg, err := LoadWithOptions(repo, LoadOptions{
		CentralPath: centralPath,
		Mode:        LoadModeMerge,
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}
	if len(cfg.Exclude.CVEs) != 2 || cfg.Exclude.CVEs[0] != "CVE-CENTRAL" || cfg.Exclude.CVEs[1] != "CVE-REPO" {
		t.Fatalf("unexpected merged cves: %#v", cfg.Exclude.CVEs)
	}
	if len(cfg.Scan.SkipPaths) != 2 || cfg.Scan.SkipPaths[0] != "central/**" || cfg.Scan.SkipPaths[1] != "repo/**" {
		t.Fatalf("unexpected merged skip paths: %#v", cfg.Scan.SkipPaths)
	}
	if cfg.Registry.Auth.Mode != RegistryAuthNone {
		t.Fatalf("expected repo auth mode to take precedence, got %q", cfg.Registry.Auth.Mode)
	}
	if len(cfg.OCI.Policies) != 1 || cfg.OCI.Policies[0].Source != "ghcr.io/example/*" {
		t.Fatalf("expected central OCI policy to be preserved, got %#v", cfg.OCI.Policies)
	}
}

func TestLoadWithOptionsOverrideModePrefersRepoPolicy(t *testing.T) {
	repo := t.TempDir()
	repoPolicyPath := filepath.Join(repo, FileName)
	repoPolicy := `version: 1
scan:
  skip_paths:
    - repo/**
exclude:
  cves:
    - CVE-REPO
`
	if err := os.WriteFile(repoPolicyPath, []byte(repoPolicy), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}

	centralPath := filepath.Join(t.TempDir(), "central.yaml")
	centralPolicy := `version: 1
scan:
  skip_paths:
    - central/**
exclude:
  cves:
    - CVE-CENTRAL
`
	if err := os.WriteFile(centralPath, []byte(centralPolicy), 0o644); err != nil {
		t.Fatalf("write central policy: %v", err)
	}

	cfg, err := LoadWithOptions(repo, LoadOptions{
		CentralPath: centralPath,
		Mode:        LoadModeOverride,
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}
	if len(cfg.Scan.SkipPaths) != 1 || cfg.Scan.SkipPaths[0] != "repo/**" {
		t.Fatalf("expected repo-only skip paths, got %#v", cfg.Scan.SkipPaths)
	}
	if len(cfg.Exclude.CVEs) != 1 || cfg.Exclude.CVEs[0] != "CVE-REPO" {
		t.Fatalf("expected repo-only cves, got %#v", cfg.Exclude.CVEs)
	}
}

func TestLoadWithOptionsOverrideModeFallsBackToCentralWhenRepoPolicyMissing(t *testing.T) {
	repo := t.TempDir()
	centralPath := filepath.Join(t.TempDir(), "central.yaml")
	centralPolicy := `version: 1
scan:
  skip_paths:
    - central/**
exclude:
  cves:
    - CVE-CENTRAL
`
	if err := os.WriteFile(centralPath, []byte(centralPolicy), 0o644); err != nil {
		t.Fatalf("write central policy: %v", err)
	}

	cfg, err := LoadWithOptions(repo, LoadOptions{
		CentralPath: centralPath,
		Mode:        LoadModeOverride,
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}
	if len(cfg.Scan.SkipPaths) != 1 || cfg.Scan.SkipPaths[0] != "central/**" {
		t.Fatalf("expected central skip paths, got %#v", cfg.Scan.SkipPaths)
	}
}

func TestLoadWithOptionsDoesNotDoubleApplyWhenCentralPathEqualsRepoPolicyPath(t *testing.T) {
	repo := t.TempDir()
	repoPolicyPath := filepath.Join(repo, FileName)
	repoPolicy := `version: 1
scan:
  skip_paths:
    - repo/**
`
	if err := os.WriteFile(repoPolicyPath, []byte(repoPolicy), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}

	cfg, err := LoadWithOptions(repo, LoadOptions{
		CentralPath: repoPolicyPath,
		Mode:        LoadModeMerge,
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}
	if len(cfg.Scan.SkipPaths) != 1 {
		t.Fatalf("expected policy to be loaded once, got %#v", cfg.Scan.SkipPaths)
	}
}

func TestLoadWithOptionsRejectsInvalidMode(t *testing.T) {
	repo := t.TempDir()
	_, err := LoadWithOptions(repo, LoadOptions{Mode: "invalid"})
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
	if !strings.Contains(err.Error(), "invalid policy load mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseYAMLWithOptionsUntrustedRepoSanitizesExecutableSections(t *testing.T) {
	content := `version: 1
registry:
  auth:
    mode: bearer
    token_env: REGISTRY_TOKEN
oci:
  external_images:
    - source: ghcr.io/example/app
      dockerfiles:
        - Dockerfile
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: do not trust repo prompt text in app mode
scan:
  cron: "0 3 * * *"
  timezone: Europe/Berlin
exclude:
  cves:
    - CVE-123
`

	cfg, err := ParseYAMLWithOptions([]byte(content), ParseOptions{UntrustedRepo: true})
	if err != nil {
		t.Fatalf("ParseYAMLWithOptions returned error: %v", err)
	}
	if cfg.Registry.Auth.Mode != RegistryAuthAuto {
		t.Fatalf("expected registry auth to fall back to default auto mode, got %q", cfg.Registry.Auth.Mode)
	}
	if len(cfg.Agent.RemediationPrompts.All) != 0 {
		t.Fatalf("expected agent prompts to be stripped, got %#v", cfg.Agent.RemediationPrompts.All)
	}
	if len(cfg.OCI.ExternalImages) != 1 || cfg.OCI.ExternalImages[0].Source != "ghcr.io/example/app" {
		t.Fatalf("expected OCI mappings to remain in untrusted mode, got %#v", cfg.OCI.ExternalImages)
	}
	if cfg.Scan.Cron != "0 3 * * *" || cfg.Scan.Timezone != "Europe/Berlin" {
		t.Fatalf("expected declarative scan policy to remain, got %#v", cfg.Scan)
	}
	if len(cfg.Exclude.CVEs) != 1 || cfg.Exclude.CVEs[0] != "CVE-123" {
		t.Fatalf("expected exclude settings to remain, got %#v", cfg.Exclude.CVEs)
	}
}

func TestLoadWithOptionsUntrustedRepoDoesNotOverrideTrustedCentralExecutionPolicy(t *testing.T) {
	repo := t.TempDir()
	repoPolicyPath := filepath.Join(repo, FileName)
	repoPolicy := `version: 1
registry:
  auth:
    mode: none
scan:
  skip_paths:
    - repo/**
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: repo guidance
`
	if err := os.WriteFile(repoPolicyPath, []byte(repoPolicy), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}

	centralPath := filepath.Join(t.TempDir(), "central.yaml")
	centralPolicy := `version: 1
registry:
  auth:
    mode: bearer
    token_env: CENTRAL_TOKEN
scan:
  skip_paths:
    - central/**
agent:
  remediation_prompts:
    all:
      - mode: extend
        template: central guidance
    fix_vulnerabilities:
      all:
        - mode: extend
          template: central fix guidance
`
	if err := os.WriteFile(centralPath, []byte(centralPolicy), 0o644); err != nil {
		t.Fatalf("write central policy: %v", err)
	}

	cfg, err := LoadWithOptions(repo, LoadOptions{
		CentralPath:   centralPath,
		Mode:          LoadModeMerge,
		UntrustedRepo: true,
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}
	if cfg.Registry.Auth.Mode != RegistryAuthBearer || cfg.Registry.Auth.TokenEnv != "CENTRAL_TOKEN" {
		t.Fatalf("expected trusted central registry auth to remain, got %#v", cfg.Registry.Auth)
	}
	if len(cfg.Scan.SkipPaths) != 2 || cfg.Scan.SkipPaths[0] != "central/**" || cfg.Scan.SkipPaths[1] != "repo/**" {
		t.Fatalf("expected safe declarative repo settings to still merge, got %#v", cfg.Scan.SkipPaths)
	}
	if len(cfg.Agent.RemediationPrompts.All) != 1 || cfg.Agent.RemediationPrompts.All[0].Template != "central guidance" {
		t.Fatalf("expected trusted central agent prompts to remain, got %#v", cfg.Agent.RemediationPrompts.All)
	}
	if len(cfg.Agent.RemediationPrompts.FixVulnerabilities.All) != 1 || cfg.Agent.RemediationPrompts.FixVulnerabilities.All[0].Template != "central fix guidance" {
		t.Fatalf("expected trusted central task prompts to remain, got %#v", cfg.Agent.RemediationPrompts.FixVulnerabilities.All)
	}
}

func TestLoadNormalizesOCIExternalImages(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
oci:
  external_images:
    - source: ghcr.io/example/backend
      dockerfiles:
        - ./images/backend/Dockerfile
        - ./images/backend/Dockerfile
  policies:
    - source: ghcr.io/example/*
      tags:
        allow:
          - '^v?\d+\.\d+\.\d+$'
          - '^v?\d+\.\d+\.\d+$'
        semver:
          - range:
              - ">=1.2.3 <2.0.0"
              - ">=1.2.3 <2.0.0"
            includePrerelease: true
            prereleaseAllow:
              - '^rc\..*'
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.OCI.ExternalImages) != 1 {
		t.Fatalf("expected one OCI external image entry, got %#v", cfg.OCI.ExternalImages)
	}
	if cfg.OCI.ExternalImages[0].Tag != OCITagStrategyLatestSemver {
		t.Fatalf("expected default OCI tag strategy %q, got %q", OCITagStrategyLatestSemver, cfg.OCI.ExternalImages[0].Tag)
	}
	if len(cfg.OCI.ExternalImages[0].Dockerfiles) != 1 || cfg.OCI.ExternalImages[0].Dockerfiles[0] != "images/backend/Dockerfile" {
		t.Fatalf("unexpected normalized dockerfile list: %#v", cfg.OCI.ExternalImages[0].Dockerfiles)
	}
	if len(cfg.OCI.Policies) != 1 {
		t.Fatalf("expected one OCI policy, got %#v", cfg.OCI.Policies)
	}
	if len(cfg.OCI.Policies[0].Tags.Allow) != 1 {
		t.Fatalf("expected deduped allow list, got %#v", cfg.OCI.Policies[0].Tags.Allow)
	}
	if len(cfg.OCI.Policies[0].Tags.Semver) != 1 || len(cfg.OCI.Policies[0].Tags.Semver[0].Range) != 1 {
		t.Fatalf("expected deduped semver ranges, got %#v", cfg.OCI.Policies[0].Tags.Semver)
	}
}

func TestLoadRejectsInvalidOCIPolicyRegex(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
oci:
  policies:
    - source: ghcr.io/example/*
      tags:
        allow:
          - '['
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected validation error for invalid OCI regex")
	}
	if !strings.Contains(err.Error(), "oci.policies[0].tags.allow[0]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsEmptyOCIExternalImageSource(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
oci:
  external_images:
    - source: ""
      dockerfiles:
        - Dockerfile
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected validation error for empty source")
	}
	if !strings.Contains(err.Error(), "oci.external_images[0].source") {
		t.Fatalf("unexpected error: %v", err)
	}
}
