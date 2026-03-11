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
	if cfg.Verification.Mode != VerificationModeAppend {
		t.Fatalf("expected verification append mode, got %q", cfg.Verification.Mode)
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
  cron: "0 3 * * *"
  timezone: Europe/Berlin
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
go:
  patching:
    runtime: toolchain
agent:
  remediation_prompts:
    all: ["  org-wide guidance  ", "", "org-wide guidance"]
    baseline_scan_repair:
      scan_baseline:
        - "fix baseline scanner setup"
    fix_vulnerabilities:
      deterministic_fix_failed:
        - "when deterministic engines fail, prefer minimal lockfile diffs"
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
	if cfg.Scan.Cron != "0 3 * * *" {
		t.Fatalf("unexpected scan cron: %q", cfg.Scan.Cron)
	}
	if cfg.Scan.Timezone != "Europe/Berlin" {
		t.Fatalf("unexpected scan timezone: %q", cfg.Scan.Timezone)
	}
	if cfg.Docker.Patching.BaseImages != DockerPatchDisabled {
		t.Fatalf("unexpected docker base patch mode: %q", cfg.Docker.Patching.BaseImages)
	}
	if cfg.Go.Patching.Runtime != GoRuntimePatchToolchain {
		t.Fatalf("unexpected go runtime patch mode: %q", cfg.Go.Patching.Runtime)
	}
	if len(cfg.Agent.RemediationPrompts.All) != 1 || cfg.Agent.RemediationPrompts.All[0] != "org-wide guidance" {
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

	if cfg.Verification.Mode != VerificationModeReplace {
		t.Fatalf("expected migrated verification mode replace, got %q", cfg.Verification.Mode)
	}
	if len(cfg.Verification.Commands) != 1 || cfg.Verification.Commands[0].Run != "make verify" {
		t.Fatalf("expected migrated verification command run field, got %#v", cfg.Verification.Commands)
	}
	if len(cfg.PostExecution.Commands) != 1 {
		t.Fatalf("expected migrated post execution commands, got %#v", cfg.PostExecution.Commands)
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
		`"pre_execution"`,
		`"post_execution"`,
		`"skip_paths"`,
		`"cron"`,
		`"timezone"`,
		`"expires_at"`,
		`"cve_rules"`,
		`"go"`,
		`"runtime"`,
		`"artifacts"`,
		`"targets_command"`,
		`"dockerfile"`,
		`"image"`,
		`"build"`,
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
      - %q
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
verification:
  commands:
    - name: repo-check
      run: make verify-repo
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
verification:
  commands:
    - name: central-check
      run: make verify-central
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
docker:
  allowed_base_images:
    - cgr.dev/chainguard/*
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
	if len(cfg.Verification.Commands) != 2 {
		t.Fatalf("expected merged verification commands, got %#v", cfg.Verification.Commands)
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
	if len(cfg.Docker.AllowedBaseImages) != 1 || cfg.Docker.AllowedBaseImages[0] != "cgr.dev/chainguard/*" {
		t.Fatalf("expected central docker policy to be preserved, got %#v", cfg.Docker.AllowedBaseImages)
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
verification:
  commands:
    - run: make verify
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
	if len(cfg.Verification.Commands) != 1 {
		t.Fatalf("expected policy to be loaded once, got %#v", cfg.Verification.Commands)
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
pre_execution:
  commands:
    - run: echo pre
verification:
  mode: replace
  commands:
    - run: make verify
post_execution:
  commands:
    - run: echo done
registry:
  auth:
    mode: bearer
    token_env: REGISTRY_TOKEN
artifacts:
  targets:
    - dockerfile: Dockerfile
      image:
        tag: patchpilot/demo:${PP_RUN_ID}
      build:
        run: make image
agent:
  remediation_prompts:
    all:
      - do not trust repo prompt text in app mode
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
	if len(cfg.Verification.Commands) != 0 {
		t.Fatalf("expected verification commands to be stripped, got %#v", cfg.Verification.Commands)
	}
	if len(cfg.PreExecution.Commands) != 0 {
		t.Fatalf("expected pre execution hooks to be stripped, got %#v", cfg.PreExecution.Commands)
	}
	if len(cfg.PostExecution.Commands) != 0 {
		t.Fatalf("expected post execution hooks to be stripped, got %#v", cfg.PostExecution.Commands)
	}
	if cfg.Registry.Auth.Mode != RegistryAuthAuto {
		t.Fatalf("expected registry auth to fall back to default auto mode, got %q", cfg.Registry.Auth.Mode)
	}
	if len(cfg.Artifacts.Targets) != 0 {
		t.Fatalf("expected artifacts to be stripped, got %#v", cfg.Artifacts.Targets)
	}
	if len(cfg.Agent.RemediationPrompts.All) != 0 {
		t.Fatalf("expected agent prompts to be stripped, got %#v", cfg.Agent.RemediationPrompts.All)
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
pre_execution:
  commands:
    - run: echo repo-pre
verification:
  mode: replace
  commands:
    - name: repo-check
      run: make verify-repo
post_execution:
  commands:
    - run: echo repo
registry:
  auth:
    mode: none
scan:
  skip_paths:
    - repo/**
agent:
  remediation_prompts:
    all:
      - repo guidance
`
	if err := os.WriteFile(repoPolicyPath, []byte(repoPolicy), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}

	centralPath := filepath.Join(t.TempDir(), "central.yaml")
	centralPolicy := `version: 1
pre_execution:
  commands:
    - run: echo central-pre
verification:
  commands:
    - name: central-check
      run: make verify-central
post_execution:
  commands:
    - run: echo central
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
      - central guidance
    fix_vulnerabilities:
      all:
        - central fix guidance
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
	if len(cfg.Verification.Commands) != 1 || cfg.Verification.Commands[0].Name != "central-check" {
		t.Fatalf("expected trusted central verification command to remain, got %#v", cfg.Verification.Commands)
	}
	if len(cfg.PreExecution.Commands) != 1 || cfg.PreExecution.Commands[0].Run != "echo central-pre" {
		t.Fatalf("expected trusted central pre hook to remain, got %#v", cfg.PreExecution.Commands)
	}
	if len(cfg.PostExecution.Commands) != 1 || cfg.PostExecution.Commands[0].Run != "echo central" {
		t.Fatalf("expected trusted central post hook to remain, got %#v", cfg.PostExecution.Commands)
	}
	if cfg.Registry.Auth.Mode != RegistryAuthBearer || cfg.Registry.Auth.TokenEnv != "CENTRAL_TOKEN" {
		t.Fatalf("expected trusted central registry auth to remain, got %#v", cfg.Registry.Auth)
	}
	if len(cfg.Scan.SkipPaths) != 2 || cfg.Scan.SkipPaths[0] != "central/**" || cfg.Scan.SkipPaths[1] != "repo/**" {
		t.Fatalf("expected safe declarative repo settings to still merge, got %#v", cfg.Scan.SkipPaths)
	}
	if len(cfg.Agent.RemediationPrompts.All) != 1 || cfg.Agent.RemediationPrompts.All[0] != "central guidance" {
		t.Fatalf("expected trusted central agent prompts to remain, got %#v", cfg.Agent.RemediationPrompts.All)
	}
	if len(cfg.Agent.RemediationPrompts.FixVulnerabilities.All) != 1 || cfg.Agent.RemediationPrompts.FixVulnerabilities.All[0] != "central fix guidance" {
		t.Fatalf("expected trusted central task prompts to remain, got %#v", cfg.Agent.RemediationPrompts.FixVulnerabilities.All)
	}
}

func TestLoadNormalizesArtifactTargets(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
artifacts:
  targets_command:
    run: make patchpilot-targets
  targets:
    - dockerfile: ./images/backend/Dockerfile
      image:
        tag: patchpilot/backend:${PP_RUN_ID}
      build:
        run: APP=backend make container-image
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Artifacts.Targets) != 1 {
		t.Fatalf("expected one artifact target, got %#v", cfg.Artifacts.Targets)
	}
	if cfg.Artifacts.TargetsCommand.Mode != ArtifactsTargetsCommandModeReplace {
		t.Fatalf("expected default targets command mode %q, got %q", ArtifactsTargetsCommandModeReplace, cfg.Artifacts.TargetsCommand.Mode)
	}
	if cfg.Artifacts.TargetsCommand.Timeout != DefaultArtifactsTargetsTimeout {
		t.Fatalf("expected default targets command timeout %q, got %q", DefaultArtifactsTargetsTimeout, cfg.Artifacts.TargetsCommand.Timeout)
	}
	if !cfg.Artifacts.TargetsCommand.FailOnErrorOrDefault() {
		t.Fatalf("expected default fail_on_error=true")
	}
	target := cfg.Artifacts.Targets[0]
	if target.ID == "" {
		t.Fatalf("expected default id to be set, got %#v", target)
	}
	if target.Dockerfile != "images/backend/Dockerfile" {
		t.Fatalf("unexpected dockerfile path: %q", target.Dockerfile)
	}
	if target.Context != "images/backend" {
		t.Fatalf("expected context to default from dockerfile dir, got %q", target.Context)
	}
	if target.Build.Timeout != "30m" {
		t.Fatalf("expected default build timeout 30m, got %q", target.Build.Timeout)
	}
	if !target.Scan.EnabledOrDefault() {
		t.Fatalf("expected scan to default to enabled")
	}
}

func TestLoadPreservesExplicitArtifactRootContext(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
artifacts:
  targets:
    - dockerfile: ./images/backend/Dockerfile
      context: .
      image:
        tag: patchpilot/backend:${PP_RUN_ID}
      build:
        run: APP=backend make container-image
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	cfg, err := Load(repo, "")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Artifacts.Targets) != 1 {
		t.Fatalf("expected one artifact target, got %#v", cfg.Artifacts.Targets)
	}
	if cfg.Artifacts.Targets[0].Context != "." {
		t.Fatalf("expected explicit root context to be preserved, got %q", cfg.Artifacts.Targets[0].Context)
	}
}

func TestLoadRejectsInvalidArtifactTargetsCommandMode(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, FileName)
	content := `version: 1
artifacts:
  targets_command:
    run: 'echo "targets: []"'
    mode: nope
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := Load(repo, "")
	if err == nil {
		t.Fatal("expected validation error for invalid mode")
	}
	if !strings.Contains(err.Error(), "artifacts.targets_command.mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}
