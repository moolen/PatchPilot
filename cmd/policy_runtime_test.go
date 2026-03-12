package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/vuln"
)

func TestOptionsFromPolicy(t *testing.T) {
	cfg := &policy.Config{
		Scan: policy.ScanPolicy{
			SkipPaths: []string{"vendor/**", "examples/**"},
		},
		Exclude: policy.ExcludePolicy{
			CVEs: []string{"CVE-2026-0001", "  ", "GHSA-xyz"},
			Vulnerabilities: []policy.VulnerabilitySelector{
				{
					ID:        "GHSA-special",
					Package:   "openssl",
					Ecosystem: "deb",
					Path:      "Dockerfile",
				},
			},
		},
		OCI: policy.OCIPolicy{
			Policies: []policy.OCIImagePolicy{
				{
					Name:   "go-base",
					Source: "registry.internal/platform/go-base",
					Tags: policy.OCITagPolicy{
						Allow: []string{`^v?\d+\.\d+\.\d+-alpine$`},
						Deny:  []string{".*-debug$"},
						Semver: []policy.OCISemverPolicy{
							{Range: []string{">=1.21.1 <1.22.0"}},
						},
					},
				},
			},
		},
		Go: policy.GoPolicy{
			Patching: policy.GoPatchingPolicy{Runtime: policy.GoRuntimePatchToolchain},
		},
	}

	sbomOptions := sbomOptionsFromPolicy(cfg)
	if !reflect.DeepEqual(sbomOptions.Exclude, []string{"vendor/**", "examples/**"}) {
		t.Fatalf("unexpected sbom excludes: %#v", sbomOptions.Exclude)
	}

	vulnOptions := vulnOptionsFromPolicy(cfg)
	if len(vulnOptions.IgnoreRules) != 3 {
		t.Fatalf("unexpected ignore rules: %#v", vulnOptions.IgnoreRules)
	}
	if !reflect.DeepEqual(vulnOptions.SkipPaths, []string{"vendor/**", "examples/**"}) {
		t.Fatalf("unexpected vuln skip paths: %#v", vulnOptions.SkipPaths)
	}

	fileOptions := fileOptionsFromPolicy(cfg, false)
	if !reflect.DeepEqual(fileOptions.SkipPaths, []string{"vendor/**", "examples/**"}) {
		t.Fatalf("unexpected file skip paths: %#v", fileOptions.SkipPaths)
	}

	dockerOptions := dockerOptionsFromPolicy(cfg)
	if !dockerOptions.BaseImagePatching {
		t.Fatalf("expected base image patching enabled")
	}
	if dockerOptions.OSPackagePatching {
		t.Fatalf("expected OS package patching disabled")
	}
	if len(dockerOptions.OCIPolicies) != 1 {
		t.Fatalf("unexpected OCI policies: %#v", dockerOptions.OCIPolicies)
	}
	if dockerOptions.OCIPolicies[0].Source != "registry.internal/platform/go-base" {
		t.Fatalf("unexpected OCI policy source: %#v", dockerOptions.OCIPolicies)
	}
	if !reflect.DeepEqual(dockerOptions.OCIPolicies[0].Tags.Deny, []string{".*-debug$"}) {
		t.Fatalf("unexpected OCI deny patterns: %#v", dockerOptions.OCIPolicies[0].Tags.Deny)
	}
	if len(dockerOptions.OCIPolicies[0].Tags.Semver) != 1 {
		t.Fatalf("unexpected OCI semver rules: %#v", dockerOptions.OCIPolicies[0].Tags.Semver)
	}
	if dockerOptions.OCIPolicies[0].Tags.Semver[0].Range[0] != ">=1.21.1 <1.22.0" {
		t.Fatalf("unexpected OCI semver range: %#v", dockerOptions.OCIPolicies[0].Tags.Semver[0])
	}
	if !reflect.DeepEqual(dockerOptions.OCIPolicies[0].Tags.Allow, []string{`^v?\d+\.\d+\.\d+-alpine$`}) {
		t.Fatalf("unexpected OCI allow patterns: %#v", dockerOptions.OCIPolicies[0].Tags.Allow)
	}

	goRuntimeOptions := goRuntimeOptionsFromPolicy(cfg)
	if goRuntimeOptions.Mode != fixer.GoRuntimeModeToolchain {
		t.Fatalf("unexpected go runtime mode: %q", goRuntimeOptions.Mode)
	}
	if !reflect.DeepEqual(goRuntimeOptions.SkipPaths, []string{"vendor/**", "examples/**"}) {
		t.Fatalf("unexpected go runtime skip paths: %#v", goRuntimeOptions.SkipPaths)
	}
}

func TestValidationCommandsForPrompt(t *testing.T) {
	standard := []string{"go build ./...", "go test -run=^$ ./..."}

	if got := validationCommandsForPrompt(nil); !reflect.DeepEqual(got, standard) {
		t.Fatalf("unexpected commands for nil config: %#v", got)
	}

	appendCfg := &policy.Config{
		Verification: policy.VerificationPolicy{
			Mode: policy.VerificationModeAppend,
			Commands: []policy.CommandPolicy{
				{Name: "lint", Run: "make lint"},
			},
		},
	}
	if got := validationCommandsForPrompt(appendCfg); !reflect.DeepEqual(got, append(append([]string{}, standard...), "make lint")) {
		t.Fatalf("unexpected append commands: %#v", got)
	}

	replaceCfg := &policy.Config{
		Verification: policy.VerificationPolicy{
			Mode: policy.VerificationModeReplace,
			Commands: []policy.CommandPolicy{
				{Name: "verify", Run: "make verify"},
			},
		},
	}
	if got := validationCommandsForPrompt(replaceCfg); !reflect.DeepEqual(got, []string{"make verify"}) {
		t.Fatalf("unexpected replace commands: %#v", got)
	}
}

func TestShouldRunHook(t *testing.T) {
	tests := []struct {
		name    string
		when    string
		success bool
		want    bool
	}{
		{name: "always default", when: "", success: true, want: true},
		{name: "always explicit", when: policy.HookWhenAlways, success: false, want: true},
		{name: "success true", when: policy.HookWhenSuccess, success: true, want: true},
		{name: "success false", when: policy.HookWhenSuccess, success: false, want: false},
		{name: "failure true", when: policy.HookWhenFailure, success: false, want: true},
		{name: "failure false", when: policy.HookWhenFailure, success: true, want: false},
		{name: "invalid", when: "unknown", success: true, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldRunHook(test.when, test.success); got != test.want {
				t.Fatalf("unexpected shouldRunHook result: got %t want %t", got, test.want)
			}
		})
	}
}

func TestRunPostExecutionHooks(t *testing.T) {
	repo := t.TempDir()
	cfg := &policy.Config{
		PostExecution: policy.PostExecutionPolicy{
			Commands: []policy.HookPolicy{
				{Name: "write", Run: "echo ok > hook.txt", When: policy.HookWhenSuccess, FailOnError: true},
			},
		},
	}
	if err := runPostExecutionHooks(context.Background(), repo, cfg, true); err != nil {
		t.Fatalf("runPostExecutionHooks returned error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "hook.txt"))
	if err != nil {
		t.Fatalf("read hook output: %v", err)
	}
	if strings.TrimSpace(string(data)) != "ok" {
		t.Fatalf("unexpected hook output: %q", string(data))
	}

	cfg.PostExecution.Commands = []policy.HookPolicy{
		{Name: "break", Run: "exit 5", When: policy.HookWhenAlways, FailOnError: false},
	}
	if err := runPostExecutionHooks(context.Background(), repo, cfg, true); err != nil {
		t.Fatalf("expected ignored hook failure, got: %v", err)
	}

	cfg.PostExecution.Commands = []policy.HookPolicy{
		{Name: "fatal", Run: "exit 6", When: policy.HookWhenAlways, FailOnError: true},
	}
	if err := runPostExecutionHooks(context.Background(), repo, cfg, true); err == nil {
		t.Fatal("expected fatal hook failure")
	}
}

func TestRunPreExecutionHooks(t *testing.T) {
	repo := t.TempDir()
	cfg := &policy.Config{
		PreExecution: policy.PreExecutionPolicy{
			Commands: []policy.PreHookPolicy{
				{Name: "write", Run: "echo pre > pre.txt", FailOnError: true},
			},
		},
	}
	if err := runPreExecutionHooks(context.Background(), repo, cfg); err != nil {
		t.Fatalf("runPreExecutionHooks returned error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "pre.txt"))
	if err != nil {
		t.Fatalf("read pre hook output: %v", err)
	}
	if strings.TrimSpace(string(data)) != "pre" {
		t.Fatalf("unexpected pre hook output: %q", string(data))
	}

	cfg.PreExecution.Commands = []policy.PreHookPolicy{
		{Name: "break", Run: "exit 5", FailOnError: false},
	}
	if err := runPreExecutionHooks(context.Background(), repo, cfg); err != nil {
		t.Fatalf("expected ignored pre hook failure, got: %v", err)
	}

	cfg.PreExecution.Commands = []policy.PreHookPolicy{
		{Name: "fatal", Run: "exit 6", FailOnError: true},
	}
	if err := runPreExecutionHooks(context.Background(), repo, cfg); err == nil {
		t.Fatal("expected fatal pre hook failure")
	}
}

func TestConfigureRegistryFromPolicy(t *testing.T) {
	repo := t.TempDir()

	restore, err := configureRegistryFromPolicy(repo, nil)
	if err != nil {
		t.Fatalf("configureRegistryFromPolicy returned error for nil config: %v", err)
	}
	restore()

	cfg := &policy.Config{
		Registry: policy.RegistryPolicy{
			Auth: policy.RegistryAuthPolicy{
				Mode:     policy.RegistryAuthBearer,
				TokenEnv: "REGISTRY_TEST_TOKEN",
			},
		},
	}

	if _, err := configureRegistryFromPolicy(repo, cfg); err == nil {
		t.Fatal("expected error when bearer token env is missing")
	}

	t.Setenv("REGISTRY_TEST_TOKEN", "token-value")
	restore, err = configureRegistryFromPolicy(repo, cfg)
	if err != nil {
		t.Fatalf("configureRegistryFromPolicy returned error: %v", err)
	}
	restore()
}

func TestRunVerificationChecksInvalidTimeout(t *testing.T) {
	cfg := &policy.Config{
		Verification: policy.VerificationPolicy{
			Mode: policy.VerificationModeAppend,
			Commands: []policy.CommandPolicy{
				{Name: "bad", Run: "echo hi", Timeout: "not-a-duration"},
			},
		},
	}

	_, err := runVerificationChecks(context.Background(), t.TempDir(), []string{"."}, cfg)
	if err == nil {
		t.Fatal("expected timeout parse error")
	}
	if !strings.Contains(err.Error(), "parse verification command timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMergeVulnerabilityReportsDeduplicatesFindings(t *testing.T) {
	left := &vuln.Report{
		RawMatches: 2,
		Findings: []vuln.Finding{
			{
				VulnerabilityID: "CVE-1",
				Package:         "openssl",
				FixedVersion:    "1.2.3",
				Ecosystem:       "deb",
				Locations:       []string{"/tmp/repo/Dockerfile"},
			},
		},
	}
	right := &vuln.Report{
		RawMatches: 1,
		Findings: []vuln.Finding{
			{
				VulnerabilityID: "CVE-1",
				Package:         "openssl",
				FixedVersion:    "1.2.3",
				Ecosystem:       "deb",
				Locations:       []string{"/tmp/repo/Dockerfile"},
			},
			{
				VulnerabilityID: "CVE-2",
				Package:         "busybox",
				FixedVersion:    "1.0.1",
				Ecosystem:       "apk",
				Locations:       []string{"/tmp/repo/Dockerfile"},
			},
		},
	}

	merged := mergeVulnerabilityReports(left, right)
	if merged.RawMatches != 3 {
		t.Fatalf("unexpected raw match count: %d", merged.RawMatches)
	}
	if len(merged.Findings) != 2 {
		t.Fatalf("unexpected merged findings: %#v", merged.Findings)
	}
}
