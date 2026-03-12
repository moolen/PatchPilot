package cmd

import (
	"reflect"
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
