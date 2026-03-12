package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type packSnapshot struct {
	Version                 int                     `json:"version"`
	VerificationMode        string                  `json:"verification_mode"`
	VerificationCommands    []CommandPolicy         `json:"verification_commands"`
	PostExecutionHooks      []HookPolicy            `json:"post_execution_hooks"`
	ExcludedCVEs            []string                `json:"excluded_cves"`
	ExcludedVulnerabilities []VulnerabilitySelector `json:"excluded_vulnerabilities"`
	ScanSkipPaths           []string                `json:"scan_skip_paths"`
	RegistryCacheDir        string                  `json:"registry_cache_dir"`
	RegistryCacheTTL        string                  `json:"registry_cache_ttl"`
	RegistryAuthMode        string                  `json:"registry_auth_mode"`
	RegistryAuthTokenEnv    string                  `json:"registry_auth_token_env"`
	OCIPolicies             []OCIImagePolicy        `json:"oci_policies"`
	OCIExternalImages       []OCIExternalImageSpec  `json:"oci_external_images"`
}

func TestPolicyPackGolden(t *testing.T) {
	root := filepath.Join("testdata", "packs")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read policy pack dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no policy packs found in %s", root)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		packDir := filepath.Join(root, name)
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(packDir, "")
			if err != nil {
				t.Fatalf("load policy pack %q: %v", name, err)
			}

			snapshot := packSnapshot{
				Version:                 cfg.Version,
				VerificationMode:        cfg.Verification.Mode,
				VerificationCommands:    cfg.Verification.Commands,
				PostExecutionHooks:      cfg.PostExecution.Commands,
				ExcludedCVEs:            cfg.Exclude.CVEs,
				ExcludedVulnerabilities: cfg.Exclude.Vulnerabilities,
				ScanSkipPaths:           cfg.Scan.SkipPaths,
				RegistryCacheDir:        cfg.Registry.Cache.Dir,
				RegistryCacheTTL:        cfg.Registry.Cache.TTL,
				RegistryAuthMode:        cfg.Registry.Auth.Mode,
				RegistryAuthTokenEnv:    cfg.Registry.Auth.TokenEnv,
				OCIPolicies:             cfg.OCI.Policies,
				OCIExternalImages:       cfg.OCI.ExternalImages,
			}
			data, err := json.MarshalIndent(snapshot, "", "  ")
			if err != nil {
				t.Fatalf("marshal snapshot: %v", err)
			}

			goldenPath := filepath.Join(packDir, "expected.golden.json")
			assertPackGolden(t, goldenPath, data)
		})
	}
}

func TestPolicyPackInvalidConfigurations(t *testing.T) {
	cases := []struct {
		name        string
		errorSubstr string
	}{
		{name: "registry-bearer-no-token", errorSubstr: "token_env"},
		{name: "verification-invalid-timeout", errorSubstr: "verification.commands[0].timeout"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := filepath.Join("testdata", "packs-invalid", tc.name)
			_, err := Load(repo, "")
			if err == nil {
				t.Fatalf("expected error for pack %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.errorSubstr) {
				t.Fatalf("expected error for pack %q to contain %q, got: %v", tc.name, tc.errorSubstr, err)
			}
		})
	}
}

func assertPackGolden(t *testing.T, path string, data []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write golden file %s: %v", path, err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file %s: %v", path, err)
	}
	if string(expected) != string(append(data, '\n')) {
		t.Fatalf("golden mismatch for %s\nset UPDATE_GOLDEN=1 to update", path)
	}
}
