package vuln

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndNormalizeRawReport(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	for _, path := range []string{
		filepath.Join(repo, "go.mod"),
		filepath.Join(repo, "Dockerfile"),
		filepath.Join(repo, ".github", "workflows", "ci.yml"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir parent for %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("placeholder\n"), 0o644); err != nil {
			t.Fatalf("write fixture file %s: %v", path, err)
		}
	}

	rawPath := filepath.Join(repo, ".patchpilot", "raw.json")
	raw := `{
  "matches": [
    {
      "artifact": {
        "name": "github.com/example/lib",
        "version": "v1.0.0",
        "type": "go-module",
        "language": "go",
        "purl": "pkg:golang/github.com/example/lib@v1.0.0",
        "locations": [
          {"path": "/go.mod"},
          {"path": "/go.mod"}
        ]
      },
      "vulnerability": {
        "id": "GHSA-keep-me",
        "namespace": "github:language:go",
        "fix": {
          "versions": ["v1.2.4", "1.2.3"],
          "state": "fixed"
        }
      }
    },
    {
      "artifact": {
        "name": "openssl",
        "version": "1.0.2",
        "type": "deb",
        "purl": "pkg:deb/debian/openssl@1.0.2",
        "locations": [
          {"path": "/Dockerfile"}
        ]
      },
      "vulnerability": {
        "id": "CVE-2025-0001",
        "namespace": "debian:distro:debian:12",
        "fix": {
          "versions": ["1.0.3", "1.0.4"],
          "state": "fixed"
        }
      }
    },
    {
      "artifact": {
        "name": "github.com/example/no-fix",
        "version": "v0.9.0",
        "type": "go-module",
        "language": "go",
        "purl": "pkg:golang/github.com/example/no-fix@v0.9.0",
        "locations": [
          {"path": "/go.mod"}
        ]
      },
      "vulnerability": {
        "id": "GHSA-ignore-me",
        "namespace": "github:language:go",
        "fix": {
          "versions": [],
          "state": "not-fixed"
        }
      }
    },
    {
      "artifact": {
        "name": "checkout",
        "version": "v4.0.0",
        "type": "github-action",
        "language": "",
        "purl": "pkg:github/actions/checkout@v4.0.0",
        "locations": [
          {"path": "/.github/workflows/ci.yml"}
        ]
      },
      "vulnerability": {
        "id": "GHSA-actions-checkout",
        "namespace": "github:language:github-action",
        "fix": {
          "versions": ["v4.2.3", "v4.2.2"],
          "state": "fixed"
        }
      }
    }
  ]
}`
	if err := os.WriteFile(rawPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write raw report: %v", err)
	}

	parsed, err := parseRawReport(rawPath)
	if err != nil {
		t.Fatalf("parseRawReport returned error: %v", err)
	}

	normalized := normalizeReport(repo, parsed, ScanOptions{})
	if normalized.RawMatches != 4 {
		t.Fatalf("expected 4 raw matches, got %d", normalized.RawMatches)
	}
	if normalized.IgnoredWithoutFix != 1 {
		t.Fatalf("expected 1 ignored finding, got %d", normalized.IgnoredWithoutFix)
	}
	if len(normalized.Findings) != 3 {
		t.Fatalf("expected 3 normalized findings, got %d", len(normalized.Findings))
	}

	var (
		goFinding     Finding
		debFinding    Finding
		actionFinding Finding
	)
	for _, finding := range normalized.Findings {
		switch {
		case finding.Ecosystem == "golang" && finding.Package == "github.com/example/lib":
			goFinding = finding
		case finding.Ecosystem == "deb" && finding.Package == "openssl":
			debFinding = finding
		case finding.Ecosystem == "github-actions" && finding.Package == "actions/checkout":
			actionFinding = finding
		}
	}

	if goFinding.Ecosystem != "golang" {
		t.Fatalf("expected golang ecosystem, got %q", goFinding.Ecosystem)
	}
	if goFinding.FixedVersion != "v1.2.3" {
		t.Fatalf("expected minimal semver fix v1.2.3, got %q", goFinding.FixedVersion)
	}
	if len(goFinding.Locations) != 1 || goFinding.Locations[0] != filepath.Join(repo, "go.mod") {
		t.Fatalf("unexpected go finding locations: %#v", goFinding.Locations)
	}

	if actionFinding.Ecosystem != "github-actions" {
		t.Fatalf("expected github-actions ecosystem, got %q", actionFinding.Ecosystem)
	}
	if actionFinding.Package != "actions/checkout" {
		t.Fatalf("expected normalized github action package, got %q", actionFinding.Package)
	}
	if actionFinding.FixedVersion != "v4.2.2" {
		t.Fatalf("expected minimal semver github action fix v4.2.2, got %q", actionFinding.FixedVersion)
	}
	if len(actionFinding.Locations) != 1 || actionFinding.Locations[0] != filepath.Join(repo, ".github", "workflows", "ci.yml") {
		t.Fatalf("unexpected action finding locations: %#v", actionFinding.Locations)
	}

	if debFinding.Ecosystem != "deb" {
		t.Fatalf("expected deb ecosystem, got %q", debFinding.Ecosystem)
	}
	if debFinding.FixedVersion != "1.0.3" {
		t.Fatalf("expected lexicographically minimal deb fix 1.0.3, got %q", debFinding.FixedVersion)
	}
	if len(debFinding.Locations) != 1 || debFinding.Locations[0] != filepath.Join(repo, "Dockerfile") {
		t.Fatalf("unexpected deb finding locations: %#v", debFinding.Locations)
	}
}

func TestNormalizeGitHubActionPackageUsesPURLPath(t *testing.T) {
	got := normalizeGitHubActionPackage("checkout", "pkg:github/actions/checkout/.github/workflows/release.yml@v1.2.3")
	if got != "actions/checkout/.github/workflows/release.yml" {
		t.Fatalf("unexpected normalized package: %q", got)
	}
}

func TestParseRawReportBytesRejectsEmptyOutput(t *testing.T) {
	_, err := parseRawReportBytes([]byte("  \n\t"))
	if err == nil {
		t.Fatal("expected error for empty output")
	}
	if !strings.Contains(err.Error(), "empty JSON output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRawReportBytesRejectsTruncatedJSON(t *testing.T) {
	_, err := parseRawReportBytes([]byte("{\"matches\": ["))
	if err == nil {
		t.Fatal("expected error for truncated JSON")
	}
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeReportAppliesIgnoreRules(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	dockerfile := filepath.Join(repo, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM debian:12\n"), 0o644); err != nil {
		t.Fatalf("write dockerfile: %v", err)
	}

	raw := &rawReport{
		Matches: []rawMatch{
			{
				Artifact: rawArtifact{
					Name:      "openssl",
					Version:   "1.0.2",
					Type:      "deb",
					PURL:      "pkg:deb/debian/openssl@1.0.2",
					Locations: []rawLocation{{Path: "/Dockerfile"}},
				},
				Vulnerability: rawVulnerability{
					ID:  "CVE-2025-0001",
					Fix: rawFix{Versions: []string{"1.0.3"}},
				},
			},
			{
				Artifact: rawArtifact{
					Name:      "busybox",
					Version:   "1.1.0",
					Type:      "apk",
					PURL:      "pkg:apk/alpine/busybox@1.1.0",
					Locations: []rawLocation{{Path: "/Dockerfile"}},
				},
				Vulnerability: rawVulnerability{
					ID:  "CVE-2025-0002",
					Fix: rawFix{Versions: []string{"1.1.1"}},
				},
			},
		},
	}

	normalized := normalizeReport(repo, raw, ScanOptions{
		IgnoreRules: []IgnoreRule{
			{ID: "CVE-2025-0001", Path: "Dockerfile"},
		},
	})
	if len(normalized.Findings) != 1 {
		t.Fatalf("expected 1 remaining finding, got %#v", normalized.Findings)
	}
	if normalized.Findings[0].VulnerabilityID != "CVE-2025-0002" {
		t.Fatalf("unexpected remaining finding: %#v", normalized.Findings[0])
	}
	if normalized.IgnoredByPolicy != 1 {
		t.Fatalf("expected 1 ignored-by-policy finding, got %d", normalized.IgnoredByPolicy)
	}
}

func TestNormalizeReportAppliesSkipPaths(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "vendor"), 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "vendor", "go.mod"), []byte("module ignored\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	raw := &rawReport{
		Matches: []rawMatch{
			{
				Artifact: rawArtifact{
					Name:      "github.com/example/lib",
					Version:   "v1.0.0",
					Type:      "go-module",
					Language:  "go",
					PURL:      "pkg:golang/github.com/example/lib@v1.0.0",
					Locations: []rawLocation{{Path: "/vendor/go.mod"}},
				},
				Vulnerability: rawVulnerability{
					ID:  "GHSA-ignored",
					Fix: rawFix{Versions: []string{"v1.2.0"}},
				},
			},
		},
	}

	normalized := normalizeReport(repo, raw, ScanOptions{SkipPaths: []string{"vendor/**"}})
	if len(normalized.Findings) != 0 {
		t.Fatalf("expected findings to be skipped, got %#v", normalized.Findings)
	}
	if normalized.IgnoredByPolicy != 1 {
		t.Fatalf("expected ignored-by-policy count 1, got %d", normalized.IgnoredByPolicy)
	}
}

func TestDetectEcosystemAdditionalLanguages(t *testing.T) {
	tests := []struct {
		name     string
		artifact rawArtifact
		want     string
	}{
		{
			name: "npm via purl",
			artifact: rawArtifact{
				PURL: "pkg:npm/lodash@4.17.20",
			},
			want: "npm",
		},
		{
			name: "python via purl",
			artifact: rawArtifact{
				PURL: "pkg:pypi/flask@2.2.2",
			},
			want: "pypi",
		},
		{
			name: "maven via purl",
			artifact: rawArtifact{
				PURL: "pkg:maven/org.apache.commons/commons-lang3@3.11.0",
			},
			want: "maven",
		},
		{
			name: "cargo via purl",
			artifact: rawArtifact{
				PURL: "pkg:cargo/serde@1.0.0",
			},
			want: "cargo",
		},
		{
			name: "nuget via purl",
			artifact: rawArtifact{
				PURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
			},
			want: "nuget",
		},
		{
			name: "composer via purl",
			artifact: rawArtifact{
				PURL: "pkg:composer/symfony/http-foundation@6.3.0",
			},
			want: "composer",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := detectEcosystem(test.artifact)
			if got != test.want {
				t.Fatalf("detectEcosystem = %q, want %q", got, test.want)
			}
		})
	}
}
