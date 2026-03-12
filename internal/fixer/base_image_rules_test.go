package fixer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRuleDrivenImageTagSelectsHighestMatchingTag(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tags":["1.21.2-alpine","1.21.4-bullseye","1.21.5-alpine","1.22.0-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	rule := BaseImageRule{
		Image: "golang",
		TagSets: []BaseImageTagSet{
			{
				SemverRange: ">=1.21.1 <1.22.0",
				Allow:       []string{`^v?\d+\.\d+\.\d+-alpine$`},
			},
		},
	}

	got := resolveRuleDrivenImageTag(context.Background(), "golang:1.21.1-alpine", rule)
	if got != "1.21.5-alpine" {
		t.Fatalf("unexpected selected tag: %q", got)
	}
}

func TestResolveRuleDrivenImageTagHonorsDenyPatterns(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tags":["1.21.2-alpine","1.21.5-alpine-debug","1.21.4-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	rule := BaseImageRule{
		Image: "golang",
		TagSets: []BaseImageTagSet{
			{
				SemverRange: ">=1.21.1 <1.22.0",
				Allow:       []string{`^v?\d+\.\d+\.\d+-alpine(?:-debug)?$`},
			},
		},
		Deny: []string{`-debug$`},
	}

	got := resolveRuleDrivenImageTag(context.Background(), "golang:1.21.1-alpine", rule)
	if got != "1.21.4-alpine" {
		t.Fatalf("unexpected selected tag: %q", got)
	}
}

func TestExtractImageTagSemverRecognizesPrereleaseBeforeSuffix(t *testing.T) {
	got, ok := extractImageTagSemver("1.21.3-rc.1-alpine")
	if !ok {
		t.Fatal("expected prerelease tag to parse")
	}
	if got != "v1.21.3-rc.1" {
		t.Fatalf("unexpected parsed semver: %q", got)
	}
}

func TestPatchDockerfileBaseImageRulesApplyWithoutFindings(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	oldNow := registryNowFunc
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
		registryNowFunc = oldNow
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tags":["1.21.2-alpine","1.21.5-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	dockerfilePath := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM golang:1.21.1-alpine\nRUN echo hi\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	patches, changed, err := patchDockerfileWithOptions(context.Background(), dockerfilePath, dockerNeeds{}, DockerfileOptions{
		BaseImagePatching: true,
		BaseImageRules: []BaseImageRule{
			{
				Image: "golang",
				TagSets: []BaseImageTagSet{
					{
						SemverRange: ">=1.21.1 <1.22.0",
						Allow:       []string{`^v?\d+\.\d+\.\d+-alpine$`},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("patchDockerfileWithOptions returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected Dockerfile to change")
	}
	if len(patches) != 1 {
		t.Fatalf("unexpected patches: %#v", patches)
	}
	if patches[0].Package != "golang" || patches[0].To != "1.21.5-alpine" {
		t.Fatalf("unexpected patch: %#v", patches[0])
	}

	updated, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if string(updated) != "FROM golang:1.21.5-alpine\nRUN echo hi\n" {
		t.Fatalf("unexpected Dockerfile contents:\n%s", string(updated))
	}
}

func TestMatchingOCIPoliciesWildcardFirstMatchPrecedence(t *testing.T) {
	policies := []OCIImagePolicy{
		{Name: "broad", Source: "ghcr.io/kyverno/**"},
		{Name: "exact", Source: "ghcr.io/kyverno/kyverno"},
	}
	matches := matchingOCIPolicies("ghcr.io/kyverno/kyverno", policies)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].Name != "broad" || matches[1].Name != "exact" {
		t.Fatalf("unexpected match order: %#v", matches)
	}
}

func TestSelectLatestSemverTagByDefaultJumpsFromNonSemver(t *testing.T) {
	got := selectLatestSemverTagByDefault("latest", []string{"1.2.0", "2.0.1", "1.9.9-alpine"})
	if got != "2.0.1" {
		t.Fatalf("expected latest semver tag, got %q", got)
	}
}

func TestSelectLatestSemverTagByDefaultKeepsPrereleaseFamily(t *testing.T) {
	got := selectLatestSemverTagByDefault(
		"1.2.0-alpine3.20",
		[]string{"1.3.0-alpine3.20", "1.4.0-alpine3.21", "1.5.0"},
	)
	if got != "1.3.0-alpine3.20" {
		t.Fatalf("expected same prerelease family, got %q", got)
	}
}

func TestSelectLatestSemverTagByDefaultKeepsSuffixFamilyForMajorOnlyTag(t *testing.T) {
	got := selectLatestSemverTagByDefault(
		"25-alpine",
		[]string{"25.8.1-trixie-slim", "25.8.1-alpine", "25.7.0-alpine"},
	)
	if got != "25.8.1-alpine" {
		t.Fatalf("expected same suffix family for major-only tag, got %q", got)
	}
}

func TestSelectLatestSemverTagByDefaultSkipsDifferentSuffixFamilyWhenNoExactMatch(t *testing.T) {
	got := selectLatestSemverTagByDefault(
		"25-alpine",
		[]string{"25.8.1-trixie-slim", "25.8.1-bookworm"},
	)
	if got != "" {
		t.Fatalf("expected no candidate when suffix family differs, got %q", got)
	}
}

func TestSelectLatestSemverTagByPolicyRespectsPrereleaseAllow(t *testing.T) {
	policy := OCIImagePolicy{
		Name:   "prerelease-rc-only",
		Source: "ghcr.io/acme/demo",
		Tags: OCIImageTagPolicy{
			Semver: []OCIImageSemverPolicy{
				{
					Range:             []string{">=1.3.0-0 <2.0.0"},
					IncludePrerelease: true,
					PrereleaseAllow:   []string{`-rc\.`},
				},
			},
		},
	}
	got := selectLatestSemverTagByPolicy("1.2.0", []string{"1.3.0-rc.1", "1.3.0-beta.1", "1.2.9"}, policy)
	if got != "1.3.0-rc.1" {
		t.Fatalf("expected rc tag, got %q", got)
	}
}
