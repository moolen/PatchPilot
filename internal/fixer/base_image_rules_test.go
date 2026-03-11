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
