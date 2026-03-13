package fixer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveLatestSemverImageTagSkipsPrereleaseAndSuffixedTags(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tags":["latest","1.2.4-rc.1","1.2.5-alpine","1.2.6","v1.2.7","1.2.8-beta.1"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	got, err := ResolveLatestSemverImageTag(context.Background(), "example.com/team/service")
	if err != nil {
		t.Fatalf("ResolveLatestSemverImageTag returned error: %v", err)
	}
	if got != "v1.2.7" {
		t.Fatalf("unexpected selected tag: %q", got)
	}
}

func TestResolveLatestSemverImageTagRejectsPrereleaseOnlyRepositories(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tags":["1.2.4-rc.1","1.2.5-alpine","v1.2.6-beta.1"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	if _, err := ResolveLatestSemverImageTag(context.Background(), "example.com/team/service"); err == nil {
		t.Fatal("expected error when no stable semver tags are available")
	}
}
