package fixer

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseImageReferenceDockerHubLibrary(t *testing.T) {
	ref, ok := parseImageReference("golang:1.21-alpine")
	if !ok {
		t.Fatalf("expected image reference to parse")
	}
	if ref.Registry != "docker.io" || ref.Repository != "library/golang" || ref.Tag != "1.21-alpine" {
		t.Fatalf("unexpected ref: %+v", ref)
	}
}

func TestParseImageReferenceWithDigest(t *testing.T) {
	ref, ok := parseImageReference("golang:1.21-alpine@sha256:abc123")
	if !ok {
		t.Fatalf("expected image reference to parse")
	}
	if ref.Registry != "docker.io" || ref.Repository != "library/golang" || ref.Tag != "1.21-alpine" || ref.Digest != "sha256:abc123" {
		t.Fatalf("unexpected ref: %+v", ref)
	}
}

func TestSelectRegistryTagPrefersMinimalMatchingFamily(t *testing.T) {
	tag := selectRegistryTag("1.21-alpine", "v1.21.1", []string{"1.21.3-alpine", "1.21.1-alpine", "1.22.0-alpine", "1.21.4-bullseye"})
	if tag != "1.21.1-alpine" {
		t.Fatalf("unexpected selected tag: %q", tag)
	}
}

func TestListRegistryTagsUsesDiskCache(t *testing.T) {
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
	now := time.Date(2026, 3, 7, 18, 0, 0, 0, time.UTC)
	registryNowFunc = func() time.Time { return now }

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"tags":["1.21.1-alpine","1.21.2-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	ref := imageReference{Registry: "example.com", Repository: "library/golang", OriginalRepository: "golang", Tag: "1.21-alpine"}
	first, err := listRegistryTags(context.Background(), ref)
	if err != nil {
		t.Fatalf("listRegistryTags returned error: %v", err)
	}
	second, err := listRegistryTags(context.Background(), ref)
	if err != nil {
		t.Fatalf("listRegistryTags returned error on cached call: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 network call, got %d", calls)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("unexpected tags: %#v %#v", first, second)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 cache file, got %d (%v)", len(entries), err)
	}
}

func TestRegistryCacheExpiresAfterTTL(t *testing.T) {
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
	now := time.Date(2026, 3, 7, 18, 0, 0, 0, time.UTC)
	registryNowFunc = func() time.Time { return now }

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"tags":["1.21.1-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	ref := imageReference{Registry: "example.com", Repository: "library/golang", OriginalRepository: "golang", Tag: "1.21-alpine"}
	if _, err := listRegistryTags(context.Background(), ref); err != nil {
		t.Fatalf("first listRegistryTags error: %v", err)
	}
	now = now.Add(registryCacheTTL + time.Minute)
	if _, err := listRegistryTags(context.Background(), ref); err != nil {
		t.Fatalf("second listRegistryTags error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 network calls after ttl expiry, got %d", calls)
	}
}

func TestMaybePatchFromUsesRegistryTagResolution(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tags":["1.21.1-alpine","1.21.3-alpine","1.22.0-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	updated, patch, ok := maybePatchFrom(context.Background(), "FROM localhost:5000/golang:1.21-alpine", filepath.Join(cacheDir, "Dockerfile"), map[string]string{"golang": "1.21.1"}, nil)
	if !ok {
		t.Fatalf("expected patch")
	}
	if !strings.Contains(updated, "1.21.1-alpine") {
		t.Fatalf("unexpected updated line: %q", updated)
	}
	if patch.To != "1.21.1-alpine" {
		t.Fatalf("unexpected patch: %+v", patch)
	}
}

func TestDefaultRegistryCacheDirUsesEnvOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "registry-cache")
	t.Setenv("PATCHPILOT_REGISTRY_CACHE_DIR", want)

	got, err := defaultRegistryCacheDir()
	if err != nil {
		t.Fatalf("defaultRegistryCacheDir returned error: %v", err)
	}
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestConfigureRegistryOverridesRuntimeSettings(t *testing.T) {
	cacheDir := t.TempDir()
	restore := ConfigureRegistry(RegistryOptions{
		CacheDir:  cacheDir,
		CacheTTL:  time.Minute,
		AuthMode:  "bearer",
		AuthToken: "token-123",
	})
	defer restore()

	gotDir, err := defaultRegistryCacheDir()
	if err != nil {
		t.Fatalf("defaultRegistryCacheDir returned error: %v", err)
	}
	if gotDir != cacheDir {
		t.Fatalf("expected overridden cache dir %q, got %q", cacheDir, gotDir)
	}
	if registryCacheTTL != time.Minute {
		t.Fatalf("expected overridden cache ttl, got %s", registryCacheTTL)
	}
	if token := initialRegistryAuthorization(); token != "Bearer token-123" {
		t.Fatalf("expected bearer token from config, got %q", token)
	}
}

func TestFetchRegistryTagsSupportsBasicChallengeFromDockerAuthConfig(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	credential := base64.StdEncoding.EncodeToString([]byte("AWS:secret"))
	t.Setenv("DOCKER_AUTH_CONFIG", fmt.Sprintf(`{"auths":{"example.com":{"auth":"%s"}}}`, credential))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got == "" {
			w.Header().Set("Www-Authenticate", `Basic realm="https://example.com/"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if got != "Basic "+credential {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"tags":["1.2.3"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	ref := imageReference{
		Registry:           "example.com",
		Repository:         "team/service",
		OriginalRepository: "example.com/team/service",
		Tag:                "1.2.0",
	}
	tags, err := fetchRegistryTags(context.Background(), ref)
	if err != nil {
		t.Fatalf("fetchRegistryTags returned error: %v", err)
	}
	if len(tags) != 1 || tags[0] != "1.2.3" {
		t.Fatalf("unexpected tags: %#v", tags)
	}
}

func TestFetchRegistryTagsSupportsBasicChallengeFromDockerCredentialHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper script uses POSIX shell")
	}
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	helperDir := t.TempDir()
	helperPath := filepath.Join(helperDir, "docker-credential-test")
	script := `#!/bin/sh
if [ "$1" != "get" ]; then
  exit 1
fi
read server
if [ "$server" != "example.com" ] && [ "$server" != "https://example.com" ]; then
  exit 1
fi
printf '{"Username":"AWS","Secret":"secret"}'
`
	if err := os.WriteFile(helperPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write helper script: %v", err)
	}
	t.Setenv("PATH", helperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_AUTH_CONFIG", `{"credsStore":"test","auths":{}}`)

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("AWS:secret"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got == "" {
			w.Header().Set("Www-Authenticate", `Basic realm="https://example.com/"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if got != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"tags":["1.2.4"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	ref := imageReference{
		Registry:           "example.com",
		Repository:         "team/service",
		OriginalRepository: "example.com/team/service",
		Tag:                "1.2.0",
	}
	tags, err := fetchRegistryTags(context.Background(), ref)
	if err != nil {
		t.Fatalf("fetchRegistryTags returned error: %v", err)
	}
	if len(tags) != 1 || tags[0] != "1.2.4" {
		t.Fatalf("unexpected tags: %#v", tags)
	}
}
