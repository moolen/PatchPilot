package fixer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestMaybePatchFromUpdatesPatchTagWithSuffix(t *testing.T) {
	updated, patch, ok := maybePatchFrom(context.Background(),
		"FROM golang:1.21-alpine",
		"/tmp/Dockerfile",
		map[string]string{"golang": "1.21.1"},
		nil,
	)
	if !ok {
		t.Fatalf("expected FROM line to be patched")
	}
	if updated != "FROM golang:1.21.1-alpine" {
		t.Fatalf("unexpected updated line: %q", updated)
	}
	if patch.Manager != "dockerfile" || patch.Package != "golang" || patch.From != "1.21-alpine" || patch.To != "1.21.1-alpine" {
		t.Fatalf("unexpected patch: %+v", patch)
	}
}

func TestMaybePatchFromSkipsWhenAlreadyFixed(t *testing.T) {
	updated, patch, ok := maybePatchFrom(context.Background(),
		"FROM golang:1.21.2-alpine",
		"/tmp/Dockerfile",
		map[string]string{"golang": "1.21.1"},
		nil,
	)
	if ok {
		t.Fatalf("expected no patch, got updated=%q patch=%+v", updated, patch)
	}
}

func TestMaybePatchFromUpdatesDigestPinnedBaseImage(t *testing.T) {
	cacheDir := t.TempDir()
	oldCacheDir := registryCacheDir
	oldBaseURL := registryBaseURL
	defer func() {
		registryCacheDir = oldCacheDir
		registryBaseURL = oldBaseURL
	}()
	registryCacheDir = func() (string, error) { return cacheDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v2/library/golang/tags/list"):
			_, _ = fmt.Fprint(w, `{"tags":["1.21.1-alpine","1.21.3-alpine","1.22.0-alpine"]}`)
		case r.URL.Path == "/v2/library/golang/manifests/1.21.1-alpine":
			w.Header().Set("Docker-Content-Digest", "sha256:newdigest")
			if r.Method != http.MethodHead {
				_, _ = fmt.Fprint(w, `{"schemaVersion":2}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	updated, patch, ok := maybePatchFrom(context.Background(),
		"FROM golang:1.21-alpine@sha256:olddigest",
		"/tmp/Dockerfile",
		map[string]string{"golang": "1.21.1"},
		nil,
	)
	if !ok {
		t.Fatalf("expected FROM line to be patched")
	}
	if updated != "FROM golang:1.21.1-alpine@sha256:newdigest" {
		t.Fatalf("unexpected updated line: %q", updated)
	}
	if patch.Manager != "dockerfile" || patch.Package != "golang" || patch.From != "1.21-alpine@sha256:olddigest" || patch.To != "1.21.1-alpine@sha256:newdigest" {
		t.Fatalf("unexpected patch: %+v", patch)
	}
}

func TestCollectDockerRequirementsTracksPackageTargets(t *testing.T) {
	dockerfile := "/repo/Dockerfile"
	reqs := collectDockerRequirements([]string{dockerfile}, []vuln.Finding{
		{Package: "openssl", FixedVersion: "1.1.3", Ecosystem: "deb", Locations: []string{dockerfile}},
		{Package: "openssl", FixedVersion: "1.1.4", Ecosystem: "deb", Locations: []string{dockerfile}},
		{Package: "busybox", FixedVersion: "1.36.2", Ecosystem: "apk", Locations: []string{dockerfile}},
		{Package: "ubi9", FixedVersion: "9.4.1", Ecosystem: "golang", Locations: []string{dockerfile}},
	})
	need := reqs[dockerfile]
	if need.DebPackages["openssl"] != "1.1.4" {
		t.Fatalf("expected highest openssl fix, got %#v", need.DebPackages)
	}
	if need.APKPackages["busybox"] != "1.36.2" {
		t.Fatalf("unexpected apk packages: %#v", need.APKPackages)
	}
	if need.BasePackages["ubi9"] != "9.4.1" {
		t.Fatalf("unexpected base packages: %#v", need.BasePackages)
	}
}

func TestPatchDockerfileAddsPackageSpecificDebUpgrade(t *testing.T) {
	tempDir := t.TempDir()
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	content := "FROM debian:12\nRUN echo hello\n"
	if err := os.WriteFile(dockerfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	patches, changed, err := patchDockerfile(context.Background(), dockerfilePath, dockerNeeds{DebPackages: map[string]string{"openssl": "1.1.4", "libssl3": "3.0.2"}})
	if err != nil {
		t.Fatalf("patchDockerfile returned error: %v", err)
	}
	if !changed {
		t.Fatalf("expected Dockerfile to change")
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 package patches, got %#v", patches)
	}

	updated, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(updated)
	want := "RUN apt-get update && apt-get install --only-upgrade -y libssl3 openssl && rm -rf /var/lib/apt/lists/*"
	if !strings.Contains(text, want) {
		t.Fatalf("expected Dockerfile to contain %q, got:\n%s", want, text)
	}
}

func TestPatchDockerfileAddsPackageSpecificAPKUpgrade(t *testing.T) {
	tempDir := t.TempDir()
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	content := "FROM alpine:3.19\nRUN echo hello\n"
	if err := os.WriteFile(dockerfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	patches, changed, err := patchDockerfile(context.Background(), dockerfilePath, dockerNeeds{APKPackages: map[string]string{"busybox": "1.36.2"}})
	if err != nil {
		t.Fatalf("patchDockerfile returned error: %v", err)
	}
	if !changed {
		t.Fatalf("expected Dockerfile to change")
	}
	if len(patches) != 1 || patches[0].Package != "busybox" {
		t.Fatalf("unexpected patches: %#v", patches)
	}

	updated, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(updated), "RUN apk upgrade --no-cache busybox") {
		t.Fatalf("unexpected Dockerfile contents:\n%s", string(updated))
	}
}

func TestPatchDockerfileAddsDebUpgradeFallback(t *testing.T) {
	tempDir := t.TempDir()
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	content := "FROM debian:12\nRUN echo hello\n"
	if err := os.WriteFile(dockerfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	patches, changed, err := patchDockerfile(context.Background(), dockerfilePath, dockerNeeds{NeedsDeb: true})
	if err != nil {
		t.Fatalf("patchDockerfile returned error: %v", err)
	}
	if !changed {
		t.Fatalf("expected Dockerfile to change")
	}
	if len(patches) != 1 || patches[0].Package != "deb-packages" {
		t.Fatalf("unexpected patch: %#v", patches)
	}

	updated, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	want := "RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*"
	if !strings.Contains(string(updated), want) {
		t.Fatalf("expected Dockerfile to contain %q, got:\n%s", want, string(updated))
	}
}

func TestPatchDockerfileUpdatesFromUsingRegistryCache(t *testing.T) {
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
	registryNowFunc = func() time.Time { return time.Date(2026, 3, 7, 18, 0, 0, 0, time.UTC) }

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"tags":["1.21.1-alpine","1.21.3-alpine","1.22.0-alpine"]}`)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	need := dockerNeeds{BasePackages: map[string]string{"golang": "1.21.1"}}
	firstPath := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(firstPath, []byte("FROM golang:1.21-alpine\nRUN echo first\n"), 0o644); err != nil {
		t.Fatalf("write first Dockerfile: %v", err)
	}
	patches, changed, err := patchDockerfile(context.Background(), firstPath, need)
	if err != nil {
		t.Fatalf("first patchDockerfile error: %v", err)
	}
	if !changed || len(patches) != 1 || patches[0].To != "1.21.1-alpine" {
		t.Fatalf("unexpected first patch result: changed=%v patches=%#v", changed, patches)
	}
	firstUpdated, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("read first Dockerfile: %v", err)
	}
	if !strings.Contains(string(firstUpdated), "FROM golang:1.21.1-alpine") {
		t.Fatalf("unexpected first Dockerfile contents:\n%s", string(firstUpdated))
	}

	secondPath := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(secondPath, []byte("FROM golang:1.21-alpine\nRUN echo second\n"), 0o644); err != nil {
		t.Fatalf("write second Dockerfile: %v", err)
	}
	patches, changed, err = patchDockerfile(context.Background(), secondPath, need)
	if err != nil {
		t.Fatalf("second patchDockerfile error: %v", err)
	}
	if !changed || len(patches) != 1 || patches[0].To != "1.21.1-alpine" {
		t.Fatalf("unexpected second patch result: changed=%v patches=%#v", changed, patches)
	}
	if calls != 1 {
		t.Fatalf("expected 1 registry call with warm cache, got %d", calls)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 cache file, got %d", len(entries))
	}
}

func TestPatchDockerfileUsesStaleRegistryCacheOnFetchFailure(t *testing.T) {
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
		if calls == 1 {
			_, _ = fmt.Fprint(w, `{"tags":["1.21.1-alpine","1.21.3-alpine"]}`)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	registryBaseURL = func(host string) string { return server.URL }

	need := dockerNeeds{BasePackages: map[string]string{"golang": "1.21.1"}}
	firstPath := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(firstPath, []byte("FROM golang:1.21-alpine\nRUN echo first\n"), 0o644); err != nil {
		t.Fatalf("write first Dockerfile: %v", err)
	}
	if _, changed, err := patchDockerfile(context.Background(), firstPath, need); err != nil || !changed {
		t.Fatalf("expected initial patch to succeed, changed=%v err=%v", changed, err)
	}

	now = now.Add(registryCacheTTL + time.Minute)
	secondPath := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(secondPath, []byte("FROM golang:1.21-alpine\nRUN echo second\n"), 0o644); err != nil {
		t.Fatalf("write second Dockerfile: %v", err)
	}
	patches, changed, err := patchDockerfile(context.Background(), secondPath, need)
	if err != nil {
		t.Fatalf("expected stale cache fallback, got error: %v", err)
	}
	if !changed || len(patches) != 1 || patches[0].To != "1.21.1-alpine" {
		t.Fatalf("unexpected stale-cache patch result: changed=%v patches=%#v", changed, patches)
	}
	secondUpdated, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("read second Dockerfile: %v", err)
	}
	if !strings.Contains(string(secondUpdated), "FROM golang:1.21.1-alpine") {
		t.Fatalf("unexpected second Dockerfile contents:\n%s", string(secondUpdated))
	}
	if calls != 2 {
		t.Fatalf("expected 2 registry calls after ttl expiry and failed refresh, got %d", calls)
	}
}

func TestPatchDockerfileRespectsDisallowedBaseImagePolicy(t *testing.T) {
	tempDir := t.TempDir()
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM ubuntu:22.04\nRUN echo hi\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	_, _, err := patchDockerfileWithOptions(context.Background(), dockerfilePath, dockerNeeds{}, DockerfileOptions{
		BaseImagePatching:    true,
		OSPackagePatching:    true,
		DisallowedBaseImages: []string{"ubuntu:*"},
	})
	if err == nil {
		t.Fatal("expected policy violation error")
	}
	if !strings.Contains(err.Error(), "docker policy violation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchDockerfileRespectsAllowedBaseImagePolicy(t *testing.T) {
	tempDir := t.TempDir()
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM debian:12\nRUN echo hi\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	_, _, err := patchDockerfileWithOptions(context.Background(), dockerfilePath, dockerNeeds{}, DockerfileOptions{
		BaseImagePatching: true,
		OSPackagePatching: true,
		AllowedBaseImages: []string{"golang:*"},
	})
	if err == nil {
		t.Fatal("expected allow-list policy violation error")
	}
	if !strings.Contains(err.Error(), "does not match allowed patterns") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchDockerfileHonorsPatchingStrategy(t *testing.T) {
	tempDir := t.TempDir()
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	content := "FROM golang:1.21-alpine\nRUN echo hello\n"
	if err := os.WriteFile(dockerfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	patches, changed, err := patchDockerfileWithOptions(context.Background(), dockerfilePath, dockerNeeds{
		BasePackages: map[string]string{"golang": "1.21.1"},
		DebPackages:  map[string]string{"openssl": "1.1.4"},
	}, DockerfileOptions{
		BaseImagePatching: false,
		OSPackagePatching: false,
	})
	if err != nil {
		t.Fatalf("patchDockerfileWithOptions returned error: %v", err)
	}
	if changed {
		t.Fatalf("expected no changes when patching is disabled, got patches=%#v", patches)
	}
}
