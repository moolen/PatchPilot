package fixer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestChooseTargetGoVersionPrefersLatestPatchOnSameSupportedLine(t *testing.T) {
	target, ok := chooseTargetGoVersion(goPatchVersion{Major: 1, Minor: 25, Patch: 2}, map[string]goPatchVersion{
		"1.25": {Major: 1, Minor: 25, Patch: 8},
		"1.26": {Major: 1, Minor: 26, Patch: 1},
	})
	if !ok {
		t.Fatal("expected a target version")
	}
	if target != (goPatchVersion{Major: 1, Minor: 25, Patch: 8}) {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestChooseTargetGoVersionMovesToOldestSupportedWhenCurrentLineUnsupported(t *testing.T) {
	target, ok := chooseTargetGoVersion(goPatchVersion{Major: 1, Minor: 24, Patch: 13}, map[string]goPatchVersion{
		"1.25": {Major: 1, Minor: 25, Patch: 8},
		"1.26": {Major: 1, Minor: 26, Patch: 1},
	})
	if !ok {
		t.Fatal("expected a target version")
	}
	if target != (goPatchVersion{Major: 1, Minor: 25, Patch: 8}) {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestApplyGoRuntimeFixesUpdatesGoDirective(t *testing.T) {
	origFetch := fetchSupportedGoPatchVersionsFunc
	origTidy := runGoModTidyFunc
	origVendor := runGoModVendorFunc
	defer func() {
		fetchSupportedGoPatchVersionsFunc = origFetch
		runGoModTidyFunc = origTidy
		runGoModVendorFunc = origVendor
	}()

	fetchSupportedGoPatchVersionsFunc = func(ctx context.Context) (map[string]goPatchVersion, error) {
		return map[string]goPatchVersion{
			"1.25": {Major: 1, Minor: 25, Patch: 8},
			"1.26": {Major: 1, Minor: 26, Patch: 1},
		}, nil
	}
	tidyCalls := 0
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		tidyCalls++
		return nil
	}
	runGoModVendorFunc = func(ctx context.Context, dir string) error {
		return nil
	}

	repo := t.TempDir()
	goModPath := filepath.Join(repo, "go.mod")
	content := "module example.com/test\n\ngo 1.24.0\n"
	if err := os.WriteFile(goModPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, err := ApplyGoRuntimeFixes(context.Background(), repo)
	if err != nil {
		t.Fatalf("ApplyGoRuntimeFixes returned error: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected one patch, got %#v", patches)
	}
	if patches[0].Manager != "goruntime" || patches[0].From != "1.24.0" || patches[0].To != "1.25.8" {
		t.Fatalf("unexpected patch: %+v", patches[0])
	}
	if tidyCalls != 1 {
		t.Fatalf("expected one tidy call, got %d", tidyCalls)
	}

	updated, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if string(updated) != "module example.com/test\n\ngo 1.25.8\n" {
		t.Fatalf("unexpected go.mod contents:\n%s", string(updated))
	}
}

func TestApplyGoRuntimeFixesSkipsWithoutStdlibFinding(t *testing.T) {
	origFetch := fetchSupportedGoPatchVersionsFunc
	defer func() { fetchSupportedGoPatchVersionsFunc = origFetch }()

	called := false
	fetchSupportedGoPatchVersionsFunc = func(ctx context.Context) (map[string]goPatchVersion, error) {
		called = true
		return map[string]goPatchVersion{"1.25": {Major: 1, Minor: 25, Patch: 8}}, nil
	}

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/test\n\ngo 1.24.0\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, err := ApplyGoRuntimeFixesWithOptions(context.Background(), repo, []vuln.Finding{{Package: "github.com/example/lib", Ecosystem: "golang"}}, GoRuntimeOptions{Mode: GoRuntimeModeMinimum})
	if err != nil {
		t.Fatalf("ApplyGoRuntimeFixesWithOptions returned error: %v", err)
	}
	if len(patches) != 0 {
		t.Fatalf("expected no patches, got %#v", patches)
	}
	if called {
		t.Fatal("expected release fetch to be skipped")
	}
}

func TestApplyGoRuntimeFixesToolchainModeAddsToolchainDirective(t *testing.T) {
	origFetch := fetchSupportedGoPatchVersionsFunc
	origTidy := runGoModTidyFunc
	origVendor := runGoModVendorFunc
	defer func() {
		fetchSupportedGoPatchVersionsFunc = origFetch
		runGoModTidyFunc = origTidy
		runGoModVendorFunc = origVendor
	}()

	fetchSupportedGoPatchVersionsFunc = func(ctx context.Context) (map[string]goPatchVersion, error) {
		return map[string]goPatchVersion{"1.26": {Major: 1, Minor: 26, Patch: 1}}, nil
	}
	runGoModTidyFunc = func(ctx context.Context, dir string) error { return nil }
	runGoModVendorFunc = func(ctx context.Context, dir string) error { return nil }

	repo := t.TempDir()
	goModPath := filepath.Join(repo, "go.mod")
	if err := os.WriteFile(goModPath, []byte("module example.com/test\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, err := ApplyGoRuntimeFixesWithOptions(context.Background(), repo, []vuln.Finding{{Package: "stdlib", Ecosystem: "golang"}}, GoRuntimeOptions{Mode: GoRuntimeModeToolchain})
	if err != nil {
		t.Fatalf("ApplyGoRuntimeFixesWithOptions returned error: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected one patch, got %#v", patches)
	}
	if patches[0].Package != "go-toolchain" || patches[0].To != "go1.26.1" {
		t.Fatalf("unexpected patch: %+v", patches[0])
	}
	updated, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if string(updated) != "module example.com/test\n\ngo 1.26\n\ntoolchain go1.26.1\n" {
		t.Fatalf("unexpected go.mod contents:\n%s", string(updated))
	}
}

func TestApplyGoRuntimeFixesMinimumModeRemovesRedundantToolchain(t *testing.T) {
	origFetch := fetchSupportedGoPatchVersionsFunc
	origTidy := runGoModTidyFunc
	origVendor := runGoModVendorFunc
	defer func() {
		fetchSupportedGoPatchVersionsFunc = origFetch
		runGoModTidyFunc = origTidy
		runGoModVendorFunc = origVendor
	}()

	fetchSupportedGoPatchVersionsFunc = func(ctx context.Context) (map[string]goPatchVersion, error) {
		return map[string]goPatchVersion{"1.26": {Major: 1, Minor: 26, Patch: 1}}, nil
	}
	runGoModTidyFunc = func(ctx context.Context, dir string) error { return nil }
	runGoModVendorFunc = func(ctx context.Context, dir string) error { return nil }

	repo := t.TempDir()
	goModPath := filepath.Join(repo, "go.mod")
	if err := os.WriteFile(goModPath, []byte("module example.com/test\n\ngo 1.26\n\ntoolchain go1.26.1\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, err := ApplyGoRuntimeFixesWithOptions(context.Background(), repo, []vuln.Finding{{Package: "stdlib", Ecosystem: "golang"}}, GoRuntimeOptions{Mode: GoRuntimeModeMinimum})
	if err != nil {
		t.Fatalf("ApplyGoRuntimeFixesWithOptions returned error: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected two patches, got %#v", patches)
	}
	updated, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if string(updated) != "module example.com/test\n\ngo 1.26.1\n" {
		t.Fatalf("unexpected go.mod contents:\n%s", string(updated))
	}
}

func TestFetchSupportedGoPatchVersions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"version": "go1.26.1", "stable": true},
			{"version": "go1.26.0", "stable": true},
			{"version": "go1.25.8", "stable": true},
			{"version": "go1.25.7", "stable": true},
			{"version": "go1.27rc1", "stable": false},
		})
	}))
	defer server.Close()

	origClient := goReleaseHTTPClient
	origURL := goReleaseAPIURL
	defer func() { goReleaseHTTPClient = origClient }()
	defer func() { goReleaseAPIURL = origURL }()
	goReleaseHTTPClient = server.Client()
	goReleaseAPIURL = server.URL

	supported, err := fetchSupportedGoPatchVersions(context.Background())
	if err != nil {
		t.Fatalf("fetchSupportedGoPatchVersions returned error: %v", err)
	}
	if got := supported["1.26"]; got != (goPatchVersion{Major: 1, Minor: 26, Patch: 1}) {
		t.Fatalf("unexpected 1.26 target: %+v", got)
	}
	if got := supported["1.25"]; got != (goPatchVersion{Major: 1, Minor: 25, Patch: 8}) {
		t.Fatalf("unexpected 1.25 target: %+v", got)
	}
	if _, ok := supported["1.27"]; ok {
		t.Fatalf("did not expect unstable line in supported map: %#v", supported)
	}
}

func TestApplyGoRuntimeFixesDisabledByEnv(t *testing.T) {
	originalFetch := fetchSupportedGoPatchVersionsFunc
	defer func() {
		fetchSupportedGoPatchVersionsFunc = originalFetch
	}()

	t.Setenv("PATCHPILOT_DISABLE_GO_RUNTIME_BUMPS", "true")

	called := false
	fetchSupportedGoPatchVersionsFunc = func(ctx context.Context) (map[string]goPatchVersion, error) {
		called = true
		return map[string]goPatchVersion{
			"1.25": {Major: 1, Minor: 25, Patch: 8},
		}, nil
	}

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/test\n\ngo 1.24.0\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, err := ApplyGoRuntimeFixes(context.Background(), repo)
	if err != nil {
		t.Fatalf("ApplyGoRuntimeFixes returned error: %v", err)
	}
	if len(patches) != 0 {
		t.Fatalf("expected no patches when runtime bumps are disabled, got %#v", patches)
	}
	if called {
		t.Fatal("expected release fetch to be skipped")
	}
}
