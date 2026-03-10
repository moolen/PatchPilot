package fixer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestApplyNPMFixesWithOptions(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()
	runNPMLockfileSyncFunc = func(ctx context.Context, dir string) error {
		lockfilePath := filepath.Join(dir, "package-lock.json")
		content := `{"lockfileVersion": 3, "synced": true}` + "\n"
		return os.WriteFile(lockfilePath, []byte(content), 0o644)
	}

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.20"
  },
  "devDependencies": {
    "jest": "29.6.0"
  }
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(`{"lockfileVersion": 3}`+"\n"), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	findings := []vuln.Finding{
		{
			Package:      "lodash",
			FixedVersion: "4.17.21",
			Ecosystem:    "npm",
			Locations:    []string{manifestPath},
		},
		{
			Package:      "jest",
			FixedVersion: "29.7.0",
			Ecosystem:    "npm",
			Locations:    []string{filepath.Join(repo, "package-lock.json")},
		},
	}

	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyNPMFixesWithOptions: %v", err)
	}
	if len(patches) != 3 {
		t.Fatalf("expected 3 patches, got %d (%#v)", len(patches), patches)
	}

	updated, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, `"lodash": "^4.17.21"`) {
		t.Fatalf("lodash not updated:\n%s", text)
	}
	if !strings.Contains(text, `"jest": "29.7.0"`) {
		t.Fatalf("jest not updated:\n%s", text)
	}
	lockfile, err := os.ReadFile(filepath.Join(repo, "package-lock.json"))
	if err != nil {
		t.Fatalf("read package-lock.json: %v", err)
	}
	if !strings.Contains(string(lockfile), `"synced": true`) {
		t.Fatalf("expected lockfile sync marker, got:\n%s", string(lockfile))
	}
}

func TestApplyNPMFixesWithOptionsDoesNotSyncMissingLockfiles(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()
	called := false
	runNPMLockfileSyncFunc = func(ctx context.Context, dir string) error {
		called = true
		return nil
	}

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	findings := []vuln.Finding{{
		Package:      "lodash",
		FixedVersion: "4.17.21",
		Ecosystem:    "npm",
		Locations:    []string{manifestPath},
	}}

	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyNPMFixesWithOptions: %v", err)
	}
	if called {
		t.Fatalf("expected lockfile sync to be skipped when no lockfiles exist")
	}
	if len(patches) != 1 {
		t.Fatalf("expected only manifest patch, got %#v", patches)
	}
}

func TestApplyNPMFixesWithOptionsFailsWhenLockfileSyncFails(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()
	runNPMLockfileSyncFunc = func(ctx context.Context, dir string) error {
		return errors.New("sync failed")
	}

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	findings := []vuln.Finding{{
		Package:      "lodash",
		FixedVersion: "4.17.21",
		Ecosystem:    "npm",
		Locations:    []string{manifestPath},
	}}

	_, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err == nil || !strings.Contains(err.Error(), "sync npm lockfiles") {
		t.Fatalf("expected lockfile sync error, got %v", err)
	}
}

func TestApplyNPMFixesWithOptionsUnknownLocationFallsBackToOverridesAndPNPMLock(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lockPath := filepath.Join(repo, "pnpm-lock.yaml")
	if err := os.WriteFile(lockPath, []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	called := false
	runPNPMLockfileSyncFunc = func(ctx context.Context, dir string) error {
		called = true
		return os.WriteFile(lockPath, []byte("lockfileVersion: '9.0'\nsynced: true\n"), 0o644)
	}

	findings := []vuln.Finding{{
		Package:      "minimatch",
		FixedVersion: "3.1.4",
		Ecosystem:    "npm",
		Locations:    nil,
	}}
	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyNPMFixesWithOptions: %v", err)
	}
	if !called {
		t.Fatalf("expected pnpm lockfile sync to run")
	}
	if !containsManager(patches, npmOverridePatch) {
		t.Fatalf("expected npm override patch, got %#v", patches)
	}
	if !containsManager(patches, pnpmOverridePatch) {
		t.Fatalf("expected pnpm override patch, got %#v", patches)
	}
	if !containsManager(patches, pnpmLockfilePatch) {
		t.Fatalf("expected pnpm lockfile patch, got %#v", patches)
	}

	updated, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, `"overrides": {`) || !strings.Contains(text, `"minimatch": "3.1.4"`) {
		t.Fatalf("expected top-level overrides to be written, got:\n%s", text)
	}
	if !strings.Contains(text, `"pnpm": {`) || !strings.Contains(text, `"overrides": {`) {
		t.Fatalf("expected pnpm overrides to be written, got:\n%s", text)
	}
}

func TestApplyNPMFixesWithOptionsPNPMFallbackDirectPatch(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lockPath := filepath.Join(repo, "pnpm-lock.yaml")
	lockContent := `lockfileVersion: '9.0'
packages:
  minimatch@3.1.2:
    resolution: {integrity: sha512-demo}
snapshots:
  filelist@1.0.4:
    dependencies:
      minimatch: 3.1.2
`
	if err := os.WriteFile(lockPath, []byte(lockContent), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	runPNPMLockfileSyncFunc = func(ctx context.Context, dir string) error {
		return errors.New("pnpm failed")
	}

	findings := []vuln.Finding{{
		Package:      "minimatch",
		FixedVersion: "3.1.4",
		Ecosystem:    "npm",
		Locations:    nil,
	}}
	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyNPMFixesWithOptions: %v", err)
	}
	if !containsManager(patches, pnpmDirectPatch) {
		t.Fatalf("expected pnpm direct fallback patch, got %#v", patches)
	}

	updated, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read pnpm-lock.yaml: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, "minimatch@3.1.4:") {
		t.Fatalf("expected header version bump, got:\n%s", text)
	}
	if !strings.Contains(text, "minimatch: 3.1.4") {
		t.Fatalf("expected dependency reference bump, got:\n%s", text)
	}
}

func TestApplyNPMFixesWithOptionsYarnLockSync(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lockPath := filepath.Join(repo, "yarn.lock")
	if err := os.WriteFile(lockPath, []byte("# yarn lock\n"), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	runYarnLockfileSyncFunc = func(ctx context.Context, dir string) error {
		return os.WriteFile(lockPath, []byte("# yarn lock\nsynced true\n"), 0o644)
	}

	findings := []vuln.Finding{{
		Package:      "js-yaml",
		FixedVersion: "3.14.2",
		Ecosystem:    "npm",
		Locations:    nil,
	}}
	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyNPMFixesWithOptions: %v", err)
	}
	if !containsManager(patches, yarnResolutionPatch) {
		t.Fatalf("expected yarn resolution patch, got %#v", patches)
	}
	if !containsManager(patches, yarnLockfilePatch) {
		t.Fatalf("expected yarn lockfile patch, got %#v", patches)
	}

	updated, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	if !strings.Contains(string(updated), `"resolutions": {`) {
		t.Fatalf("expected resolutions block in package.json, got:\n%s", string(updated))
	}
}

func TestApplyNPMFixesWithOptionsYarnLockSyncFailureIsNonFatal(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lockPath := filepath.Join(repo, "yarn.lock")
	if err := os.WriteFile(lockPath, []byte("# yarn lock\n"), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	runYarnLockfileSyncFunc = func(ctx context.Context, dir string) error {
		return errors.New("simulated yarn failure")
	}

	findings := []vuln.Finding{{
		Package:      "js-yaml",
		FixedVersion: "3.14.2",
		Ecosystem:    "npm",
		Locations:    nil,
	}}
	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("expected yarn sync failure to be non-fatal, got %v", err)
	}
	if !containsManager(patches, yarnResolutionPatch) {
		t.Fatalf("expected yarn resolution patch despite sync failure, got %#v", patches)
	}
}

func TestApplyNPMFixesWithOptionsUntrustedRepoSkipsYarnLockSync(t *testing.T) {
	restore := stubNpmSyncRunners()
	defer restore()

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "package.json")
	content := `{
  "name": "demo",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lockPath := filepath.Join(repo, "yarn.lock")
	if err := os.WriteFile(lockPath, []byte("# yarn lock\n"), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	called := false
	runYarnLockfileSyncFunc = func(ctx context.Context, dir string) error {
		called = true
		return os.WriteFile(lockPath, []byte("# yarn lock\nsynced true\n"), 0o644)
	}

	findings := []vuln.Finding{{
		Package:      "js-yaml",
		FixedVersion: "3.14.2",
		Ecosystem:    "npm",
		Locations:    nil,
	}}
	patches, err := ApplyNPMFixesWithOptions(context.Background(), repo, findings, FileOptions{UntrustedRepo: true})
	if err != nil {
		t.Fatalf("ApplyNPMFixesWithOptions: %v", err)
	}
	if called {
		t.Fatal("expected yarn lockfile sync to be skipped in untrusted repo mode")
	}
	if !containsManager(patches, yarnResolutionPatch) {
		t.Fatalf("expected yarn resolution patch, got %#v", patches)
	}
	if containsManager(patches, yarnLockfilePatch) {
		t.Fatalf("did not expect yarn lockfile patch when sync is skipped, got %#v", patches)
	}
}

func TestCollectNPMRequirementsFallsBackToRootManifestForUnknownLocation(t *testing.T) {
	repo := t.TempDir()
	rootManifest := filepath.Join(repo, "package.json")
	if err := os.WriteFile(rootManifest, []byte(`{"name":"root"}`), 0o644); err != nil {
		t.Fatalf("write root package.json: %v", err)
	}
	subDir := filepath.Join(repo, "packages", "api")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	subManifest := filepath.Join(subDir, "package.json")
	if err := os.WriteFile(subManifest, []byte(`{"name":"api"}`), 0o644); err != nil {
		t.Fatalf("write sub package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, pnpmLockFile), []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	requirements := collectNPMRequirements(repo, []string{rootManifest, subManifest}, []vuln.Finding{{
		Package:      "minimatch",
		FixedVersion: "3.1.4",
		Ecosystem:    "npm",
		Locations:    nil,
	}})
	if len(requirements) != 1 {
		t.Fatalf("expected one fallback target, got %#v", requirements)
	}
	if requirements[rootManifest]["minimatch"] != "3.1.4" {
		t.Fatalf("unexpected requirements map: %#v", requirements)
	}
}

func TestDetectYarnPathFromConfig(t *testing.T) {
	repo := t.TempDir()
	if got := detectYarnPathFromConfig(repo); got != "" {
		t.Fatalf("expected empty yarn path, got %q", got)
	}

	if err := os.MkdirAll(filepath.Join(repo, ".yarn", "releases"), 0o755); err != nil {
		t.Fatalf("mkdir releases: %v", err)
	}
	yarnCJS := filepath.Join(repo, ".yarn", "releases", "yarn-4.9.4.cjs")
	if err := os.WriteFile(yarnCJS, []byte("// stub\n"), 0o644); err != nil {
		t.Fatalf("write yarn cjs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".yarnrc.yml"), []byte("yarnPath: .yarn/releases/yarn-4.9.4.cjs\n"), 0o644); err != nil {
		t.Fatalf("write .yarnrc.yml: %v", err)
	}

	got := detectYarnPathFromConfig(repo)
	if got != yarnCJS {
		t.Fatalf("unexpected yarn path: got %q want %q", got, yarnCJS)
	}
}

func containsManager(patches []Patch, manager string) bool {
	for _, patch := range patches {
		if patch.Manager == manager {
			return true
		}
	}
	return false
}

func stubNpmSyncRunners() func() {
	origNPM := runNPMLockfileSyncFunc
	origPNPM := runPNPMLockfileSyncFunc
	origYarn := runYarnLockfileSyncFunc
	runNPMLockfileSyncFunc = func(ctx context.Context, dir string) error { return nil }
	runPNPMLockfileSyncFunc = func(ctx context.Context, dir string) error { return nil }
	runYarnLockfileSyncFunc = func(ctx context.Context, dir string) error { return nil }
	return func() {
		runNPMLockfileSyncFunc = origNPM
		runPNPMLockfileSyncFunc = origPNPM
		runYarnLockfileSyncFunc = origYarn
	}
}
