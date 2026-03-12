package goenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandEnvUsesRepoStateDir(t *testing.T) {
	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "nested", "module")
	stateDir := filepath.Join(repo, ".patchpilot")
	for _, dir := range []string{moduleDir, stateDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	env, err := CommandEnv(moduleDir)
	if err != nil {
		t.Fatalf("CommandEnv returned error: %v", err)
	}

	lookup := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			lookup[key] = value
		}
	}

	for _, key := range []string{"GOMODCACHE", "GOPATH", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		value := lookup[key]
		if !strings.HasPrefix(value, stateDir) {
			t.Fatalf("expected %s to live under %s, got %q", key, stateDir, value)
		}
		if info, err := os.Stat(value); err != nil || !info.IsDir() {
			t.Fatalf("expected %s directory to exist at %q: %v", key, value, err)
		}
	}
}

func TestCommandEnvAddsModCacheWritableFlag(t *testing.T) {
	moduleDir := t.TempDir()
	env, err := CommandEnv(moduleDir)
	if err != nil {
		t.Fatalf("CommandEnv returned error: %v", err)
	}
	lookup := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			lookup[key] = value
		}
	}
	if !strings.Contains(lookup["GOFLAGS"], "-modcacherw") {
		t.Fatalf("expected GOFLAGS to include -modcacherw, got %q", lookup["GOFLAGS"])
	}
}

func TestStateDirFallsBackToGitRepoRoot(t *testing.T) {
	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "src", "foo-test")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("mkdir module dir: %v", err)
	}

	stateDir, err := StateDir(moduleDir)
	if err != nil {
		t.Fatalf("StateDir returned error: %v", err)
	}

	want := filepath.Join(repo, ".patchpilot")
	if stateDir != want {
		t.Fatalf("StateDir = %q, want %q", stateDir, want)
	}
	if info, err := os.Stat(stateDir); err != nil || !info.IsDir() {
		t.Fatalf("expected state dir at %q: %v", stateDir, err)
	}
}
