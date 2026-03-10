package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestApplyCargoFixesWithOptions(t *testing.T) {
	orig := runCargoLockfileSyncFunc
	defer func() { runCargoLockfileSyncFunc = orig }()

	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "Cargo.toml")
	lockfilePath := filepath.Join(repo, "Cargo.lock")
	content := `[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0.190"
reqwest = { version = "0.11.20", features = ["json"] }
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}
	lockfile := `version = 3

[[package]]
name = "serde"
version = "1.0.190"

[[package]]
name = "reqwest"
version = "0.11.20"
`
	if err := os.WriteFile(lockfilePath, []byte(lockfile), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}
	runCargoLockfileSyncFunc = func(ctx context.Context, manifestPath string, requirements map[string]string) error {
		data, err := os.ReadFile(lockfilePath)
		if err != nil {
			return err
		}
		text := string(data)
		text = strings.ReplaceAll(text, `version = "1.0.190"`, `version = "1.0.197"`)
		text = strings.ReplaceAll(text, `version = "0.11.20"`, `version = "0.11.27"`)
		return os.WriteFile(lockfilePath, []byte(text), 0o644)
	}

	findings := []vuln.Finding{
		{Package: "serde", FixedVersion: "1.0.197", Ecosystem: "cargo", Locations: []string{manifestPath}},
		{Package: "reqwest", FixedVersion: "0.11.27", Ecosystem: "cargo", Locations: []string{manifestPath}},
	}

	patches, err := ApplyCargoFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyCargoFixesWithOptions: %v", err)
	}
	if len(patches) != 3 {
		t.Fatalf("expected 3 patches, got %#v", patches)
	}

	updated, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read Cargo.toml: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, `serde = "1.0.197"`) {
		t.Fatalf("expected serde bump, got:\n%s", text)
	}
	if !strings.Contains(text, `reqwest = { version = "0.11.27", features = ["json"] }`) {
		t.Fatalf("expected reqwest bump, got:\n%s", text)
	}

	updatedLock, err := os.ReadFile(lockfilePath)
	if err != nil {
		t.Fatalf("read Cargo.lock: %v", err)
	}
	lockText := string(updatedLock)
	if !strings.Contains(lockText, `version = "1.0.197"`) || !strings.Contains(lockText, `version = "0.11.27"`) {
		t.Fatalf("expected lockfile sync, got:\n%s", lockText)
	}
}
