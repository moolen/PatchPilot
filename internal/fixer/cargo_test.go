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
	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "Cargo.toml")
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

	findings := []vuln.Finding{
		{Package: "serde", FixedVersion: "1.0.197", Ecosystem: "cargo", Locations: []string{manifestPath}},
		{Package: "reqwest", FixedVersion: "0.11.27", Ecosystem: "cargo", Locations: []string{manifestPath}},
	}

	patches, err := ApplyCargoFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyCargoFixesWithOptions: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %#v", patches)
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
}
