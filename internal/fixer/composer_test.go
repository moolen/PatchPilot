package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestApplyComposerFixesWithOptions(t *testing.T) {
	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "composer.json")
	content := `{
  "name": "demo/app",
  "require": {
    "symfony/http-foundation": "^6.3.0"
  },
  "require-dev": {
    "phpunit/phpunit": "10.3.1"
  }
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write composer.json: %v", err)
	}

	findings := []vuln.Finding{
		{Package: "symfony/http-foundation", FixedVersion: "6.4.6", Ecosystem: "composer", Locations: []string{manifestPath}},
		{Package: "phpunit/phpunit", FixedVersion: "10.5.15", Ecosystem: "composer", Locations: []string{manifestPath}},
	}

	patches, err := ApplyComposerFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyComposerFixesWithOptions: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %#v", patches)
	}

	updated, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read composer.json: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, `"symfony/http-foundation": "^6.4.6"`) {
		t.Fatalf("expected symfony bump, got:\n%s", text)
	}
	if !strings.Contains(text, `"phpunit/phpunit": "10.5.15"`) {
		t.Fatalf("expected phpunit bump, got:\n%s", text)
	}
}
