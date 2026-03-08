package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestApplyNPMFixesWithOptions(t *testing.T) {
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
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
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
}
