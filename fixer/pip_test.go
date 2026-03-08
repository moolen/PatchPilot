package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/vuln"
)

func TestApplyPIPFixesWithOptions(t *testing.T) {
	repo := t.TempDir()
	requirementsPath := filepath.Join(repo, "requirements.txt")
	content := "flask==2.2.2\nrequests>=2.30.0\n"
	if err := os.WriteFile(requirementsPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	findings := []vuln.Finding{
		{
			Package:      "flask",
			FixedVersion: "2.3.3",
			Ecosystem:    "pypi",
			Locations:    []string{requirementsPath},
		},
		{
			Package:      "requests",
			FixedVersion: "2.31.0",
			Ecosystem:    "pypi",
			Locations:    []string{requirementsPath},
		},
	}

	patches, err := ApplyPIPFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyPIPFixesWithOptions: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}

	updated, err := os.ReadFile(requirementsPath)
	if err != nil {
		t.Fatalf("read requirements.txt: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, "flask>=2.3.3") {
		t.Fatalf("flask not updated:\n%s", text)
	}
	if !strings.Contains(text, "requests>=2.31.0") {
		t.Fatalf("requests not updated:\n%s", text)
	}
}
