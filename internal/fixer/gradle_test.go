package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestApplyGradleFixesWithOptions(t *testing.T) {
	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "build.gradle")
	content := `plugins {
  id 'java'
}

dependencies {
  implementation "org.apache.commons:commons-lang3:3.13.0"
  testImplementation 'junit:junit:4.12'
}
`
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}

	findings := []vuln.Finding{
		{Package: "org.apache.commons:commons-lang3", FixedVersion: "3.14.0", Ecosystem: "maven", Locations: []string{manifestPath}},
		{Package: "junit", FixedVersion: "4.13.2", Ecosystem: "maven", Locations: []string{manifestPath}},
	}

	patches, err := ApplyGradleFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyGradleFixesWithOptions: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %#v", patches)
	}

	updated, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read build.gradle: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, `"org.apache.commons:commons-lang3:3.14.0"`) {
		t.Fatalf("expected commons-lang3 bump, got:\n%s", text)
	}
	if !strings.Contains(text, `'junit:junit:4.13.2'`) {
		t.Fatalf("expected junit bump, got:\n%s", text)
	}
}
