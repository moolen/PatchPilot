package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/vuln"
)

func TestApplyMavenFixesWithOptions(t *testing.T) {
	repo := t.TempDir()
	pomPath := filepath.Join(repo, "pom.xml")
	content := `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.11.0</version>
    </dependency>
  </dependencies>
</project>
`
	if err := os.WriteFile(pomPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	findings := []vuln.Finding{
		{
			Package:      "org.apache.commons:commons-lang3",
			FixedVersion: "3.12.0",
			Ecosystem:    "maven",
			Locations:    []string{pomPath},
		},
	}

	patches, err := ApplyMavenFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyMavenFixesWithOptions: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}

	updated, err := os.ReadFile(pomPath)
	if err != nil {
		t.Fatalf("read pom.xml: %v", err)
	}
	if !strings.Contains(string(updated), "<version>3.12.0</version>") {
		t.Fatalf("version not updated:\n%s", string(updated))
	}
}
