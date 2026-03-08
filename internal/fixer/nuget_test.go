package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestApplyNuGetFixesWithOptions(t *testing.T) {
	repo := t.TempDir()
	projectPath := filepath.Join(repo, "Demo.csproj")
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Version="8.0.0" Include="Microsoft.Extensions.Logging" />
    <PackageReference Include="Serilog">
      <Version>2.11.0</Version>
    </PackageReference>
  </ItemGroup>
</Project>
`
	if err := os.WriteFile(projectPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write csproj: %v", err)
	}

	findings := []vuln.Finding{
		{Package: "Newtonsoft.Json", FixedVersion: "13.0.3", Ecosystem: "nuget", Locations: []string{projectPath}},
		{Package: "Microsoft.Extensions.Logging", FixedVersion: "8.0.1", Ecosystem: "nuget", Locations: []string{projectPath}},
		{Package: "Serilog", FixedVersion: "2.12.0", Ecosystem: "nuget", Locations: []string{projectPath}},
	}

	patches, err := ApplyNuGetFixesWithOptions(context.Background(), repo, findings, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyNuGetFixesWithOptions: %v", err)
	}
	if len(patches) != 3 {
		t.Fatalf("expected 3 patches, got %#v", patches)
	}

	updated, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatalf("read csproj: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, `Include="Newtonsoft.Json" Version="13.0.3"`) {
		t.Fatalf("expected Newtonsoft.Json bump, got:\n%s", text)
	}
	if !strings.Contains(text, `Version="8.0.1" Include="Microsoft.Extensions.Logging"`) {
		t.Fatalf("expected Microsoft.Extensions.Logging bump, got:\n%s", text)
	}
	if !strings.Contains(text, `<Version>2.12.0</Version>`) {
		t.Fatalf("expected Serilog bump, got:\n%s", text)
	}
}
