//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltBinaryBumpsGitHubActionTag(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)
	repo := newScenarioRepo(t, map[string]string{
		".patchpilot.yaml":       "version: 1\nfix:\n  updates:\n    - package-ecosystem: github-actions\n      enabled: true\n",
		".github/workflows/ci.yml": "name: ci\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.0.0\n",
	})

	result := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
	if result.exitCode != 0 {
		t.Fatalf("expected fix to succeed, got %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, result.stdout, result.stderr)
	}

	content := readFile(t, repo, ".github/workflows/ci.yml")
	if !strings.Contains(content, "actions/checkout@v4.2.2") {
		t.Fatalf("expected workflow to be bumped, got:\n%s", content)
	}

	summary := readSummary(t, repo)
	if summary.Before != 1 || summary.Fixed != 1 || summary.After != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestBuiltBinaryBumpsGitHubActionSHAPin(t *testing.T) {
	toolsDir := installFakeTools(t)
	installFakeGitForGitHubActions(t, toolsDir)

	env := integrationEnv(toolsDir)
	repo := newScenarioRepo(t, map[string]string{
		".patchpilot.yaml":       "version: 1\nfix:\n  updates:\n    - package-ecosystem: github-actions\n      enabled: true\n",
		".github/workflows/ci.yml": "name: ci\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
	})

	result := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
	if result.exitCode != 0 {
		t.Fatalf("expected fix to succeed, got %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, result.stdout, result.stderr)
	}

	content := readFile(t, repo, ".github/workflows/ci.yml")
	if !strings.Contains(content, "actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("expected workflow SHA pin to be bumped, got:\n%s", content)
	}

	summary := readSummary(t, repo)
	if summary.Before != 1 || summary.Fixed != 1 || summary.After != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func installFakeGitForGitHubActions(t *testing.T, toolsDir string) {
	t.Helper()
	script := `#!/bin/sh
set -eu
if [ "$#" -ge 3 ] && [ "$1" = "ls-remote" ] && [ "$2" = "--tags" ] && [ "$3" = "https://github.com/actions/checkout.git" ]; then
  printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v4.0.0\n'
  printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v4.2.2\n'
  exit 0
fi
exec /usr/bin/git "$@"
`
	path := filepath.Join(toolsDir, "git")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
}
