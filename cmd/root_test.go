package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootHelpShowsFlags(t *testing.T) {
	command := NewRootCommand()
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute returned error for help: %v", err)
	}

	text := output.String()
	if !strings.Contains(text, "--dir") {
		t.Fatalf("expected --dir in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--repo-url") {
		t.Fatalf("expected --repo-url in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--policy") {
		t.Fatalf("expected --policy in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--policy-mode") {
		t.Fatalf("expected --policy-mode in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--json") {
		t.Fatalf("expected --json in help output, got:\n%s", text)
	}
}

func TestFixHelpShowsAgentFlags(t *testing.T) {
	command := NewRootCommand()
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"fix", "--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute returned error for fix help: %v", err)
	}

	text := output.String()
	if !strings.Contains(text, "--enable-agent") {
		t.Fatalf("expected --enable-agent in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--agent-command") {
		t.Fatalf("expected --agent-command in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--agent-max-attempts") {
		t.Fatalf("expected --agent-max-attempts in help output, got:\n%s", text)
	}
	if !strings.Contains(text, "--agent-artifact-dir") {
		t.Fatalf("expected --agent-artifact-dir in help output, got:\n%s", text)
	}
}

func TestResolveRepoRejectsMutuallyExclusiveFlags(t *testing.T) {
	command := &cobra.Command{}
	_, err := resolveRepo(command, &cliOptions{dir: "/tmp/repo", repoURL: "https://example.com/repo.git"}, nil)
	if err == nil {
		t.Fatal("expected mutually exclusive flags error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRepoUsesDirFlag(t *testing.T) {
	command := &cobra.Command{}
	repo, err := resolveRepo(command, &cliOptions{dir: "."}, []string{"ignored"})
	if err != nil {
		t.Fatalf("resolveRepo returned error: %v", err)
	}
	expected, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve abs path: %v", err)
	}
	if repo != expected {
		t.Fatalf("expected %q, got %q", expected, repo)
	}
}

func TestResolveRepoClonesURLToTemp(t *testing.T) {
	originalMakeTempDir := makeTempDir
	originalCloneRepoFunc := cloneRepoFunc
	t.Cleanup(func() {
		makeTempDir = originalMakeTempDir
		cloneRepoFunc = originalCloneRepoFunc
	})

	tempRoot := t.TempDir()
	makeTempDir = func(dir, pattern string) (string, error) {
		return tempRoot, nil
	}

	called := false
	cloneRepoFunc = func(ctx context.Context, writer io.Writer, repoURL, target string) error {
		called = true
		if repoURL != "https://example.com/repo.git" {
			t.Fatalf("unexpected repo URL %q", repoURL)
		}
		return os.MkdirAll(target, 0o755)
	}

	command := &cobra.Command{}
	var errOut strings.Builder
	command.SetErr(&errOut)

	repo, err := resolveRepo(command, &cliOptions{repoURL: "https://example.com/repo.git"}, nil)
	if err != nil {
		t.Fatalf("resolveRepo returned error: %v", err)
	}
	if !called {
		t.Fatal("expected cloneRepoFunc to be called")
	}
	expected := filepath.Join(tempRoot, "repo")
	if repo != expected {
		t.Fatalf("expected %q, got %q", expected, repo)
	}
	if !strings.Contains(errOut.String(), "Cloned https://example.com/repo.git to") {
		t.Fatalf("expected clone location message, got:\n%s", errOut.String())
	}
}

func TestSchemaCommandPrintsJSONSchema(t *testing.T) {
	command := NewRootCommand()
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"schema"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute returned error for schema: %v", err)
	}

	text := output.String()
	if !strings.Contains(text, "\"$schema\"") {
		t.Fatalf("expected JSON schema output, got:\n%s", text)
	}
	if !strings.Contains(text, "\"PatchPilot Policy\"") {
		t.Fatalf("expected schema title, got:\n%s", text)
	}
}

func TestNormalizeBoolFlagArgsRewritesEnableAgentFalse(t *testing.T) {
	args := []string{"fix", "--enable-agent", "false", "--dir", "/repo"}
	got := normalizeBoolFlagArgs(args)
	want := []string{"fix", "--enable-agent=false", "--dir", "/repo"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected normalized args: got %#v want %#v", got, want)
	}
}

func TestNormalizeBoolFlagArgsRewritesEnableAgentTrue(t *testing.T) {
	args := []string{"fix", "--enable-agent", "TRUE", "--dir", "/repo"}
	got := normalizeBoolFlagArgs(args)
	want := []string{"fix", "--enable-agent=true", "--dir", "/repo"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected normalized args: got %#v want %#v", got, want)
	}
}

func TestNormalizeBoolFlagArgsLeavesPositionalArgsAfterDoubleDash(t *testing.T) {
	args := []string{"fix", "--", "--enable-agent", "false"}
	got := normalizeBoolFlagArgs(args)
	if !slices.Equal(got, args) {
		t.Fatalf("unexpected normalized args after --: got %#v want %#v", got, args)
	}
}
