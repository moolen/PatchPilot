package githubapp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCommandScrubsSensitiveHostEnv(t *testing.T) {
	t.Setenv("PP_PRIVATE_KEY_PEM", "super-secret-private-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("GOPRIVATE", "example.com/private")

	stdout, stderr, err := runCommand(
		context.Background(),
		t.TempDir(),
		map[string]string{"PATCHPILOT_TEST_EXTRA": "extra-ok"},
		"sh",
		"-c",
		`printf '%s|%s|%s|%s' "${PP_PRIVATE_KEY_PEM:-}" "${AWS_SECRET_ACCESS_KEY:-}" "${GOPRIVATE:-}" "${PATCHPILOT_TEST_EXTRA:-}"`,
	)
	if err != nil {
		t.Fatalf("runCommand returned error: %v\nstderr=%s", err, stderr)
	}

	parts := strings.Split(stdout, "|")
	if len(parts) != 4 {
		t.Fatalf("unexpected output %q", stdout)
	}
	if parts[0] != "" {
		t.Fatalf("expected PP_PRIVATE_KEY_PEM to be scrubbed, got %q", parts[0])
	}
	if parts[1] != "" {
		t.Fatalf("expected AWS_SECRET_ACCESS_KEY to be scrubbed, got %q", parts[1])
	}
	if parts[2] != "example.com/private" {
		t.Fatalf("expected GOPRIVATE to survive allowlist, got %q", parts[2])
	}
	if parts[3] != "extra-ok" {
		t.Fatalf("expected extra env override to be preserved, got %q", parts[3])
	}
}

func TestRunCommandWithInputPassesStdin(t *testing.T) {
	stdout, stderr, err := runCommandWithInput(
		context.Background(),
		t.TempDir(),
		nil,
		"stdin payload",
		"sh",
		"-c",
		"cat",
	)
	if err != nil {
		t.Fatalf("runCommandWithInput returned error: %v\nstderr=%s", err, stderr)
	}
	if stdout != "stdin payload" {
		t.Fatalf("unexpected stdout %q", stdout)
	}
}

func TestFilterMeaningfulPathsIgnoresNestedPatchpilotArtifacts(t *testing.T) {
	input := []string{
		".patchpilot/findings.json",
		"src/foo-test/.patchpilot/gocache/cache.bin",
		"src/foo-test/.patchpilot/gomodcache/mod.zip",
		"src/foo-test/go.mod",
		".patchpilot.yaml",
	}

	got := filterMeaningfulPaths(input)
	want := []string{"src/foo-test/go.mod", ".patchpilot.yaml"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected filtered paths:\n got: %q\nwant: %q", got, want)
	}
}

func TestUnstagePatchPilotArtifactsRemovesNestedArtifactsOnly(t *testing.T) {
	repo := t.TempDir()
	runGitOrFail(t, repo, "init", "-b", "master")

	goModPath := filepath.Join(repo, "src", "foo-test", "go.mod")
	if err := os.MkdirAll(filepath.Dir(goModPath), 0o755); err != nil {
		t.Fatalf("mkdir module dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if err := os.WriteFile(goModPath, []byte("module example.com/foo\n\ngo 1.26.1\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	runGitOrFail(t, repo, "add", "-A")
	runGitOrFail(t, repo, "-c", "user.name=Tester", "-c", "user.email=test@example.com", "commit", "-m", "seed")

	if err := os.WriteFile(goModPath, []byte("module example.com/foo\n\ngo 1.27.0\n"), 0o644); err != nil {
		t.Fatalf("rewrite go.mod: %v", err)
	}
	artifactPath := filepath.Join(repo, "src", "foo-test", ".patchpilot", "gocache", "cache.bin")
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
		t.Fatalf("mkdir artifact dir: %v", err)
	}
	if err := os.WriteFile(artifactPath, []byte("cache"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	runGitOrFail(t, repo, "add", "-A")
	if err := unstagePatchPilotArtifacts(context.Background(), repo); err != nil {
		t.Fatalf("unstagePatchPilotArtifacts returned error: %v", err)
	}

	changedFiles, err := stagedChangedFiles(context.Background(), repo)
	if err != nil {
		t.Fatalf("stagedChangedFiles returned error: %v", err)
	}
	if len(changedFiles) != 1 || changedFiles[0] != "src/foo-test/go.mod" {
		t.Fatalf("unexpected staged files after unstage: %q", changedFiles)
	}

	rawStaged, err := stagedPaths(context.Background(), repo)
	if err != nil {
		t.Fatalf("stagedPaths returned error: %v", err)
	}
	if len(rawStaged) != 1 || rawStaged[0] != "src/foo-test/go.mod" {
		t.Fatalf("unexpected raw staged files after unstage: %q", rawStaged)
	}
}

func TestUnstagePatchPilotArtifactsHandlesLargeArtifactSets(t *testing.T) {
	repo := t.TempDir()
	runGitOrFail(t, repo, "init", "-b", "master")

	goModPath := filepath.Join(repo, "src", "foo-test", "go.mod")
	if err := os.MkdirAll(filepath.Dir(goModPath), 0o755); err != nil {
		t.Fatalf("mkdir module dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if err := os.WriteFile(goModPath, []byte("module example.com/foo\n\ngo 1.26.1\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	runGitOrFail(t, repo, "add", "-A")
	runGitOrFail(t, repo, "-c", "user.name=Tester", "-c", "user.email=test@example.com", "commit", "-m", "seed")

	if err := os.WriteFile(goModPath, []byte("module example.com/foo\n\ngo 1.27.0\n"), 0o644); err != nil {
		t.Fatalf("rewrite go.mod: %v", err)
	}

	artifactDir := filepath.Join(
		repo,
		strings.Repeat("a", 100),
		strings.Repeat("b", 100),
		strings.Repeat("c", 100),
		".patchpilot",
		"gocache",
	)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatalf("mkdir artifact dir: %v", err)
	}
	longPrefix := strings.Repeat("d", 140)
	for i := 0; i < 5000; i++ {
		artifactPath := filepath.Join(artifactDir, fmt.Sprintf("%s-%05d.bin", longPrefix, i))
		if err := os.WriteFile(artifactPath, nil, 0o644); err != nil {
			t.Fatalf("write artifact %d: %v", i, err)
		}
	}

	runGitOrFail(t, repo, "add", "-A")
	if err := unstagePatchPilotArtifacts(context.Background(), repo); err != nil {
		t.Fatalf("unstagePatchPilotArtifacts returned error: %v", err)
	}

	changedFiles, err := stagedChangedFiles(context.Background(), repo)
	if err != nil {
		t.Fatalf("stagedChangedFiles returned error: %v", err)
	}
	if len(changedFiles) != 1 || changedFiles[0] != "src/foo-test/go.mod" {
		t.Fatalf("unexpected staged files after unstage: %q", changedFiles)
	}

	rawStaged, err := stagedPaths(context.Background(), repo)
	if err != nil {
		t.Fatalf("stagedPaths returned error: %v", err)
	}
	if len(rawStaged) != 1 || rawStaged[0] != "src/foo-test/go.mod" {
		t.Fatalf("unexpected raw staged files after unstage: %q", rawStaged)
	}
}

func runGitOrFail(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed:\n%s\n%v", strings.Join(args, " "), string(output), err)
	}
}
