//go:build integration

package integration

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type recordedFakeAgentInvocation struct {
	Timestamp string            `json:"timestamp"`
	Args      []string          `json:"args"`
	CWD       string            `json:"cwd"`
	Env       map[string]string `json:"env"`
	Stdin     string            `json:"stdin"`
}

func TestBuiltBinaryBumpsGoMod(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)
	repo := newScenarioRepo(t, map[string]string{
		"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
	})

	result := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
	if result.exitCode != 0 {
		t.Fatalf("expected fix to succeed, got %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, result.stdout, result.stderr)
	}

	content := readFile(t, repo, "go.mod")
	if !strings.Contains(content, "github.com/example/lib v1.2.3") {
		t.Fatalf("expected go.mod to be bumped, got:\n%s", content)
	}

	summary := readSummary(t, repo)
	if summary.Before != 1 || summary.Fixed != 1 || summary.After != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestBuiltBinaryBumpsDockerfile(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)
	env = withRegistryTagCache(t, env, registryTagFixture{
		Registry:   "docker.io",
		Repository: "library/golang",
		Tags:       []string{"1.21.0-alpine", "1.21.1-alpine", "1.22.0-alpine"},
	})
	repo := newScenarioRepo(t, map[string]string{
		"Dockerfile": "# patchpilot:base-golang\nFROM golang:1.21.0-alpine\nRUN echo baseline\n",
	})
	writeFile(t, repo, ".patchpilot.yaml", "version: 1\noci:\n  policies:\n    - name: golang-alpine\n      source: golang\n      tags:\n        allow:\n          - '^1\\.21\\.[0-9]+-alpine$'\n        semver:\n          - range:\n              - '>=1.21.1 <1.22.0'\n")

	result := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
	if result.exitCode != 0 {
		t.Fatalf("expected fix to succeed, got %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, result.stdout, result.stderr)
	}

	content := readFile(t, repo, "Dockerfile")
	if !strings.Contains(content, "FROM golang:1.21.1-alpine") {
		t.Fatalf("expected Dockerfile to be bumped, got:\n%s", content)
	}

	summary := readSummary(t, repo)
	if summary.Before != 1 || summary.Fixed != 1 || summary.After != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestBuiltBinaryInvokesDefaultAgentCommand(t *testing.T) {
	toolsDir := installFakeTools(t)
	installFakeAgentCommand(t, toolsDir)

	recordPath := filepath.Join(t.TempDir(), "agent-invocations.jsonl")
	env := integrationEnv(toolsDir)
	env["FAKE_AGENT_RECORD_PATH"] = recordPath

	repo := newScenarioRepo(t, map[string]string{
		"go.mod":              "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
		".scenario/fail-tidy": "1\n",
	})

	result := runBinary(t, env, "--dir", repo, "fix")
	if result.exitCode != 0 {
		t.Fatalf("expected fix to succeed through agent loop, got %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, result.stdout, result.stderr)
	}

	attemptDir := filepath.Join(repo, ".patchpilot", "agent", "attempt-1")
	promptPath := filepath.Join(attemptDir, "prompt.txt")
	lastMessagePath := filepath.Join(attemptDir, "last-message.txt")

	invocations := readFakeAgentInvocations(t, recordPath)
	if len(invocations) != 1 {
		t.Fatalf("expected exactly one agent invocation, got %#v", invocations)
	}
	invocation := invocations[0]

	wantArgs := []string{
		"exec",
		"--skip-git-repo-check",
		"--sandbox",
		"workspace-write",
		"-o",
		lastMessagePath,
		"-",
	}
	if !reflect.DeepEqual(invocation.Args, wantArgs) {
		t.Fatalf("unexpected agent args: got %#v want %#v", invocation.Args, wantArgs)
	}
	if invocation.CWD != repo {
		t.Fatalf("unexpected agent cwd: got %q want %q", invocation.CWD, repo)
	}

	if got := invocation.Env["PATCHPILOT_REPO_PATH"]; got != repo {
		t.Fatalf("unexpected PATCHPILOT_REPO_PATH: got %q want %q", got, repo)
	}
	if got := invocation.Env["PATCHPILOT_ATTEMPT_NUMBER"]; got != "1" {
		t.Fatalf("unexpected PATCHPILOT_ATTEMPT_NUMBER: got %q want %q", got, "1")
	}
	if got := invocation.Env["PATCHPILOT_PROMPT_FILE"]; got != promptPath {
		t.Fatalf("unexpected PATCHPILOT_PROMPT_FILE: got %q want %q", got, promptPath)
	}
	if got := invocation.Env["PATCHPILOT_AGENT_ARTIFACT_DIR"]; got != attemptDir {
		t.Fatalf("unexpected PATCHPILOT_AGENT_ARTIFACT_DIR: got %q want %q", got, attemptDir)
	}

	promptText := readFile(t, repo, ".patchpilot/agent/attempt-1/prompt.txt")
	if invocation.Stdin != promptText {
		t.Fatalf("expected agent stdin to equal prompt.txt\nstdin:\n%s\nprompt:\n%s", invocation.Stdin, promptText)
	}
	if !strings.Contains(promptText, "Task:\nfix_vulnerabilities") {
		t.Fatalf("expected fix prompt, got:\n%s", promptText)
	}
	if !strings.Contains(promptText, "Fix vulnerabilities with minimal changes and keep the build passing.") {
		t.Fatalf("expected fix goal in prompt, got:\n%s", promptText)
	}
	if !strings.Contains(result.stderr, "Prompt passed to agent") {
		t.Fatalf("expected stderr to include prompt log, got:\n%s", result.stderr)
	}

	for _, rel := range []string{
		".patchpilot/agent/attempt-1/prompt.txt",
		".patchpilot/agent/attempt-1/agent.log",
		".patchpilot/agent/attempt-1/validation.log",
		".patchpilot/agent/attempt-1/summary.json",
		".patchpilot/agent/attempt-1/last-message.txt",
	} {
		if _, err := os.Stat(filepath.Join(repo, rel)); err != nil {
			t.Fatalf("expected artifact %s: %v", rel, err)
		}
	}

	summary := readSummary(t, repo)
	if summary.Before != 1 || summary.Fixed != 1 || summary.After != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func installFakeAgentCommand(t *testing.T, toolsDir string) {
	t.Helper()
	src, err := os.Open(integrationFakeAgentBinary)
	if err != nil {
		t.Fatalf("open fake agent binary: %v", err)
	}
	defer src.Close()

	dstPath := filepath.Join(toolsDir, "codex")
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("create fake codex binary: %v", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		t.Fatalf("copy fake agent binary: %v", err)
	}
}

func readFakeAgentInvocations(t *testing.T, path string) []recordedFakeAgentInvocation {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fake agent record file: %v", err)
	}
	defer file.Close()

	invocations := make([]recordedFakeAgentInvocation, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var invocation recordedFakeAgentInvocation
		if err := json.Unmarshal([]byte(line), &invocation); err != nil {
			t.Fatalf("decode fake agent invocation: %v", err)
		}
		invocations = append(invocations, invocation)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fake agent invocations: %v", err)
	}
	return invocations
}
