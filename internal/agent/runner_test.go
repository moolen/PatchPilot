package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerRunAttemptSuccess(t *testing.T) {
	temp := t.TempDir()
	runner := Runner{Command: `echo run-ok; test -f "$PATCHPILOT_PROMPT_FILE"`}

	result, err := runner.RunAttempt(context.Background(), AttemptRequest{
		RepoPath:          temp,
		AttemptNumber:     1,
		TaskKind:          TaskKindFixVulnerabilities,
		Goal:              "Fix vulnerabilities.",
		CurrentStateLabel: "Current state",
		CurrentState:      "{}",
		WorkingDirectory:  temp,
		PromptFilePath:    filepath.Join(temp, "prompt.txt"),
	})
	if err != nil {
		t.Fatalf("RunAttempt returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success result, got %#v", result)
	}
	if !strings.Contains(result.Logs, "Prompt passed to agent") {
		t.Fatalf("expected logs to include prompt, got %q", result.Logs)
	}
	if !strings.Contains(result.Logs, "Task:\n"+TaskKindFixVulnerabilities) {
		t.Fatalf("expected prompt contents in logs, got %q", result.Logs)
	}
	if !strings.Contains(result.Logs, "run-ok") {
		t.Fatalf("expected logs to include command output, got %q", result.Logs)
	}
	promptBytes, err := os.ReadFile(filepath.Join(temp, "prompt.txt"))
	if err != nil {
		t.Fatalf("read prompt file: %v", err)
	}
	if !strings.Contains(string(promptBytes), "Fix vulnerabilities.") {
		t.Fatalf("expected prompt file to contain goal, got %q", string(promptBytes))
	}
}

func TestRunnerRunAttemptInheritsParentEnv(t *testing.T) {
	t.Setenv("AZURE_OPENAI_API_KEY", "unit-test-key")

	temp := t.TempDir()
	runner := Runner{Command: `test "$AZURE_OPENAI_API_KEY" = "unit-test-key"`}

	result, err := runner.RunAttempt(context.Background(), AttemptRequest{
		RepoPath:          temp,
		AttemptNumber:     1,
		TaskKind:          TaskKindFixVulnerabilities,
		Goal:              "Fix vulnerabilities.",
		CurrentStateLabel: "Current state",
		CurrentState:      "{}",
		WorkingDirectory:  temp,
		PromptFilePath:    filepath.Join(temp, "prompt.txt"),
	})
	if err != nil {
		t.Fatalf("RunAttempt returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success result, got %#v", result)
	}
}

func TestRunnerRunAttemptNonZeroExitIsAttemptFailure(t *testing.T) {
	temp := t.TempDir()
	runner := Runner{Command: `echo run-failed; exit 3`}

	result, err := runner.RunAttempt(context.Background(), AttemptRequest{
		RepoPath:          temp,
		AttemptNumber:     1,
		TaskKind:          TaskKindFixVulnerabilities,
		Goal:              "Fix vulnerabilities.",
		CurrentStateLabel: "Current state",
		CurrentState:      "{}",
		WorkingDirectory:  temp,
		PromptFilePath:    filepath.Join(temp, "prompt.txt"),
	})
	if err != nil {
		t.Fatalf("RunAttempt returned error: %v", err)
	}
	if result.Success {
		t.Fatalf("expected failed attempt result, got %#v", result)
	}
	if !strings.Contains(result.Summary, "code 3") {
		t.Fatalf("expected exit code in summary, got %q", result.Summary)
	}
	if !strings.Contains(result.Logs, "run-failed") {
		t.Fatalf("expected command logs, got %q", result.Logs)
	}
}

func TestRunnerRunAttemptWritesPromptToConfiguredStderr(t *testing.T) {
	temp := t.TempDir()
	var stderr bytes.Buffer
	runner := Runner{
		Command: `echo run-ok`,
		Stderr:  &stderr,
	}

	_, err := runner.RunAttempt(context.Background(), AttemptRequest{
		RepoPath:          temp,
		AttemptNumber:     1,
		TaskKind:          TaskKindFixVulnerabilities,
		Goal:              "Fix vulnerabilities.",
		CurrentStateLabel: "Current state",
		CurrentState:      "{}",
		WorkingDirectory:  temp,
		PromptFilePath:    filepath.Join(temp, "prompt.txt"),
	})
	if err != nil {
		t.Fatalf("RunAttempt returned error: %v", err)
	}
	if !strings.Contains(stderr.String(), "Prompt passed to agent") {
		t.Fatalf("expected configured stderr to include prompt log, got %q", stderr.String())
	}
}

func TestRunnerRunAttemptRequiresCommand(t *testing.T) {
	_, err := (Runner{}).RunAttempt(context.Background(), AttemptRequest{PromptFilePath: filepath.Join(t.TempDir(), "prompt.txt")})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}
