package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerRunAttemptSuccess(t *testing.T) {
	temp := t.TempDir()
	runner := Runner{Command: `echo run-ok; test -f "$CVEFIX_PROMPT_FILE"`}

	result, err := runner.RunAttempt(context.Background(), AttemptRequest{
		RepoPath:                 temp,
		AttemptNumber:            1,
		RemainingVulnerabilities: "{}",
		WorkingDirectory:         temp,
		PromptFilePath:           filepath.Join(temp, "prompt.txt"),
	})
	if err != nil {
		t.Fatalf("RunAttempt returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success result, got %#v", result)
	}
	if !strings.Contains(result.Logs, "run-ok") {
		t.Fatalf("expected logs to include command output, got %q", result.Logs)
	}
}

func TestRunnerRunAttemptInheritsParentEnv(t *testing.T) {
	t.Setenv("AZURE_OPENAI_API_KEY", "unit-test-key")

	temp := t.TempDir()
	runner := Runner{Command: `test "$AZURE_OPENAI_API_KEY" = "unit-test-key"`}

	result, err := runner.RunAttempt(context.Background(), AttemptRequest{
		RepoPath:                 temp,
		AttemptNumber:            1,
		RemainingVulnerabilities: "{}",
		WorkingDirectory:         temp,
		PromptFilePath:           filepath.Join(temp, "prompt.txt"),
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
		RepoPath:                 temp,
		AttemptNumber:            1,
		RemainingVulnerabilities: "{}",
		WorkingDirectory:         temp,
		PromptFilePath:           filepath.Join(temp, "prompt.txt"),
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

func TestRunnerRunAttemptRequiresCommand(t *testing.T) {
	_, err := (Runner{}).RunAttempt(context.Background(), AttemptRequest{PromptFilePath: filepath.Join(t.TempDir(), "prompt.txt")})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}
