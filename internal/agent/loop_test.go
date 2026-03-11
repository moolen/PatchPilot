package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoopRunPersistsArtifactsAndStopsOnSuccess(t *testing.T) {
	temp := t.TempDir()
	runner := Runner{Command: `echo external-agent-run`}
	loop := Loop{Agent: runner}

	attempts := 0
	result, err := loop.Run(context.Background(), LoopRequest{
		RepoPath:             temp,
		WorkingDirectory:     temp,
		ArtifactDirectory:    filepath.Join(temp, ".patchpilot", "agent"),
		MaxAttempts:          5,
		TaskKind:             TaskKindFixVulnerabilities,
		Goal:                 "Fix vulnerabilities.",
		CurrentStateLabel:    "Remaining vulnerabilities",
		InitialProgressCount: 3,
		InitialCurrentState:  `{"matches":[{"id":"CVE-1"}]}`,
		ValidationPlan:       []string{"go build ./...", "go test -run=^$ ./..."},
		Validate: func(ctx context.Context, attemptNumber int) (ValidationResult, error) {
			attempts++
			if attemptNumber == 1 {
				return ValidationResult{ValidationPassed: false, GoalMet: false, ProgressCount: 2, CurrentState: "{}", Logs: "attempt 1 failed"}, nil
			}
			return ValidationResult{ValidationPassed: true, GoalMet: true, ProgressCount: 0, CurrentState: "{}", Logs: "attempt 2 passed"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful loop result, got %#v", result)
	}
	if result.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", result.Attempts)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 validations, got %d", attempts)
	}

	for _, rel := range []string{
		".patchpilot/agent/attempt-1/prompt.txt",
		".patchpilot/agent/attempt-1/agent.log",
		".patchpilot/agent/attempt-1/validation.log",
		".patchpilot/agent/attempt-1/summary.json",
		".patchpilot/agent/attempt-2/prompt.txt",
		".patchpilot/agent/attempt-2/agent.log",
		".patchpilot/agent/attempt-2/validation.log",
		".patchpilot/agent/attempt-2/summary.json",
	} {
		path := filepath.Join(temp, rel)
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected artifact %s: %v", path, statErr)
		}
	}
}

func TestLoopRunCanSucceedEvenWhenAgentCommandExitsNonZero(t *testing.T) {
	temp := t.TempDir()
	loop := Loop{Agent: Runner{Command: `echo agent-failed; exit 1`}}

	result, err := loop.Run(context.Background(), LoopRequest{
		RepoPath:             temp,
		WorkingDirectory:     temp,
		ArtifactDirectory:    filepath.Join(temp, ".patchpilot", "agent"),
		MaxAttempts:          1,
		TaskKind:             TaskKindBaselineScanRepair,
		Goal:                 "Make the baseline scan succeed.",
		CurrentStateLabel:    "Current baseline state",
		InitialProgressCount: 1,
		InitialCurrentState:  "{}",
		Validate: func(ctx context.Context, attemptNumber int) (ValidationResult, error) {
			return ValidationResult{ValidationPassed: true, GoalMet: true, ProgressCount: 0, CurrentState: "{}"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful loop result, got %#v", result)
	}
}
