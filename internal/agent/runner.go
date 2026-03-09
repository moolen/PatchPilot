package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/moolen/patchpilot/internal/execsafe"
)

// Runner executes an external agent harness command.
type Runner struct {
	Command string
	Stdout  io.Writer
	Stderr  io.Writer
}

func (runner Runner) RunAttempt(ctx context.Context, req AttemptRequest) (AttemptResult, error) {
	if strings.TrimSpace(runner.Command) == "" {
		return AttemptResult{}, errors.New("agent command is empty")
	}
	if strings.TrimSpace(req.PromptFilePath) == "" {
		return AttemptResult{}, errors.New("prompt file path is empty")
	}

	prompt := BuildPrompt(req)
	if err := os.MkdirAll(filepath.Dir(req.PromptFilePath), 0o755); err != nil {
		return AttemptResult{}, fmt.Errorf("create prompt directory: %w", err)
	}
	if err := os.WriteFile(req.PromptFilePath, []byte(prompt), 0o644); err != nil {
		return AttemptResult{}, fmt.Errorf("write prompt file: %w", err)
	}

	workingDir := strings.TrimSpace(req.WorkingDirectory)
	if workingDir == "" {
		workingDir = req.RepoPath
	}
	if strings.TrimSpace(workingDir) == "" {
		workingDir = "."
	}

	stdout := io.Writer(nil)
	stderr := io.Writer(nil)
	if runner.Stdout != nil {
		stdout = runner.Stdout
	}
	if runner.Stderr != nil {
		stderr = runner.Stderr
	} else if runner.Stdout != nil {
		stderr = runner.Stdout
	}

	runResult, err := execsafe.Run(ctx, execsafe.Spec{
		Name:           "agent",
		Dir:            workingDir,
		ShellCommand:   runner.Command,
		Stdout:         stdout,
		Stderr:         stderr,
		ArtifactDir:    filepath.Dir(req.PromptFilePath),
		ArtifactPrefix: "agent-command",
		Env: []string{
			"PATCHPILOT_REPO_PATH=" + req.RepoPath,
			fmt.Sprintf("PATCHPILOT_ATTEMPT_NUMBER=%d", req.AttemptNumber),
			"PATCHPILOT_PROMPT_FILE=" + req.PromptFilePath,
			"PATCHPILOT_AGENT_ARTIFACT_DIR=" + filepath.Dir(req.PromptFilePath),
		},
		// Agent harnesses may require provider credentials and other host settings.
		// Inherit the parent environment, then overlay PATCHPILOT_* variables above.
		EnvAllowlist: []string{"*"},
	})
	result := AttemptResult{Logs: strings.TrimSpace(runResult.Combined)}
	if err == nil {
		result.Success = true
		result.Summary = "agent command completed successfully"
		return result, nil
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.Success = false
		result.Summary = fmt.Sprintf("agent command exited with code %d", runResult.ExitCode)
		if result.Logs == "" {
			result.Logs = err.Error()
		}
		return result, nil
	}
	return result, fmt.Errorf("run agent command: %w", err)
}
