package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	var logs bytes.Buffer
	stdout := io.Writer(&logs)
	stderr := io.Writer(&logs)
	if runner.Stdout != nil {
		stdout = io.MultiWriter(stdout, runner.Stdout)
	}
	if runner.Stderr != nil {
		stderr = io.MultiWriter(stderr, runner.Stderr)
	} else if runner.Stdout != nil {
		stderr = io.MultiWriter(stderr, runner.Stdout)
	}

	command := exec.CommandContext(ctx, "sh", "-c", runner.Command)
	command.Dir = workingDir
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = append(os.Environ(),
		"CVEFIX_REPO_PATH="+req.RepoPath,
		fmt.Sprintf("CVEFIX_ATTEMPT_NUMBER=%d", req.AttemptNumber),
		"CVEFIX_PROMPT_FILE="+req.PromptFilePath,
	)

	err := command.Run()
	result := AttemptResult{Logs: strings.TrimSpace(logs.String())}
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
		result.Summary = fmt.Sprintf("agent command exited with code %d", exitErr.ExitCode())
		if result.Logs == "" {
			result.Logs = err.Error()
		}
		return result, nil
	}
	return result, fmt.Errorf("run agent command: %w", err)
}
