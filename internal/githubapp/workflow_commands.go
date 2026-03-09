package githubapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runCommand(ctx context.Context, dir string, extraEnv map[string]string, name string, args ...string) (string, string, error) {
	if err := validateExecutableName(name); err != nil {
		return "", "", err
	}

	command := exec.CommandContext(ctx, name, args...) // #nosec G204,G702 -- command/args are controlled by internal callsites and validated executable names.
	command.Dir = dir

	if len(extraEnv) > 0 {
		env := os.Environ()
		for key, value := range extraEnv {
			env = append(env, key+"="+value)
		}
		command.Env = env
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer

	err := command.Run()
	return stdoutBuffer.String(), stderrBuffer.String(), err
}

func validateExecutableName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("command name cannot be empty")
	}
	if strings.ContainsAny(name, "\n\r\t") {
		return fmt.Errorf("command name contains invalid characters")
	}
	return nil
}

func hasRepositoryChanges(ctx context.Context, repoPath string) (bool, error) {
	stdout, _, err := runCommand(ctx, repoPath, nil, "git", "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("check git status: %w", err)
	}
	return strings.TrimSpace(stdout) != "", nil
}

func stagedChangedFiles(ctx context.Context, repoPath string) ([]string, error) {
	stdout, _, err := runCommand(ctx, repoPath, nil, "git", "diff", "--cached", "--name-only")
	if err != nil {
		return nil, fmt.Errorf("list changed files: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result, nil
}

func currentHeadSHA(ctx context.Context, repoPath string) (string, error) {
	stdout, _, err := runCommand(ctx, repoPath, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("resolve head commit: %w", err)
	}
	sha := strings.TrimSpace(stdout)
	if sha == "" {
		return "", fmt.Errorf("resolve head commit: empty sha")
	}
	return sha, nil
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func truncateForComment(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "(empty)"
	}
	const max = 3500
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "\n... (truncated)"
}
