package githubapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func runCommand(ctx context.Context, dir string, extraEnv map[string]string, name string, args ...string) (string, string, error) {
	if err := validateExecutableName(name); err != nil {
		return "", "", err
	}

	command := exec.CommandContext(ctx, name, args...) // #nosec G204,G702 -- command/args are controlled by internal callsites and validated executable names.
	command.Dir = dir
	command.Env = githubAppCommandEnv(extraEnv)

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer

	err := command.Run()
	return stdoutBuffer.String(), stderrBuffer.String(), err
}

var githubAppEnvAllowlist = []string{
	"PATH",
	"HOME",
	"TMPDIR",
	"LANG",
	"LC_*",
	"TERM",
	"USER",
	"LOGNAME",
	"TZ",
	"CI",
	"ACTIONS_*",
	"RUNNER_*",
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"no_proxy",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"NODE_EXTRA_CA_CERTS",
	"DOCKER_*",
	"PODMAN_*",
	"CONTAINER_*",
	"XDG_*",
	"GIT_*",
	"SSH_*",
	"GO*",
	"CGO_*",
}

func githubAppCommandEnv(extraEnv map[string]string) []string {
	merged := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !githubAppEnvAllowed(key) {
			continue
		}
		merged[key] = value
	}
	for key, value := range extraEnv {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		merged[key] = value
	}
	if _, exists := merged["GIT_TERMINAL_PROMPT"]; !exists {
		merged["GIT_TERMINAL_PROMPT"] = "0"
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+merged[key])
	}
	return env
}

func githubAppEnvAllowed(key string) bool {
	for _, allowed := range githubAppEnvAllowlist {
		if strings.HasSuffix(allowed, "*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(key, prefix) {
				return true
			}
			continue
		}
		if key == allowed {
			return true
		}
	}
	return false
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
	return len(filterMeaningfulPaths(parseStatusPaths(stdout))) > 0, nil
}

func stagedChangedFiles(ctx context.Context, repoPath string) ([]string, error) {
	paths, err := stagedPaths(ctx, repoPath)
	if err != nil {
		return nil, err
	}
	return filterMeaningfulPaths(paths), nil
}

func stagedPaths(ctx context.Context, repoPath string) ([]string, error) {
	stdout, _, err := runCommand(ctx, repoPath, nil, "git", "diff", "--cached", "--name-only")
	if err != nil {
		return nil, fmt.Errorf("list changed files: %w", err)
	}
	return strings.Split(strings.TrimSpace(stdout), "\n"), nil
}

func unstagePath(ctx context.Context, repoPath string, target string) error {
	if strings.TrimSpace(target) == "" {
		return nil
	}
	if _, _, err := runCommand(ctx, repoPath, nil, "git", "reset", "--quiet", "HEAD", "--", target); err != nil {
		return fmt.Errorf("unstage %s: %w", target, err)
	}
	return nil
}

func unstagePatchPilotArtifacts(ctx context.Context, repoPath string) error {
	paths, err := stagedPaths(ctx, repoPath)
	if err != nil {
		return err
	}
	artifactPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		if isPatchPilotArtifactPath(path) {
			artifactPaths = append(artifactPaths, filepath.ToSlash(strings.TrimSpace(path)))
		}
	}
	if len(artifactPaths) == 0 {
		return nil
	}
	args := append([]string{"reset", "--quiet", "HEAD", "--"}, artifactPaths...)
	if _, _, err := runCommand(ctx, repoPath, nil, "git", args...); err != nil {
		return fmt.Errorf("unstage .patchpilot artifacts: %w", err)
	}
	return nil
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

func parseStatusPaths(statusOutput string) []string {
	lines := strings.Split(statusOutput, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) > 3 {
			result = append(result, strings.TrimSpace(line[3:]))
			continue
		}
		result = append(result, strings.TrimSpace(line))
	}
	return result
}

func filterMeaningfulPaths(paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		normalized := filepath.ToSlash(strings.TrimSpace(path))
		if normalized == "" {
			continue
		}
		if isPatchPilotArtifactPath(normalized) {
			continue
		}
		result = append(result, normalized)
	}
	return result
}

func isPatchPilotArtifactPath(path string) bool {
	normalized := filepath.ToSlash(strings.TrimSpace(path))
	if normalized == "" {
		return false
	}
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		if part == ".patchpilot" {
			return true
		}
	}
	return false
}
