package execsafe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Spec describes a hardened subprocess execution.
type Spec struct {
	Name         string
	Dir          string
	Binary       string
	Args         []string
	ShellCommand string
	Timeout      time.Duration

	// If true, use Env exactly and ignore host environment.
	ReplaceEnv bool
	// Env entries must be in KEY=VALUE form.
	Env []string
	// EnvAllowlist controls which host env entries are retained when ReplaceEnv is false.
	// Supports exact keys and prefix patterns ending in "*".
	EnvAllowlist []string

	Stdout io.Writer
	Stderr io.Writer

	ArtifactDir    string
	ArtifactPrefix string
	RedactValues   []string
}

type Result struct {
	ExitCode       int
	DurationMillis int64
	TimedOut       bool
	Stdout         string
	Stderr         string
	Combined       string
}

func Run(ctx context.Context, spec Spec) (Result, error) {
	commandName, commandArgs, err := resolveCommand(spec)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(spec.Name) == "" {
		spec.Name = commandName
	}

	runCtx := ctx
	cancel := func() {}
	if spec.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, spec.Timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(runCtx, commandName, commandArgs...)
	if strings.TrimSpace(spec.Dir) != "" {
		cmd.Dir = spec.Dir
	}

	env, err := buildEnv(spec)
	if err != nil {
		return Result{}, err
	}
	cmd.Env = env

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	var combinedBuffer bytes.Buffer

	stdoutWriter := io.Writer(&stdoutBuffer)
	stderrWriter := io.Writer(&stderrBuffer)
	if spec.Stdout != nil {
		stdoutWriter = io.MultiWriter(stdoutWriter, spec.Stdout)
	}
	if spec.Stderr != nil {
		stderrWriter = io.MultiWriter(stderrWriter, spec.Stderr)
	}
	cmd.Stdout = io.MultiWriter(stdoutWriter, &combinedBuffer)
	cmd.Stderr = io.MultiWriter(stderrWriter, &combinedBuffer)

	started := time.Now()
	runErr := cmd.Run()
	durationMillis := time.Since(started).Milliseconds()

	result := Result{
		ExitCode:       exitCodeFromError(runErr),
		DurationMillis: durationMillis,
		TimedOut:       errors.Is(runCtx.Err(), context.DeadlineExceeded),
		Stdout:         redact(stdoutBuffer.String(), spec.RedactValues),
		Stderr:         redact(stderrBuffer.String(), spec.RedactValues),
		Combined:       redact(combinedBuffer.String(), spec.RedactValues),
	}
	if writeErr := writeArtifacts(spec, result); writeErr != nil {
		return result, writeErr
	}
	return result, runErr
}

func resolveCommand(spec Spec) (string, []string, error) {
	if strings.TrimSpace(spec.ShellCommand) != "" {
		return "sh", []string{"-c", spec.ShellCommand}, nil
	}
	binary := strings.TrimSpace(spec.Binary)
	if binary == "" {
		return "", nil, errors.New("binary is required")
	}
	return binary, append([]string(nil), spec.Args...), nil
}

func buildEnv(spec Spec) ([]string, error) {
	extra := normalizeEnv(spec.Env)
	if spec.ReplaceEnv {
		return extra, nil
	}

	allowlist := spec.EnvAllowlist
	if len(allowlist) == 0 {
		allowlist = DefaultEnvAllowlist()
	}

	merged := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !isAllowedEnv(key, allowlist) {
			continue
		}
		merged[key] = value
	}
	for _, entry := range extra {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("invalid env entry %q", entry)
		}
		merged[key] = value
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+merged[key])
	}
	return result, nil
}

func normalizeEnv(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, entry := range values {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func isAllowedEnv(key string, allowlist []string) bool {
	for _, allowed := range allowlist {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
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

func DefaultEnvAllowlist() []string {
	return []string{
		"PATH",
		"HOME",
		"TMPDIR",
		"LANG",
		"LC_*",
		"TERM",
		"SSH_*",
		"GIT_*",
		"CI",
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",
		"http_proxy",
		"https_proxy",
		"no_proxy",
		"ACTIONS_*",
		"RUNNER_*",
	}
}

func writeArtifacts(spec Spec, result Result) error {
	dir := strings.TrimSpace(spec.ArtifactDir)
	if dir == "" {
		return nil
	}
	prefix := strings.TrimSpace(spec.ArtifactPrefix)
	if prefix == "" {
		prefix = "command"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create artifact dir: %w", err)
	}
	artifacts := map[string]string{
		filepath.Join(dir, prefix+".stdout.log"):   result.Stdout,
		filepath.Join(dir, prefix+".stderr.log"):   result.Stderr,
		filepath.Join(dir, prefix+".combined.log"): result.Combined,
	}
	for path, content := range artifacts {
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write artifact %s: %w", path, err)
		}
	}
	return nil
}

func redact(content string, values []string) string {
	redacted := content
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) < 4 {
			continue
		}
		redacted = strings.ReplaceAll(redacted, value, "REDACTED")
	}
	return redacted
}

func exitCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}
