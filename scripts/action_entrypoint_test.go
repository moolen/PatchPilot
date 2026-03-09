package scripts

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type scriptResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func TestActionEntrypointRejectsUnsupportedCommand(t *testing.T) {
	tempDir := t.TempDir()
	createFakePatchPilot(t, tempDir)
	outputPath := filepath.Join(tempDir, "github-output.txt")

	result := runActionEntrypoint(t, tempDir, map[string]string{
		"INPUT_COMMAND": "unknown",
		"GITHUB_OUTPUT": outputPath,
	})
	if result.exitCode != 2 {
		t.Fatalf("unexpected exit code: got %d want %d\nstdout=%s\nstderr=%s", result.exitCode, 2, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr, "unsupported command") {
		t.Fatalf("expected unsupported command error, got stderr=%q", result.stderr)
	}
}

func TestActionEntrypointAcceptableExitCodeAndOutputContract(t *testing.T) {
	tempDir := t.TempDir()
	argsPath := createFakePatchPilot(t, tempDir)
	outputPath := filepath.Join(tempDir, "github-output.txt")

	result := runActionEntrypoint(t, tempDir, map[string]string{
		"INPUT_COMMAND":               "scan",
		"INPUT_DIR":                   "repo",
		"INPUT_ACCEPTABLE_EXIT_CODES": "0, 23",
		"PATCHPILOT_EXIT_CODE":        "23",
		"GITHUB_OUTPUT":               outputPath,
	})
	if result.exitCode != 0 {
		t.Fatalf("expected accepted exit code to return 0, got %d\nstdout=%s\nstderr=%s", result.exitCode, result.stdout, result.stderr)
	}

	args := readArgLines(t, argsPath)
	expectedPrefix := []string{"scan", "--dir", "repo"}
	if len(args) < len(expectedPrefix) {
		t.Fatalf("expected at least %d args, got %d (%v)", len(expectedPrefix), len(args), args)
	}
	for index, expected := range expectedPrefix {
		if args[index] != expected {
			t.Fatalf("unexpected arg %d: got %q want %q (all args: %v)", index, args[index], expected, args)
		}
	}

	outputRaw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read github output file: %v", err)
	}
	if !strings.Contains(string(outputRaw), "exit-code=23") {
		t.Fatalf("expected exit-code output, got: %s", string(outputRaw))
	}
}

func TestActionEntrypointFixCommandPassesAgentAndExtraArgs(t *testing.T) {
	tempDir := t.TempDir()
	argsPath := createFakePatchPilot(t, tempDir)

	result := runActionEntrypoint(t, tempDir, map[string]string{
		"INPUT_COMMAND":            "fix",
		"INPUT_DIR":                "repo-dir",
		"INPUT_REPO_URL":           "https://github.com/example/service.git",
		"INPUT_POLICY":             ".patchpilot.yaml",
		"INPUT_ENABLE_AGENT":       "true",
		"INPUT_AGENT_COMMAND":      "codex",
		"INPUT_AGENT_MAX_ATTEMPTS": "7",
		"INPUT_EXTRA_ARGS":         "--json --policy /tmp/custom.yaml",
	})
	if result.exitCode != 0 {
		t.Fatalf("unexpected exit code: %d\nstdout=%s\nstderr=%s", result.exitCode, result.stdout, result.stderr)
	}

	args := readArgLines(t, argsPath)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "fix --repo-url https://github.com/example/service.git") {
		t.Fatalf("expected repo_url to be passed to patchpilot, args=%v", args)
	}
	if strings.Contains(joined, "--dir repo-dir") {
		t.Fatalf("did not expect --dir when repo_url is set, args=%v", args)
	}
	for _, expected := range []string{
		"--policy .patchpilot.yaml",
		"--enable-agent=true",
		"--agent-command codex",
		"--agent-max-attempts 7",
		"--json",
		"--policy /tmp/custom.yaml",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing expected args segment %q in %q", expected, joined)
		}
	}
}

func runActionEntrypoint(t *testing.T, tempDir string, extraEnv map[string]string) scriptResult {
	t.Helper()
	scriptPath := filepath.Join("action-entrypoint.sh")
	command := exec.Command("bash", scriptPath)
	command.Dir = "."

	env := append(os.Environ(), "PATH="+tempDir+":"+os.Getenv("PATH"))
	for key, value := range extraEnv {
		env = append(env, key+"="+value)
	}
	command.Env = env

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	result := scriptResult{stdout: stdout.String(), stderr: stderr.String()}
	if err == nil {
		return result
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.exitCode = exitErr.ExitCode()
		return result
	}
	t.Fatalf("run action entrypoint: %v", err)
	return result
}

func createFakePatchPilot(t *testing.T, tempDir string) string {
	t.Helper()
	argsPath := filepath.Join(tempDir, "patchpilot-args.txt")
	binaryPath := filepath.Join(tempDir, "patchpilot")
	script := "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$PATCHPILOT_ARGS_FILE\"\nexit \"${PATCHPILOT_EXIT_CODE:-0}\"\n"
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake patchpilot binary: %v", err)
	}
	t.Setenv("PATCHPILOT_ARGS_FILE", argsPath)
	return argsPath
}

func readArgLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patchpilot args: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}
