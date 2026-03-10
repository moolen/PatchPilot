package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const fileName = "sbom.json"

var defaultExcludes = []string{
	"./.git",
	"./.patchpilot",
	"./bin",
	"./vendor",
	"**/.terraform",
	"**/.terraform/**",
}

type Options struct {
	Exclude []string
}

func Generate(ctx context.Context, repo string) (string, error) {
	return GenerateWithOptions(ctx, repo, Options{})
}

func GenerateWithOptions(ctx context.Context, repo string, options Options) (string, error) {
	outputPath := filepath.Join(repo, ".patchpilot", fileName)
	return GenerateForSourceWithOptions(ctx, repo, "dir:"+repo, outputPath, options)
}

func GenerateForSourceWithOptions(ctx context.Context, repo, source, outputPath string, options Options) (string, error) {
	if err := ensureTool("syft"); err != nil {
		return "", err
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return "", fmt.Errorf("syft source must not be empty")
	}

	if strings.TrimSpace(outputPath) == "" {
		outputPath = filepath.Join(repo, ".patchpilot", fileName)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	args := []string{source, "-o", "cyclonedx-json"}
	if strings.HasPrefix(strings.ToLower(source), "dir:") {
		for _, exclude := range buildExcludes(options.Exclude) {
			args = append(args, "--exclude", exclude)
		}
	}

	cmd := exec.CommandContext(ctx, "syft", args...)
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuffer)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run syft: %w%s", err, formatCapturedStderr(stderrBuffer.String()))
	}

	output := stdoutBuffer.Bytes()
	if err := validateSBOMOutput(output); err != nil {
		if writeErr := os.WriteFile(outputPath, output, 0o644); writeErr == nil {
			return "", fmt.Errorf("invalid syft output: %w (raw output at %s)%s", err, outputPath, formatCapturedStderr(stderrBuffer.String()))
		}
		return "", fmt.Errorf("invalid syft output: %w%s", err, formatCapturedStderr(stderrBuffer.String()))
	}

	if err := os.WriteFile(outputPath, output, 0o644); err != nil {
		return "", fmt.Errorf("write sbom output: %w", err)
	}

	return outputPath, nil
}

func buildExcludes(extra []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0)
	for _, exclude := range defaultExcludes {
		exclude = strings.TrimSpace(exclude)
		if exclude == "" {
			continue
		}
		if _, ok := seen[exclude]; ok {
			continue
		}
		seen[exclude] = struct{}{}
		result = append(result, exclude)
	}
	for _, exclude := range extra {
		exclude = strings.TrimSpace(exclude)
		if exclude == "" {
			continue
		}
		if !strings.HasPrefix(exclude, "./") && !strings.HasPrefix(exclude, "**/") {
			exclude = "./" + exclude
		}
		if _, ok := seen[exclude]; ok {
			continue
		}
		seen[exclude] = struct{}{}
		result = append(result, exclude)
	}
	return result
}

func Path(repo string) string {
	return filepath.Join(repo, ".patchpilot", fileName)
}

func ensureTool(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required tool %q not found in PATH", name)
	}
	return nil
}

func validateSBOMOutput(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return fmt.Errorf("empty JSON output")
	}
	if !json.Valid(trimmed) {
		return fmt.Errorf("invalid JSON output")
	}
	return nil
}

func formatCapturedStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return "\nsyft stderr:\n" + stderr
}
