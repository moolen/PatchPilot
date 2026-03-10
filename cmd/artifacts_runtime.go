package cmd

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

	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/sbom"
	"github.com/moolen/patchpilot/internal/vuln"
	"gopkg.in/yaml.v3"
)

type artifactScanOptions struct {
	RunID   string
	Phase   string
	Command string
}

type artifactTarget struct {
	ID           string
	Dockerfile   string
	Context      string
	ImageTagTmpl string
	BuildRun     string
	BuildTimeout time.Duration
}

func scanArtifactVulnerabilities(ctx context.Context, repo string, cfg *policy.Config, options artifactScanOptions) (*vuln.Report, error) {
	targets, err := artifactTargetsFromPolicy(ctx, repo, cfg, options)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	runID := strings.TrimSpace(options.RunID)
	if runID == "" {
		runID = newRunID()
	}
	phase := strings.TrimSpace(options.Phase)
	if phase == "" {
		phase = "scan"
	}
	phaseLabel := sanitizeArtifactName(phase)
	if phaseLabel == "" {
		phaseLabel = "scan"
	}

	reports := make([]*vuln.Report, 0, len(targets))
	for _, target := range targets {
		resolvedTag := resolveArtifactTemplate(target.ImageTagTmpl, map[string]string{
			"PP_RUN_ID":    runID,
			"PP_TARGET_ID": target.ID,
		})
		resolvedTag = strings.TrimSpace(resolvedTag)
		if resolvedTag == "" {
			return nil, fmt.Errorf("artifact target %q resolved empty image tag", target.ID)
		}

		logProgress("artifact target %q: building image %q", target.ID, resolvedTag)
		buildEnv := map[string]string{
			"PP_RUN_ID":     runID,
			"PP_TARGET_ID":  target.ID,
			"PP_IMAGE_TAG":  resolvedTag,
			"PP_DOCKERFILE": target.Dockerfile,
			"PP_CONTEXT":    target.Context,
			"PP_REPO_ROOT":  repo,
			"PP_COMMAND":    strings.TrimSpace(options.Command),
			"PP_PHASE":      phase,
		}
		if _, stderr, err := runShellCommand(ctx, repo, target.BuildRun, buildEnv, target.BuildTimeout); err != nil {
			return nil, fmt.Errorf("artifact target %q build failed: %w%s", target.ID, err, formatCommandStderr(stderr))
		}

		logProgress("artifact target %q: validating image tag %q", target.ID, resolvedTag)
		if _, stderr, err := runBinaryCommand(ctx, repo, nil, 2*time.Minute, "docker", "image", "inspect", resolvedTag); err != nil {
			return nil, fmt.Errorf("artifact target %q image inspect failed for %q: %w%s", target.ID, resolvedTag, err, formatCommandStderr(stderr))
		}

		prefix := fmt.Sprintf("%s-%s", sanitizeArtifactName(target.ID), phaseLabel)
		sbomPath := filepath.Join(repo, ".patchpilot", "artifacts", prefix+"-sbom.json")
		if _, err := sbom.GenerateForSourceWithOptions(ctx, repo, "image:"+resolvedTag, sbomPath, sbom.Options{}); err != nil {
			return nil, fmt.Errorf("artifact target %q sbom generation failed: %w", target.ID, err)
		}

		scanOptions := vulnOptionsFromPolicy(cfg)
		scanOptions.OutputPrefix = "artifact-" + prefix
		artifactReport, err := vuln.ScanSBOMWithOptions(ctx, repo, sbomPath, scanOptions)
		if err != nil {
			return nil, fmt.Errorf("artifact target %q vulnerability scan failed: %w", target.ID, err)
		}

		mappedFindings := make([]vuln.Finding, 0, len(artifactReport.Findings))
		for _, finding := range artifactReport.Findings {
			if !isContainerPackageEcosystem(finding.Ecosystem) {
				continue
			}
			finding.Locations = []string{target.Dockerfile}
			mappedFindings = append(mappedFindings, finding)
		}
		artifactReport.Findings = mappedFindings
		logProgress("artifact target %q: %d container finding(s) with fix versions", target.ID, len(mappedFindings))
		reports = append(reports, artifactReport)
	}

	return mergeVulnerabilityReports(reports...), nil
}

type artifactTargetsCommandOutput struct {
	Targets *[]policy.ArtifactTargetPolicy `yaml:"targets"`
}

func artifactTargetsFromPolicy(ctx context.Context, repo string, cfg *policy.Config, options artifactScanOptions) ([]artifactTarget, error) {
	if cfg == nil {
		return nil, nil
	}
	targetConfigs := append([]policy.ArtifactTargetPolicy(nil), cfg.Artifacts.Targets...)
	commandCfg := cfg.Artifacts.TargetsCommand
	if strings.TrimSpace(commandCfg.Run) != "" {
		resolvedFromCommand, err := resolveArtifactTargetsFromCommand(ctx, repo, commandCfg, options)
		if err != nil {
			if commandCfg.FailOnErrorOrDefault() {
				return nil, err
			}
			logProgress("artifact targets_command failed (ignored): %v", err)
		} else {
			switch commandCfg.Mode {
			case policy.ArtifactsTargetsCommandModeAppend:
				targetConfigs = mergeArtifactTargetPolicies(targetConfigs, resolvedFromCommand)
			default:
				targetConfigs = resolvedFromCommand
			}
		}
	}
	if err := writeResolvedArtifactTargets(repo, targetConfigs); err != nil {
		return nil, err
	}
	if len(targetConfigs) == 0 {
		return nil, nil
	}

	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}

	targets := make([]artifactTarget, 0, len(targetConfigs))
	for index, targetCfg := range targetConfigs {
		if !targetCfg.Scan.EnabledOrDefault() {
			continue
		}

		dockerfilePath, err := resolvePathInsideRepo(repoAbs, targetCfg.Dockerfile)
		if err != nil {
			return nil, fmt.Errorf("artifacts.targets[%d].dockerfile: %w", index, err)
		}
		if _, err := os.Stat(dockerfilePath); err != nil {
			return nil, fmt.Errorf("artifacts.targets[%d].dockerfile: %w", index, err)
		}

		contextPath, err := resolvePathInsideRepo(repoAbs, targetCfg.Context)
		if err != nil {
			return nil, fmt.Errorf("artifacts.targets[%d].context: %w", index, err)
		}
		info, err := os.Stat(contextPath)
		if err != nil {
			return nil, fmt.Errorf("artifacts.targets[%d].context: %w", index, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("artifacts.targets[%d].context must be a directory", index)
		}

		timeout, err := time.ParseDuration(targetCfg.Build.Timeout)
		if err != nil {
			return nil, fmt.Errorf("artifacts.targets[%d].build.timeout: %w", index, err)
		}
		targets = append(targets, artifactTarget{
			ID:           targetCfg.ID,
			Dockerfile:   dockerfilePath,
			Context:      contextPath,
			ImageTagTmpl: targetCfg.Image.Tag,
			BuildRun:     targetCfg.Build.Run,
			BuildTimeout: timeout,
		})
	}

	return targets, nil
}

func resolveArtifactTargetsFromCommand(ctx context.Context, repo string, command policy.ArtifactsTargetsCommandPolicy, options artifactScanOptions) ([]policy.ArtifactTargetPolicy, error) {
	env := map[string]string{
		"PP_RUN_ID":    strings.TrimSpace(options.RunID),
		"PP_REPO_ROOT": repo,
		"PP_COMMAND":   strings.TrimSpace(options.Command),
		"PP_PHASE":     strings.TrimSpace(options.Phase),
	}
	if env["PP_RUN_ID"] == "" {
		env["PP_RUN_ID"] = newRunID()
	}

	timeout, err := time.ParseDuration(command.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parse artifacts.targets_command.timeout: %w", err)
	}
	stdout, stderr, err := runShellCommand(ctx, repo, command.Run, env, timeout)
	if err != nil {
		return nil, fmt.Errorf("run artifacts.targets_command: %w%s", err, formatCommandStderr(stderr))
	}

	targets, err := parseArtifactTargetsCommandOutput(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse artifacts.targets_command output: %w%s", err, formatCommandStderr(stderr))
	}
	return targets, nil
}

func parseArtifactTargetsCommandOutput(raw string) ([]policy.ArtifactTargetPolicy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty stdout")
	}
	decoder := yaml.NewDecoder(strings.NewReader(raw))
	decoder.KnownFields(true)

	var payload artifactTargetsCommandOutput
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Targets == nil {
		return nil, errors.New("expected top-level targets key")
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, err
		}
	} else {
		return nil, errors.New("expected single YAML document")
	}

	normalized, err := policy.NormalizeArtifactTargets(*payload.Targets)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func mergeArtifactTargetPolicies(base, overlay []policy.ArtifactTargetPolicy) []policy.ArtifactTargetPolicy {
	merged := append([]policy.ArtifactTargetPolicy(nil), base...)
	indexByID := map[string]int{}
	for index := range merged {
		indexByID[merged[index].ID] = index
	}
	for _, target := range overlay {
		if index, ok := indexByID[target.ID]; ok {
			merged[index] = target
			continue
		}
		indexByID[target.ID] = len(merged)
		merged = append(merged, target)
	}
	return merged
}

func writeResolvedArtifactTargets(repo string, targets []policy.ArtifactTargetPolicy) error {
	path := filepath.Join(repo, ".patchpilot", "artifacts", "targets.resolved.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create artifacts state dir: %w", err)
	}
	payload := struct {
		Targets []policy.ArtifactTargetPolicy `yaml:"targets"`
	}{
		Targets: targets,
	}
	content, err := yaml.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal resolved artifact targets: %w", err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("write resolved artifact targets: %w", err)
	}
	return nil
}

func resolvePathInsideRepo(repoAbs, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is empty")
	}
	resolved := filepath.Clean(path)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(repoAbs, resolved)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(repoAbs, abs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes repository", path)
	}
	return abs, nil
}

func resolveArtifactTemplate(template string, values map[string]string) string {
	resolved := template
	for key, value := range values {
		resolved = strings.ReplaceAll(resolved, "${"+key+"}", value)
		resolved = strings.ReplaceAll(resolved, "$"+key, value)
	}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		resolved = strings.ReplaceAll(resolved, "${"+key+"}", value)
		resolved = strings.ReplaceAll(resolved, "$"+key, value)
	}
	return resolved
}

func runShellCommand(ctx context.Context, dir, command string, env map[string]string, timeout time.Duration) (string, string, error) {
	return runBinaryCommand(ctx, dir, env, timeout, "sh", "-c", command)
}

func runBinaryCommand(ctx context.Context, dir string, env map[string]string, timeout time.Duration, name string, args ...string) (string, string, error) {
	runCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{}, os.Environ()...)
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for key := range env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			cmd.Env = append(cmd.Env, key+"="+env[key])
		}
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer
	err := cmd.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return stdoutBuffer.String(), stderrBuffer.String(), fmt.Errorf("timed out after %s", timeout)
	}
	return stdoutBuffer.String(), stderrBuffer.String(), err
}

func formatCommandStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return "\ncommand stderr:\n" + stderr
}

func isContainerPackageEcosystem(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deb", "apk", "rpm":
		return true
	default:
		return false
	}
}
