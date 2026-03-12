package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	agentpkg "github.com/moolen/patchpilot/internal/agent"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/report"
	"github.com/moolen/patchpilot/internal/verifycheck"
	"github.com/moolen/patchpilot/internal/vuln"
)

type fixOptions struct {
	EnableAgent      bool
	AgentCommand     string
	AgentMaxAttempts int
	AgentArtifactDir string
	UntrustedRepo    bool
	JSONOutput       bool
	FindingsFile     string
	RepositoryKey    string
	OCIImage         string
	OCIImageTag      string
	OCIImageRepo     string
}

type validationCycle struct {
	After            *vuln.Report
	Verification     verifycheck.Report
	ValidationPassed bool
	Logs             string
}

func runFix(ctx context.Context, repo string, cfg *policy.Config, options fixOptions) (resultErr error) {
	if options.EnableAgent && strings.TrimSpace(options.AgentCommand) == "" {
		return wrapWithExitCode(ExitCodePatchFailed, fmt.Errorf("%w: --agent-command is required when --enable-agent is set", errInvalidRuntimeConfig))
	}
	deterministicIssues := make([]string, 0)

	tracker := newRunTracker("fix", repo, options.JSONOutput)
	defer func() {
		failure := classifyRunFailure(resultErr, nil, options.EnableAgent, false, deterministicIssues)
		if err := tracker.complete(resultErr, failure); err != nil && resultErr == nil {
			resultErr = err
		}
	}()

	logProgress("starting fix workflow for %s", repo)

	stage := tracker.beginStage("configure_registry")
	restoreRegistry, err := configureRegistryFromPolicy(repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	tracker.endStageSuccess(stage, nil)
	defer restoreRegistry()

	stage = tracker.beginStage("load_findings")
	findings, err := loadFixFindings(ctx, repo, cfg, tracker.record.RunID, options)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	tracker.endStageSuccess(stage, map[string]any{
		"findings":            len(findings.Findings),
		"ignored_without_fix": findings.IgnoredWithoutFix,
		"ignored_by_policy":   findings.IgnoredByPolicy,
	})
	tracker.addCounter("findings_before", len(findings.Findings))
	if len(findings.Findings) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No fixable vulnerabilities found in current findings.")
		return nil
	}

	fileOptions := fileOptionsFromPolicy(cfg, options.UntrustedRepo)
	dockerOptions := dockerOptionsFromPolicy(cfg)
	goRuntimeOptions := goRuntimeOptionsFromPolicy(cfg)

	logProgress("applying deterministic fixes")
	stage = tracker.beginStage("apply_deterministic_fixes")
	allPatches, deterministicIssues, engineDetails, err := applyDeterministicFixes(
		ctx,
		repo,
		findings.Findings,
		fileOptions,
		dockerOptions,
		goRuntimeOptions,
		true,
	)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	tracker.endStageSuccess(stage, map[string]any{
		"engines":       engineDetails,
		"patches_total": len(allPatches),
		"issues":        len(deterministicIssues),
	})

	stage = tracker.beginStage("container_os_agent_patch")
	if err := applyContainerOSPatchingWithAgent(ctx, repo, cfg, findings, options); err != nil {
		deterministicIssues = append(deterministicIssues, fmt.Sprintf("container_os_patching: %v", err))
		tracker.endStageSuccess(stage, map[string]any{
			"status": "failed",
			"error":  err.Error(),
		})
	} else {
		tracker.endStageSuccess(stage, map[string]any{
			"status": "completed",
		})
	}

	stage = tracker.beginStage("write_sarif")
	if err := report.WriteSARIF(repo, findings.Findings); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{"path": ".patchpilot/findings.sarif"})

	logProgress("fix workflow completed")
	if len(allPatches) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No applicable fixes were applied.")
	}
	if len(deterministicIssues) > 0 {
		_, _ = fmt.Fprintln(os.Stdout, strings.Join(deterministicIssues, "\n"))
	}

	return nil
}

func loadFixFindings(ctx context.Context, repo string, cfg *policy.Config, runID string, options fixOptions) (*vuln.Report, error) {
	findingsPath := strings.TrimSpace(options.FindingsFile)
	if findingsPath != "" {
		report, err := readFindingsFromFile(repo, findingsPath)
		if err == nil {
			return report, nil
		}
		return nil, err
	}
	report, err := vuln.ReadNormalized(repo)
	if err == nil {
		return report, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if sbomErr := generateSBOM(ctx, repo, cfg); sbomErr != nil {
		return nil, sbomErr
	}
	return scanVulnerabilitiesForRun(ctx, repo, cfg, runID, "fix-load-findings", "fix")
}

func readFindingsFromFile(repo, findingsPath string) (*vuln.Report, error) {
	path := strings.TrimSpace(findingsPath)
	if path == "" {
		return nil, errors.New("findings file path is empty")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(repo, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read findings file %s: %w", path, err)
	}
	var report vuln.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode findings file %s: %w", path, err)
	}
	return &report, nil
}

func applyContainerOSPatchingWithAgent(ctx context.Context, repo string, cfg *policy.Config, findings *vuln.Report, options fixOptions) error {
	if !options.EnableAgent || strings.TrimSpace(options.AgentCommand) == "" {
		return nil
	}
	if findings == nil || len(findings.Findings) == 0 {
		return nil
	}
	containerFindings := make([]vuln.Finding, 0)
	for _, finding := range findings.Findings {
		if isContainerPackageEcosystem(finding.Ecosystem) {
			containerFindings = append(containerFindings, finding)
		}
	}
	if len(containerFindings) == 0 {
		return nil
	}
	dockerfiles, err := discoverDockerfilesForFix(repo, cfg)
	if err != nil {
		return err
	}
	repository := strings.TrimSpace(options.RepositoryKey)
	if repository == "" {
		repository = filepath.Base(repo)
	}
	state := map[string]any{
		"repository":           repository,
		"dockerfiles":          dockerfiles,
		"container_findings":   containerFindings,
		"oci_image":            strings.TrimSpace(options.OCIImage),
		"oci_image_tag":        strings.TrimSpace(options.OCIImageTag),
		"oci_image_repository": strings.TrimSpace(options.OCIImageRepo),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	artifactDir := filepath.Join(repo, ".patchpilot", "githubapp-agent", "container-os-patching")
	if configured := strings.TrimSpace(options.AgentArtifactDir); configured != "" {
		artifactDir = configured
		if !filepath.IsAbs(artifactDir) {
			artifactDir = filepath.Join(repo, artifactDir)
		}
	}
	runner := agentpkg.Runner{
		Command: options.AgentCommand,
		Stdout:  os.Stderr,
		Stderr:  os.Stderr,
	}
	_, err = runner.RunAttempt(ctx, agentpkg.AttemptRequest{
		RepoPath:          repo,
		AttemptNumber:     1,
		TaskKind:          "github_app_container_os_patching",
		Goal:              "Update Dockerfiles to remediate container OS package vulnerabilities after deterministic base image updates. Do not run validation commands.",
		CurrentStateLabel: "Current state",
		CurrentState:      string(data),
		Constraints: []string{
			"Do not run build, test, or scan commands.",
			"Prefer minimal Dockerfile changes.",
			"Preserve or restore non-root USER behavior.",
			"Do not modify .patchpilot artifacts or .patchpilot.yaml.",
		},
		ValidationPlan: []string{
			"Review container findings and relevant Dockerfiles.",
			"Apply OS package remediation only where it is actually needed.",
			"Do not run validation commands.",
		},
		WorkingDirectory: repo,
		PromptFilePath:   filepath.Join(artifactDir, "prompt.txt"),
	})
	if err != nil {
		return fmt.Errorf("run agent patch attempt: %w", err)
	}
	return nil
}

func discoverDockerfilesForFix(repo string, cfg *policy.Config) ([]string, error) {
	skipPaths := []string(nil)
	if cfg != nil {
		skipPaths = append(skipPaths, cfg.Scan.SkipPaths...)
	}
	result := make([]string, 0)
	err := filepath.WalkDir(repo, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(repo, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(relative)
		if normalized == ".git" || strings.HasPrefix(normalized, ".git/") || normalized == ".patchpilot" || strings.HasPrefix(normalized, ".patchpilot/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		for _, skip := range skipPaths {
			if matchesSkipPath(normalized, skip) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") || strings.HasSuffix(name, ".Dockerfile") {
			result = append(result, normalized)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover dockerfiles: %w", err)
	}
	sort.Strings(result)
	return result, nil
}

func matchesSkipPath(path, pattern string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	if path == pattern {
		return true
	}
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	return false
}
