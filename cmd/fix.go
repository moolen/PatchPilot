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
	OCIMappingFile   string
}

type validationCycle struct {
	After            *vuln.Report
	Verification     verifycheck.Report
	ValidationPassed bool
	Logs             string
}

func runFix(ctx context.Context, repo string, cfg *policy.Config, options fixOptions) (resultErr error) {
	if options.EnableAgent {
		if strings.TrimSpace(options.AgentCommand) == "" {
			return wrapWithExitCode(ExitCodePatchFailed, fmt.Errorf("%w: --agent-command is required when --enable-agent is set", errInvalidRuntimeConfig))
		}
		if options.AgentMaxAttempts <= 0 {
			return wrapWithExitCode(ExitCodePatchFailed, fmt.Errorf("%w: --agent-max-attempts must be greater than zero", errInvalidRuntimeConfig))
		}
	}

	var summaryForFailure *report.Summary
	agentSucceeded := false
	deterministicIssues := make([]string, 0)

	tracker := newRunTracker("fix", repo, options.JSONOutput)
	defer func() {
		failure := classifyRunFailure(resultErr, summaryForFailure, options.EnableAgent, agentSucceeded, deterministicIssues)
		if err := tracker.complete(resultErr, failure); err != nil && resultErr == nil {
			resultErr = err
		}
	}()

	defer func() {
		hookErr := runPostExecutionHooks(ctx, repo, cfg, resultErr == nil)
		if hookErr == nil {
			return
		}
		if resultErr == nil {
			resultErr = wrapWithExitCode(ExitCodePatchFailed, hookErr)
			return
		}
		resultErr = fmt.Errorf("%w; %v", resultErr, hookErr)
	}()

	logProgress("starting fix workflow for %s", repo)
	ociContext := ociScanContext{
		RepositoryKey: strings.TrimSpace(options.RepositoryKey),
		MappingFile:   strings.TrimSpace(options.OCIMappingFile),
	}

	stage := tracker.beginStage("pre_execution_hooks")
	if err := runPreExecutionHooks(ctx, repo, cfg); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	tracker.endStageSuccess(stage, nil)

	stage = tracker.beginStage("configure_registry")
	restoreRegistry, err := configureRegistryFromPolicy(repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	tracker.endStageSuccess(stage, nil)
	defer restoreRegistry()

	var before *vuln.Report

	stage = tracker.beginStage("load_findings")
	before, err = loadFixFindings(repo, options)
	explicitFindingsFile := strings.TrimSpace(options.FindingsFile) != ""
	switch {
	case err == nil:
		tracker.endStageSuccess(stage, map[string]any{
			"findings":            len(before.Findings),
			"ignored_without_fix": before.IgnoredWithoutFix,
			"ignored_by_policy":   before.IgnoredByPolicy,
		})
	case explicitFindingsFile || !errors.Is(err, os.ErrNotExist):
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	default:
		tracker.endStageSuccess(stage, map[string]any{"source": "baseline_scan"})
	}

	if before == nil {
		logProgress("generating baseline SBOM")
		stage = tracker.beginStage("generate_baseline_sbom")
		if err := generateSBOM(ctx, repo, cfg); err != nil {
			if !options.EnableAgent {
				tracker.endStageFailure(stage, err, nil)
				return err
			}
			tracker.endStageSuccess(stage, map[string]any{
				"status": "deferred_to_agent",
				"error":  err.Error(),
			})

			stage = tracker.beginStage("baseline_scan_repair_loop")
			var attempts int
			before, attempts, err = runBaselineRepairLoop(ctx, repo, cfg, options, ociContext, tracker.record.RunID, "generate_baseline_sbom", err)
			if err != nil {
				tracker.endStageFailure(stage, err, nil)
				return err
			}
			agentSucceeded = true
			tracker.endStageSuccess(stage, map[string]any{
				"attempts": attempts,
				"success":  true,
			})
		} else {
			tracker.endStageSuccess(stage, nil)

			logProgress("scanning baseline vulnerabilities")
			stage = tracker.beginStage("scan_baseline")
			before, err = scanVulnerabilitiesForRun(ctx, repo, cfg, tracker.record.RunID, "baseline", "fix", ociContext)
			if err != nil {
				if !options.EnableAgent {
					tracker.endStageFailure(stage, err, nil)
					return err
				}
				tracker.endStageSuccess(stage, map[string]any{
					"status": "deferred_to_agent",
					"error":  err.Error(),
				})

				stage = tracker.beginStage("baseline_scan_repair_loop")
				var attempts int
				before, attempts, err = runBaselineRepairLoop(ctx, repo, cfg, options, ociContext, tracker.record.RunID, "scan_baseline", err)
				if err != nil {
					tracker.endStageFailure(stage, err, nil)
					return err
				}
				agentSucceeded = true
				tracker.endStageSuccess(stage, map[string]any{
					"attempts": attempts,
					"success":  true,
				})
			} else {
				tracker.endStageSuccess(stage, map[string]any{
					"findings":            len(before.Findings),
					"ignored_without_fix": before.IgnoredWithoutFix,
					"ignored_by_policy":   before.IgnoredByPolicy,
				})
			}
		}
	}
	if before == nil {
		return wrapWithExitCode(ExitCodePatchFailed, errors.New("unable to produce baseline vulnerability report"))
	}
	tracker.addCounter("findings_before", len(before.Findings))
	logProgress("baseline findings with fix versions: %d", len(before.Findings))

	logProgress("writing scan baseline")
	stage = tracker.beginStage("write_baseline")
	if err := report.WriteBaseline(repo, before); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, nil)

	logProgress("discovering modules for verification")
	stage = tracker.beginStage("discover_verification_modules")
	verificationDirs, err := discoverVerificationDirs(repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{"modules": len(verificationDirs)})
	logProgress("discovered %d module(s)", len(verificationDirs))

	logProgress("running baseline verification checks")
	stage = tracker.beginStage("verification_baseline")
	verificationBaseline, err := runVerificationChecks(ctx, repo, verificationDirs, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	if len(verificationBaseline.Modules) > 0 {
		if err := report.WriteVerificationBaseline(repo, verificationBaseline); err != nil {
			tracker.endStageFailure(stage, err, nil)
			return err
		}
	}
	tracker.endStageSuccess(stage, map[string]any{
		"modules": len(verificationBaseline.Modules),
	})

	fileOptions := fileOptionsFromPolicy(cfg, options.UntrustedRepo)
	dockerOptions := dockerOptionsFromPolicy(cfg)
	goRuntimeOptions := goRuntimeOptionsFromPolicy(cfg)

	logProgress("applying deterministic fixes")
	stage = tracker.beginStage("apply_deterministic_fixes")
	allPatches, deterministicIssues, engineDetails, err := applyDeterministicFixes(
		ctx,
		repo,
		before.Findings,
		fileOptions,
		dockerOptions,
		goRuntimeOptions,
		options.EnableAgent,
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
	if err := applyContainerOSPatchingWithAgent(ctx, repo, cfg, before, options); err != nil {
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

	logProgress("validating post-fix state")
	stage = tracker.beginStage("validate_post_fix")
	finalValidation, validationErr := runValidationCycle(ctx, repo, cfg, verificationBaseline, verificationDirs, tracker.record.RunID, "post-fix", ociContext)
	if validationErr != nil {
		if !options.EnableAgent {
			tracker.endStageFailure(stage, validationErr, nil)
			return validationErr
		}
		issue := fmt.Sprintf("deterministic validation failed: %v", validationErr)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
		tracker.endStageSuccess(stage, map[string]any{
			"status": "deferred_to_agent",
			"error":  validationErr.Error(),
		})
	} else if finalValidation.After != nil {
		logProgress("remaining findings with fix versions: %d", len(finalValidation.After.Findings))
		tracker.endStageSuccess(stage, map[string]any{
			"remaining_findings":  len(finalValidation.After.Findings),
			"verification_errors": len(finalValidation.Verification.Regressions),
		})
	} else {
		tracker.endStageSuccess(stage, map[string]any{"remaining_findings": 0})
	}
	shouldRunAgent := shouldRunAgentRepair(options, deterministicIssues, finalValidation, validationErr)

	if shouldRunAgent {
		stage = tracker.beginStage("agent_repair_loop")
		var attempts int
		finalValidation, agentSucceeded, attempts, err = runAgentRepairLoop(
			ctx,
			repo,
			cfg,
			options,
			ociContext,
			deterministicIssues,
			before,
			finalValidation,
			validationErr,
			verificationBaseline,
			verificationDirs,
			tracker.record.RunID,
		)
		if err != nil {
			tracker.endStageFailure(stage, err, nil)
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		tracker.endStageSuccess(stage, map[string]any{
			"attempts": attempts,
			"success":  agentSucceeded,
		})
	} else {
		stage = tracker.beginStage("agent_repair_loop")
		tracker.endStageSuccess(stage, map[string]any{"status": "skipped"})
	}

	if finalValidation.After == nil {
		if validationErr != nil {
			return validationErr
		}
		return wrapWithExitCode(ExitCodePatchFailed, errors.New("unable to produce post-fix vulnerability report"))
	}

	stage = tracker.beginStage("build_summary")
	summary := report.BuildSummary(before, finalValidation.After, allPatches)
	verificationSummary := report.SummarizeVerification(finalValidation.Verification)
	if verificationSummary != nil {
		summary.Verification = verificationSummary
		summary = report.ApplyVerificationRegressions(summary, before, finalValidation.After, verificationSummary)
	}
	summary.Explanations = report.BuildFixExplanations(before, finalValidation.After, allPatches, summary.Verification)
	tracker.endStageSuccess(stage, map[string]any{
		"before":          summary.Before,
		"fixed":           summary.Fixed,
		"after":           summary.After,
		"patches":         len(summary.Patches),
		"explanations":    len(summary.Explanations),
		"unsupported":     len(summary.Unsupported),
		"verification_ok": len(finalValidation.Verification.Regressions) == 0,
	})
	tracker.addCounter("findings_after", summary.After)
	tracker.addCounter("findings_fixed", summary.Fixed)
	summaryForFailure = &summary

	stage = tracker.beginStage("write_sarif")
	if err := report.WriteSARIF(repo, finalValidation.After.Findings); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{"path": ".patchpilot/findings.sarif"})

	logProgress("writing summary report")
	stage = tracker.beginStage("write_summary")
	if err := report.WriteSummary(repo, summary); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, nil)

	stage = tracker.beginStage("print_summary")
	report.PrintSummary(os.Stdout, summary)
	if len(finalValidation.Verification.Modules) > 0 {
		verifycheck.PrintSummary(os.Stdout, finalValidation.Verification)
	}
	tracker.endStageSuccess(stage, nil)
	logProgress("fix workflow completed")

	if summary.Fixed == 0 && len(summary.Patches) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No applicable fixes were applied.")
	}

	if len(finalValidation.Verification.Regressions) > 0 {
		return verificationRegressedError(len(finalValidation.Verification.Regressions))
	}
	if agentSucceeded {
		return nil
	}
	if summary.After > 0 {
		return vulnsRemainError(summary.After)
	}
	if options.EnableAgent && len(deterministicIssues) > 0 {
		return wrapWithExitCode(ExitCodePatchFailed, fmt.Errorf("deterministic patching failed and agent loop did not resolve all issues"))
	}

	return nil
}

func loadFixFindings(repo string, options fixOptions) (*vuln.Report, error) {
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
	return nil, err
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
		"repository":         repository,
		"dockerfiles":        dockerfiles,
		"container_findings": containerFindings,
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
		RemediationPrompts: containerOSRemediationPromptGuidance(cfg),
		WorkingDirectory:   repo,
		PromptFilePath:     filepath.Join(artifactDir, "prompt.txt"),
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
