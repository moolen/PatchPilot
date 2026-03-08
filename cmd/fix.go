package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moolen/patchpilot/fixer"
	agentpkg "github.com/moolen/patchpilot/pkg/agent"
	"github.com/moolen/patchpilot/policy"
	"github.com/moolen/patchpilot/report"
	"github.com/moolen/patchpilot/verifycheck"
	"github.com/moolen/patchpilot/vuln"
)

type fixOptions struct {
	EnableAgent      bool
	AgentCommand     string
	AgentMaxAttempts int
	AgentArtifactDir string
	JSONOutput       bool
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

	stage := tracker.beginStage("configure_registry")
	restoreRegistry, err := configureRegistryFromPolicy(repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	tracker.endStageSuccess(stage, nil)
	defer restoreRegistry()

	logProgress("generating baseline SBOM")
	stage = tracker.beginStage("generate_baseline_sbom")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, nil)

	logProgress("scanning baseline vulnerabilities")
	stage = tracker.beginStage("scan_baseline")
	before, err := scanVulnerabilities(ctx, repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{
		"findings":            len(before.Findings),
		"ignored_without_fix": before.IgnoredWithoutFix,
		"ignored_by_policy":   before.IgnoredByPolicy,
	})
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

	fileOptions := fileOptionsFromPolicy(cfg)
	dockerOptions := dockerOptionsFromPolicy(cfg)

	logProgress("applying deterministic fixes")
	stage = tracker.beginStage("apply_deterministic_fixes")
	allPatches := make([]fixer.Patch, 0)
	engineDetails := map[string]any{}
	for _, engine := range fixer.DefaultEngines(fileOptions, dockerOptions) {
		patches, applyErr := engine.Apply(ctx, repo, before.Findings)
		if applyErr != nil {
			if !options.EnableAgent {
				tracker.endStageFailure(stage, applyErr, map[string]any{"engine": engine.Name()})
				return wrapWithExitCode(ExitCodePatchFailed, applyErr)
			}
			issue := fmt.Sprintf("%s fixes failed: %v", engine.Name(), applyErr)
			deterministicIssues = append(deterministicIssues, issue)
			engineDetails[engine.Name()] = map[string]any{
				"status": "failed",
				"error":  applyErr.Error(),
			}
			logProgress("%s", issue)
			continue
		}
		allPatches = append(allPatches, patches...)
		engineDetails[engine.Name()] = map[string]any{
			"status":  "applied",
			"patches": len(patches),
		}
		logProgress("applied %d patch(es) via %s", len(patches), engine.Name())
	}
	tracker.endStageSuccess(stage, map[string]any{
		"engines":       engineDetails,
		"patches_total": len(allPatches),
		"issues":        len(deterministicIssues),
	})

	logProgress("validating post-fix state")
	stage = tracker.beginStage("validate_post_fix")
	finalValidation, validationErr := runValidationCycle(ctx, repo, cfg, verificationBaseline, verificationDirs)
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
	shouldRunAgent := options.EnableAgent && (len(deterministicIssues) > 0 ||
		validationErr != nil ||
		(finalValidation.After != nil && len(finalValidation.After.Findings) > 0) ||
		len(finalValidation.Verification.Regressions) > 0)

	if shouldRunAgent {
		stage = tracker.beginStage("agent_repair_loop")
		logProgress("deterministic phase incomplete, starting agent repair loop")

		initialVulnCount := len(before.Findings)
		initialVulnJSON := readFileOrDefault(before.RawPath, "{}")
		if finalValidation.After != nil {
			initialVulnCount = len(finalValidation.After.Findings)
			if data := readFileOrDefault(finalValidation.After.RawPath, ""); strings.TrimSpace(data) != "" {
				initialVulnJSON = data
			}
		}
		knownVulnCount := initialVulnCount
		lastValidationErr := validationErr

		runner := agentpkg.Runner{
			Command: options.AgentCommand,
			Stdout:  os.Stderr,
			Stderr:  os.Stderr,
		}
		loop := agentpkg.Loop{Agent: runner}

		artifactDir := strings.TrimSpace(options.AgentArtifactDir)
		if artifactDir == "" {
			artifactDir = filepath.Join(repo, ".cvefix", "agent")
		} else if !filepath.IsAbs(artifactDir) {
			artifactDir = filepath.Join(repo, artifactDir)
		}

		loopResult, loopErr := loop.Run(ctx, agentpkg.LoopRequest{
			RepoPath:                        repo,
			WorkingDirectory:                repo,
			ArtifactDirectory:               artifactDir,
			MaxAttempts:                     options.AgentMaxAttempts,
			InitialVulnerabilityCount:       initialVulnCount,
			InitialRemainingVulnerabilities: initialVulnJSON,
			PreviousAttemptSummaries:        deterministicIssues,
			ValidationCommands:              validationCommandsForPrompt(cfg),
			Validate: func(validateCtx context.Context, attemptNumber int) (agentpkg.ValidationResult, error) {
				validation, err := runValidationCycle(validateCtx, repo, cfg, verificationBaseline, verificationDirs)
				if err != nil {
					lastValidationErr = err
				}

				result := agentpkg.ValidationResult{
					ValidationPassed:   validation.ValidationPassed,
					VulnerabilityCount: knownVulnCount,
					Summary: fmt.Sprintf(
						"attempt=%d validation_passed=%t vulnerabilities=%d",
						attemptNumber,
						validation.ValidationPassed,
						knownVulnCount,
					),
					Logs: validation.Logs,
				}

				if validation.After != nil {
					knownVulnCount = len(validation.After.Findings)
					result.VulnerabilityCount = knownVulnCount
					result.RemainingVulnerabilities = readFileOrDefault(validation.After.RawPath, "{}")
					result.Summary = fmt.Sprintf(
						"attempt=%d validation_passed=%t vulnerabilities=%d",
						attemptNumber,
						validation.ValidationPassed,
						knownVulnCount,
					)
					finalValidation = validation
				}

				return result, err
			},
		})
		if loopErr != nil {
			tracker.endStageFailure(stage, loopErr, nil)
			return wrapWithExitCode(ExitCodePatchFailed, fmt.Errorf("run agent repair loop: %w", loopErr))
		}

		agentSucceeded = loopResult.Success
		if agentSucceeded {
			logProgress("agent repair loop succeeded after %d attempt(s)", loopResult.Attempts)
			tracker.endStageSuccess(stage, map[string]any{
				"attempts": loopResult.Attempts,
				"success":  true,
			})
		} else {
			logProgress("agent repair loop exhausted %d attempt(s) without success", loopResult.Attempts)
			tracker.endStageSuccess(stage, map[string]any{
				"attempts": loopResult.Attempts,
				"success":  false,
			})
			if finalValidation.After == nil && lastValidationErr != nil {
				return lastValidationErr
			}
		}
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
	if len(finalValidation.Verification.Modules) > 0 {
		summary.Verification = report.SummarizeVerification(finalValidation.Verification)
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
		fmt.Fprintln(os.Stdout, "No applicable fixes were applied.")
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

func runValidationCycle(ctx context.Context, repo string, cfg *policy.Config, verificationBaseline verifycheck.Report, verificationDirs []string) (validationCycle, error) {
	result := validationCycle{}
	var logs strings.Builder

	logs.WriteString("generate SBOM\n")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		result.Logs = logs.String()
		return result, err
	}

	logs.WriteString("scan vulnerabilities\n")
	after, err := scanVulnerabilities(ctx, repo, cfg)
	if err != nil {
		result.Logs = logs.String()
		return result, err
	}
	result.After = after
	fmt.Fprintf(&logs, "remaining findings with fix versions: %d\n", len(after.Findings))

	if len(verificationBaseline.Modules) == 0 {
		result.ValidationPassed = true
		result.Logs = strings.TrimSpace(logs.String())
		return result, nil
	}

	logs.WriteString("run verification checks\n")
	verificationAfter, err := runVerificationChecks(ctx, repo, verificationDirs, cfg)
	if err != nil {
		result.Logs = strings.TrimSpace(logs.String())
		return result, err
	}
	verificationAfter.Regressions = verifycheck.Compare(verificationBaseline, verificationAfter)
	if err := report.WriteVerification(repo, verificationAfter); err != nil {
		result.Logs = strings.TrimSpace(logs.String())
		return result, err
	}
	result.Verification = verificationAfter

	verifySummary := verifycheck.Summarize(verificationAfter)
	result.ValidationPassed = verifySummary.Failed == 0 && verifySummary.Timeouts == 0 && len(verificationAfter.Regressions) == 0

	verifycheck.PrintSummary(&logs, verificationAfter)
	result.Logs = strings.TrimSpace(logs.String())
	return result, nil
}

func readFileOrDefault(path, fallback string) string {
	if strings.TrimSpace(path) == "" {
		return fallback
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func validationCommandsForPrompt(cfg *policy.Config) []string {
	standard := []string{"go build ./...", "go test -run=^$ ./...", "go vet ./..."}
	if cfg == nil || len(cfg.Verification.Commands) == 0 {
		return standard
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Verification.Mode))
	commands := make([]string, 0)
	if mode != policy.VerificationModeReplace {
		commands = append(commands, standard...)
	}
	for _, command := range cfg.Verification.Commands {
		run := strings.TrimSpace(command.Run)
		if run == "" {
			continue
		}
		commands = append(commands, run)
	}
	if len(commands) == 0 {
		return standard
	}
	return commands
}
