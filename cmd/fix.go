package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

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
	shouldRunAgent := shouldRunAgentRepair(options, deterministicIssues, finalValidation, validationErr)

	if shouldRunAgent {
		stage = tracker.beginStage("agent_repair_loop")
		var attempts int
		finalValidation, agentSucceeded, attempts, err = runAgentRepairLoop(
			ctx,
			repo,
			cfg,
			options,
			deterministicIssues,
			before,
			finalValidation,
			validationErr,
			verificationBaseline,
			verificationDirs,
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
