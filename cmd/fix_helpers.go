package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agentpkg "github.com/moolen/patchpilot/internal/agent"
	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/report"
	"github.com/moolen/patchpilot/internal/verifycheck"
	"github.com/moolen/patchpilot/internal/vuln"
)

type baselineScanCycle struct {
	Baseline    *vuln.Report
	FailedStage string
	Logs        string
}

func applyDeterministicFixes(ctx context.Context, repo string, findings []vuln.Finding, fileOptions fixer.FileOptions, dockerOptions fixer.DockerfileOptions, goRuntimeOptions fixer.GoRuntimeOptions, allowFailures bool) ([]fixer.Patch, []string, map[string]any, error) {
	return applyDeterministicFixesWithPolicy(ctx, repo, nil, findings, fileOptions, dockerOptions, goRuntimeOptions, allowFailures)
}

func applyDeterministicFixesWithPolicy(ctx context.Context, repo string, cfg *policy.Config, findings []vuln.Finding, fileOptions fixer.FileOptions, dockerOptions fixer.DockerfileOptions, goRuntimeOptions fixer.GoRuntimeOptions, allowFailures bool) ([]fixer.Patch, []string, map[string]any, error) {
	engines := filterFixEnginesByPolicy(cfg, fixer.DefaultEngines(fileOptions, dockerOptions, goRuntimeOptions))
	return applyFixEngines(ctx, repo, findings, engines, allowFailures)
}

func applyFixEngines(ctx context.Context, repo string, findings []vuln.Finding, engines []fixer.Engine, allowFailures bool) ([]fixer.Patch, []string, map[string]any, error) {
	patches := make([]fixer.Patch, 0)
	issues := make([]string, 0)
	engineDetails := map[string]any{}

	for _, engine := range engines {
		logProgress("running %s fixer", engine.Name())
		enginePatches, applyErr := engine.Apply(ctx, repo, findings)
		if applyErr != nil {
			if !allowFailures {
				return nil, nil, nil, applyErr
			}
			issue := fmt.Sprintf("%s fixes failed: %v", engine.Name(), applyErr)
			issues = append(issues, issue)
			engineDetails[engine.Name()] = map[string]any{
				"status": "failed",
				"error":  applyErr.Error(),
			}
			logProgress("%s", issue)
			continue
		}
		patches = append(patches, enginePatches...)
		if len(enginePatches) == 0 {
			engineDetails[engine.Name()] = map[string]any{
				"status":  "no_changes",
				"patches": 0,
			}
			logProgress("%s fixer made no changes", engine.Name())
			continue
		}
		engineDetails[engine.Name()] = map[string]any{
			"status":  "applied",
			"patches": len(enginePatches),
		}
		logProgress("%s fixer applied %d patch(es)", engine.Name(), len(enginePatches))
	}

	return patches, issues, engineDetails, nil
}

func filterFixEnginesByPolicy(cfg *policy.Config, engines []fixer.Engine) []fixer.Engine {
	filtered := make([]fixer.Engine, 0, len(engines))
	for _, engine := range engines {
		ecosystem, ok := fixEcosystemForEngine(engine.Name())
		if !ok {
			filtered = append(filtered, engine)
			continue
		}
		if cfg != nil {
			if !cfg.IsFixEcosystemEnabled(ecosystem) {
				logProgress("skipping %s fixer: ecosystem %q disabled by policy", engine.Name(), ecosystem)
				continue
			}
			filtered = append(filtered, engine)
			continue
		}
		if ecosystem == policy.FixEcosystemGitHubActions {
			logProgress("skipping %s fixer: ecosystem %q disabled by default", engine.Name(), ecosystem)
			continue
		}
		filtered = append(filtered, engine)
	}
	return filtered
}

func fixEcosystemForEngine(engineName string) (string, bool) {
	switch strings.TrimSpace(engineName) {
	case "go_runtime", "go_modules":
		return policy.FixEcosystemGoMod, true
	case "docker":
		return policy.FixEcosystemDocker, true
	case "github_actions":
		return policy.FixEcosystemGitHubActions, true
	case "npm":
		return policy.FixEcosystemNPM, true
	case "pip":
		return policy.FixEcosystemPIP, true
	case "maven":
		return policy.FixEcosystemMaven, true
	case "gradle":
		return policy.FixEcosystemGradle, true
	case "cargo":
		return policy.FixEcosystemCargo, true
	case "nuget":
		return policy.FixEcosystemNuGet, true
	case "composer":
		return policy.FixEcosystemComposer, true
	default:
		return "", false
	}
}

func shouldRunAgentRepair(options fixOptions, deterministicIssues []string, validation validationCycle, validationErr error) bool {
	if !options.EnableAgent {
		return false
	}
	return len(deterministicIssues) > 0 ||
		validationErr != nil ||
		(validation.After != nil && len(validation.After.Findings) > 0) ||
		len(validation.Verification.Regressions) > 0
}

func runAgentRepairLoop(
	ctx context.Context,
	repo string,
	cfg *policy.Config,
	options fixOptions,
	ociContext ociScanContext,
	deterministicIssues []string,
	before *vuln.Report,
	validation validationCycle,
	validationErr error,
	verificationBaseline verifycheck.Report,
	verificationDirs []string,
	runID string,
) (validationCycle, bool, int, error) {
	logProgress("deterministic phase incomplete, starting agent repair loop")

	initialVulnCount := len(before.Findings)
	initialVulnJSON := readFileOrDefault(before.RawPath, "{}")
	if validation.After != nil {
		initialVulnCount = len(validation.After.Findings)
		if data := readFileOrDefault(validation.After.RawPath, ""); strings.TrimSpace(data) != "" {
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

	artifactDir := agentArtifactDir(repo, options.AgentArtifactDir, "")

	loopResult, loopErr := loop.Run(ctx, agentpkg.LoopRequest{
		RepoPath:                 repo,
		WorkingDirectory:         repo,
		ArtifactDirectory:        artifactDir,
		MaxAttempts:              options.AgentMaxAttempts,
		TaskKind:                 agentpkg.TaskKindFixVulnerabilities,
		Goal:                     "Fix vulnerabilities with minimal changes and keep the build passing.",
		CurrentStateLabel:        "Remaining vulnerabilities (grype JSON)",
		Constraints:              fixPromptConstraints(),
		RemediationPrompts:       fixRemediationPromptGuidance(cfg, deterministicIssues, validation, validationErr),
		InitialProgressCount:     initialVulnCount,
		InitialCurrentState:      initialVulnJSON,
		PreviousAttemptSummaries: deterministicIssues,
		ValidationPlan:           validationCommandsForPrompt(cfg),
		Validate: func(validateCtx context.Context, attemptNumber int) (agentpkg.ValidationResult, error) {
			phase := fmt.Sprintf("agent-attempt-%d", attemptNumber)
			next, err := runValidationCycle(validateCtx, repo, cfg, verificationBaseline, verificationDirs, runID, phase, ociContext)
			if err != nil {
				lastValidationErr = err
			}

			result := agentpkg.ValidationResult{
				ValidationPassed: next.ValidationPassed,
				GoalMet:          false,
				ProgressCount:    knownVulnCount,
				Summary: fmt.Sprintf(
					"attempt=%d validation_passed=%t remaining_vulnerabilities=%d",
					attemptNumber,
					next.ValidationPassed,
					knownVulnCount,
				),
				Logs: next.Logs,
			}

			if next.After != nil {
				knownVulnCount = len(next.After.Findings)
				result.ProgressCount = knownVulnCount
				result.CurrentState = readFileOrDefault(next.After.RawPath, "{}")
				result.GoalMet = next.ValidationPassed && knownVulnCount == 0
				result.Summary = fmt.Sprintf(
					"attempt=%d validation_passed=%t remaining_vulnerabilities=%d",
					attemptNumber,
					next.ValidationPassed,
					knownVulnCount,
				)
				validation = next
			}

			return result, err
		},
	})
	if loopErr != nil {
		return validation, false, 0, fmt.Errorf("run agent repair loop: %w", loopErr)
	}

	if loopResult.Success {
		logProgress("agent repair loop succeeded after %d attempt(s)", loopResult.Attempts)
		return validation, true, loopResult.Attempts, nil
	}

	logProgress("agent repair loop exhausted %d attempt(s) without success", loopResult.Attempts)
	if validation.After == nil && lastValidationErr != nil {
		return validation, false, loopResult.Attempts, lastValidationErr
	}
	return validation, false, loopResult.Attempts, nil
}

func runBaselineRepairLoop(
	ctx context.Context,
	repo string,
	cfg *policy.Config,
	options fixOptions,
	ociContext ociScanContext,
	runID string,
	failedStage string,
	initialErr error,
) (*vuln.Report, int, error) {
	logProgress("baseline scan incomplete, starting agent repair loop")

	runner := agentpkg.Runner{
		Command: options.AgentCommand,
		Stdout:  os.Stderr,
		Stderr:  os.Stderr,
	}
	loop := agentpkg.Loop{Agent: runner}

	lastStage := strings.TrimSpace(failedStage)
	lastErr := initialErr
	var baseline *vuln.Report

	previousSummaries := []string{}
	if lastStage != "" || lastErr != nil {
		previousSummaries = append(previousSummaries, summarizeBaselineFailure(lastStage, lastErr))
	}

	loopResult, loopErr := loop.Run(ctx, agentpkg.LoopRequest{
		RepoPath:                 repo,
		WorkingDirectory:         repo,
		ArtifactDirectory:        agentArtifactDir(repo, options.AgentArtifactDir, "baseline-scan"),
		MaxAttempts:              options.AgentMaxAttempts,
		TaskKind:                 agentpkg.TaskKindBaselineScanRepair,
		Goal:                     "Repair the repository so PatchPilot can complete its baseline vulnerability scan.",
		CurrentStateLabel:        "Current baseline scan state",
		Constraints:              baselinePromptConstraints(),
		RemediationPrompts:       baselineRemediationPromptGuidance(cfg, lastStage),
		InitialProgressCount:     1,
		InitialCurrentState:      buildBaselineAgentState(cfg, lastStage, lastErr, nil),
		PreviousAttemptSummaries: previousSummaries,
		ValidationPlan:           baselineValidationPlan(cfg),
		Validate: func(validateCtx context.Context, attemptNumber int) (agentpkg.ValidationResult, error) {
			phase := fmt.Sprintf("baseline-agent-attempt-%d", attemptNumber)
			next, err := runBaselineScanCycle(validateCtx, repo, cfg, runID, phase, ociContext)
			if err != nil {
				lastErr = err
				if strings.TrimSpace(next.FailedStage) != "" {
					lastStage = next.FailedStage
				}
			}

			result := agentpkg.ValidationResult{
				ValidationPassed: err == nil,
				GoalMet:          err == nil && next.Baseline != nil,
				ProgressCount:    1,
				CurrentState:     buildBaselineAgentState(cfg, next.FailedStage, err, next.Baseline),
				Summary:          fmt.Sprintf("attempt=%d baseline_ready=%t", attemptNumber, err == nil && next.Baseline != nil),
				Logs:             next.Logs,
			}
			if next.Baseline != nil && err == nil {
				baseline = next.Baseline
				result.ProgressCount = 0
				result.Summary = fmt.Sprintf(
					"attempt=%d baseline_ready=true findings=%d",
					attemptNumber,
					len(next.Baseline.Findings),
				)
			}
			return result, err
		},
	})
	if loopErr != nil {
		return nil, 0, fmt.Errorf("run baseline repair loop: %w", loopErr)
	}

	if loopResult.Success && baseline != nil {
		logProgress("baseline repair loop succeeded after %d attempt(s)", loopResult.Attempts)
		return baseline, loopResult.Attempts, nil
	}

	logProgress("baseline repair loop exhausted %d attempt(s) without success", loopResult.Attempts)
	if lastErr != nil {
		return nil, loopResult.Attempts, lastErr
	}
	return nil, loopResult.Attempts, errors.New("baseline scan did not succeed within agent attempts")
}

func runBaselineScanCycle(ctx context.Context, repo string, cfg *policy.Config, runID, phase string, ociContext ociScanContext) (baselineScanCycle, error) {
	result := baselineScanCycle{}
	var logs strings.Builder

	result.FailedStage = "generate_baseline_sbom"
	logs.WriteString("generate baseline SBOM\n")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		result.Logs = strings.TrimSpace(logs.String())
		return result, err
	}

	result.FailedStage = "scan_baseline"
	logs.WriteString("scan baseline vulnerabilities\n")
	baseline, err := scanVulnerabilitiesForRun(ctx, repo, cfg, runID, phase, "fix", ociContext)
	if err != nil {
		result.Logs = strings.TrimSpace(logs.String())
		return result, err
	}

	result.Baseline = baseline
	result.FailedStage = ""
	_, _ = fmt.Fprintf(&logs, "baseline findings with fix versions: %d\n", len(baseline.Findings))
	result.Logs = strings.TrimSpace(logs.String())
	return result, nil
}

func runValidationCycle(ctx context.Context, repo string, cfg *policy.Config, verificationBaseline verifycheck.Report, verificationDirs []string, runID, phase string, ociContext ociScanContext) (validationCycle, error) {
	result := validationCycle{}
	var logs strings.Builder

	logs.WriteString("generate SBOM\n")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		result.Logs = logs.String()
		return result, err
	}

	logs.WriteString("scan vulnerabilities\n")
	after, err := scanVulnerabilitiesForRun(ctx, repo, cfg, runID, phase, "fix", ociContext)
	if err != nil {
		result.Logs = logs.String()
		return result, err
	}
	result.After = after
	_, _ = fmt.Fprintf(&logs, "remaining findings with fix versions: %d\n", len(after.Findings))

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

func agentArtifactDir(repo, configured, suffix string) string {
	artifactDir := strings.TrimSpace(configured)
	if artifactDir == "" {
		artifactDir = filepath.Join(repo, ".patchpilot", "agent")
	} else if !filepath.IsAbs(artifactDir) {
		artifactDir = filepath.Join(repo, artifactDir)
	}
	if strings.TrimSpace(suffix) == "" {
		return artifactDir
	}
	return filepath.Join(artifactDir, suffix)
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
	_ = cfg
	return []string{"go build ./...", "go test -run=^$ ./..."}
}

func baselineRemediationPromptGuidance(cfg *policy.Config, failedStage string) []agentpkg.RemediationPrompt {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	prompts := make([]agentpkg.RemediationPrompt, 0)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.All)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.BaselineScanRepair.All)

	switch strings.TrimSpace(failedStage) {
	case "generate_baseline_sbom":
		prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.BaselineScanRepair.GenerateBaselineSBOM)
	case "scan_baseline":
		prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.BaselineScanRepair.ScanBaseline)
	}
	if len(prompts) == 0 {
		return nil
	}
	return prompts
}

func fixRemediationPromptGuidance(
	cfg *policy.Config,
	deterministicIssues []string,
	validation validationCycle,
	validationErr error,
) []agentpkg.RemediationPrompt {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	prompts := make([]agentpkg.RemediationPrompt, 0)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.All)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.All)
	if len(deterministicIssues) > 0 {
		prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.DeterministicFixFailed)
	}
	if validationErr != nil {
		prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.ValidationFailed)
	}
	if validation.After != nil && len(validation.After.Findings) > 0 {
		prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.VulnerabilitiesRemaining)
	}
	if len(validation.Verification.Regressions) > 0 {
		prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.VerificationRegressed)
	}
	if len(prompts) == 0 {
		return nil
	}
	return prompts
}

func containerOSRemediationPromptGuidance(cfg *policy.Config) []agentpkg.RemediationPrompt {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	prompts := make([]agentpkg.RemediationPrompt, 0)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.All)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.All)
	prompts = appendPromptGuidance(prompts, seen, cfg.Agent.RemediationPrompts.FixVulnerabilities.ContainerOSPatching)
	if len(prompts) == 0 {
		return nil
	}
	return prompts
}

func appendPromptGuidance(
	dst []agentpkg.RemediationPrompt,
	seen map[string]struct{},
	extra []policy.AgentRemediationPromptPolicy,
) []agentpkg.RemediationPrompt {
	for _, prompt := range extra {
		prompt.Mode = strings.TrimSpace(prompt.Mode)
		prompt.Template = strings.TrimSpace(prompt.Template)
		if prompt.Mode == "" || prompt.Template == "" {
			continue
		}
		key := prompt.Mode + "\x00" + prompt.Template
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, agentpkg.RemediationPrompt{
			Mode:     prompt.Mode,
			Template: prompt.Template,
		})
	}
	return dst
}

func fixPromptConstraints() []string {
	return []string{
		"prioritize minimal dependency upgrades and repository-specific changes",
		"preserve the repository's intended build and verification behavior",
		"do not modify .patchpilot/ artifacts or .patchpilot.yaml",
	}
}

func baselinePromptConstraints() []string {
	return []string{
		"prefer minimal, repository-specific fixes",
		"preserve the repository's intended build and scan behavior",
		"do not disable scanning or external OCI image scanning to make the baseline pass",
		"if external OCI scans fail, fix the relevant image mappings, credentials, or Dockerfile targets instead of bypassing scanning",
		"do not modify .patchpilot/ artifacts or .patchpilot.yaml",
	}
}

func baselineValidationPlan(cfg *policy.Config) []string {
	plan := []string{
		"generate the repository SBOM",
		"run the repository vulnerability scan",
	}
	if cfg != nil && len(cfg.OCI.ExternalImages) > 0 {
		plan = append(plan,
			"resolve configured external OCI image mappings",
			"pull and scan mapped external OCI images",
		)
	}
	return plan
}

func buildBaselineAgentState(cfg *policy.Config, failedStage string, lastErr error, baseline *vuln.Report) string {
	state := map[string]any{
		"baseline_ready": strings.TrimSpace(failedStage) == "" && lastErr == nil && baseline != nil,
	}
	if strings.TrimSpace(failedStage) != "" {
		state["failed_stage"] = failedStage
	}
	if lastErr != nil {
		state["last_error"] = lastErr.Error()
	}
	if baseline != nil {
		state["findings_with_fix_versions"] = len(baseline.Findings)
	}
	if cfg != nil {
		state["external_oci_images_configured"] = len(cfg.OCI.ExternalImages)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

func summarizeBaselineFailure(stage string, err error) string {
	stage = strings.TrimSpace(stage)
	switch {
	case stage == "" && err == nil:
		return "baseline scan failed"
	case stage == "":
		return fmt.Sprintf("baseline scan failed: %v", err)
	case err == nil:
		return fmt.Sprintf("baseline scan failed at stage %s", stage)
	default:
		return fmt.Sprintf("baseline scan failed at stage %s: %v", stage, err)
	}
}
