package cmd

import (
	"context"
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

func applyDeterministicFixes(ctx context.Context, repo string, findings []vuln.Finding, fileOptions fixer.FileOptions, dockerOptions fixer.DockerfileOptions, allowFailures bool) ([]fixer.Patch, []string, map[string]any, error) {
	patches := make([]fixer.Patch, 0)
	issues := make([]string, 0)
	engineDetails := map[string]any{}

	for _, engine := range fixer.DefaultEngines(fileOptions, dockerOptions) {
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
		engineDetails[engine.Name()] = map[string]any{
			"status":  "applied",
			"patches": len(enginePatches),
		}
		logProgress("applied %d patch(es) via %s", len(enginePatches), engine.Name())
	}

	return patches, issues, engineDetails, nil
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
	deterministicIssues []string,
	before *vuln.Report,
	validation validationCycle,
	validationErr error,
	verificationBaseline verifycheck.Report,
	verificationDirs []string,
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
			next, err := runValidationCycle(validateCtx, repo, cfg, verificationBaseline, verificationDirs)
			if err != nil {
				lastValidationErr = err
			}

			result := agentpkg.ValidationResult{
				ValidationPassed:   next.ValidationPassed,
				VulnerabilityCount: knownVulnCount,
				Summary: fmt.Sprintf(
					"attempt=%d validation_passed=%t vulnerabilities=%d",
					attemptNumber,
					next.ValidationPassed,
					knownVulnCount,
				),
				Logs: next.Logs,
			}

			if next.After != nil {
				knownVulnCount = len(next.After.Findings)
				result.VulnerabilityCount = knownVulnCount
				result.RemainingVulnerabilities = readFileOrDefault(next.After.RawPath, "{}")
				result.Summary = fmt.Sprintf(
					"attempt=%d validation_passed=%t vulnerabilities=%d",
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
