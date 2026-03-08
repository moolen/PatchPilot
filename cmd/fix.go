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
			return errors.New("--agent-command is required when --enable-agent is set")
		}
		if options.AgentMaxAttempts <= 0 {
			return errors.New("--agent-max-attempts must be greater than zero")
		}
	}

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
	restoreRegistry, err := configureRegistryFromPolicy(repo, cfg)
	if err != nil {
		return wrapWithExitCode(ExitCodePatchFailed, err)
	}
	defer restoreRegistry()

	logProgress("step 1/14: generating SBOM")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		return err
	}

	logProgress("step 2/14: scanning vulnerabilities (baseline)")
	before, err := scanVulnerabilities(ctx, repo, cfg)
	if err != nil {
		return err
	}
	logProgress("baseline findings with fix versions: %d", len(before.Findings))

	logProgress("step 3/14: writing scan baseline")
	if err := report.WriteBaseline(repo, before); err != nil {
		return err
	}

	logProgress("step 4/14: discovering modules for verification")
	verificationDirs, err := discoverVerificationDirs(repo, cfg)
	if err != nil {
		return err
	}
	logProgress("discovered %d module(s)", len(verificationDirs))

	logProgress("step 5/14: running baseline verification checks")
	verificationBaseline, err := runVerificationChecks(ctx, repo, verificationDirs, cfg)
	if err != nil {
		return err
	}
	if len(verificationBaseline.Modules) > 0 {
		if err := report.WriteVerificationBaseline(repo, verificationBaseline); err != nil {
			return err
		}
	}

	deterministicIssues := make([]string, 0)
	fileOptions := fileOptionsFromPolicy(cfg)

	logProgress("step 6/14: applying Go runtime bumps")
	runtimePatches, err := fixer.ApplyGoRuntimeFixesWithOptions(ctx, repo, fileOptions)
	if err != nil {
		if !options.EnableAgent {
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		issue := fmt.Sprintf("go runtime bumps failed: %v", err)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else {
		logProgress("applied %d Go runtime bump(s)", len(runtimePatches))
	}

	logProgress("step 7/14: applying Go module fixes")
	goPatches, err := fixer.ApplyGoModuleFixesWithOptions(ctx, repo, before.Findings, fileOptions)
	if err != nil {
		if !options.EnableAgent {
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		issue := fmt.Sprintf("go module fixes failed: %v", err)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else {
		logProgress("applied %d Go patch(es)", len(goPatches))
	}

	logProgress("step 8/14: applying Dockerfile fixes")
	dockerPatches, err := fixer.ApplyDockerfileFixesWithOptions(ctx, repo, before.Findings, dockerOptionsFromPolicy(cfg))
	if err != nil {
		if !options.EnableAgent {
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		issue := fmt.Sprintf("dockerfile fixes failed: %v", err)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else {
		logProgress("applied %d Docker patch(es)", len(dockerPatches))
	}

	logProgress("step 9/14: applying npm fixes")
	npmPatches, err := fixer.ApplyNPMFixesWithOptions(ctx, repo, before.Findings, fileOptions)
	if err != nil {
		if !options.EnableAgent {
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		issue := fmt.Sprintf("npm fixes failed: %v", err)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else {
		logProgress("applied %d npm patch(es)", len(npmPatches))
	}

	logProgress("step 10/14: applying pip fixes")
	pipPatches, err := fixer.ApplyPIPFixesWithOptions(ctx, repo, before.Findings, fileOptions)
	if err != nil {
		if !options.EnableAgent {
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		issue := fmt.Sprintf("pip fixes failed: %v", err)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else {
		logProgress("applied %d pip patch(es)", len(pipPatches))
	}

	logProgress("step 11/14: applying maven fixes")
	mavenPatches, err := fixer.ApplyMavenFixesWithOptions(ctx, repo, before.Findings, fileOptions)
	if err != nil {
		if !options.EnableAgent {
			return wrapWithExitCode(ExitCodePatchFailed, err)
		}
		issue := fmt.Sprintf("maven fixes failed: %v", err)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else {
		logProgress("applied %d maven patch(es)", len(mavenPatches))
	}

	logProgress("step 12/14: validating post-fix state")
	finalValidation, validationErr := runValidationCycle(ctx, repo, cfg, verificationBaseline, verificationDirs)
	if validationErr != nil {
		if !options.EnableAgent {
			return validationErr
		}
		issue := fmt.Sprintf("deterministic validation failed: %v", validationErr)
		deterministicIssues = append(deterministicIssues, issue)
		logProgress("%s", issue)
	} else if finalValidation.After != nil {
		logProgress("remaining findings with fix versions: %d", len(finalValidation.After.Findings))
	}

	allPatches := make([]fixer.Patch, 0, len(runtimePatches)+len(goPatches)+len(dockerPatches)+len(npmPatches)+len(pipPatches)+len(mavenPatches))
	allPatches = append(allPatches, runtimePatches...)
	allPatches = append(allPatches, goPatches...)
	allPatches = append(allPatches, dockerPatches...)
	allPatches = append(allPatches, npmPatches...)
	allPatches = append(allPatches, pipPatches...)
	allPatches = append(allPatches, mavenPatches...)

	agentSucceeded := false
	shouldRunAgent := options.EnableAgent && (len(deterministicIssues) > 0 ||
		validationErr != nil ||
		(finalValidation.After != nil && len(finalValidation.After.Findings) > 0) ||
		len(finalValidation.Verification.Regressions) > 0)

	if shouldRunAgent {
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

		loopResult, loopErr := loop.Run(ctx, agentpkg.LoopRequest{
			RepoPath:                        repo,
			WorkingDirectory:                repo,
			ArtifactDirectory:               filepath.Join(repo, ".cvefix", "agent"),
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
			return wrapWithExitCode(ExitCodePatchFailed, fmt.Errorf("run agent repair loop: %w", loopErr))
		}

		agentSucceeded = loopResult.Success
		if agentSucceeded {
			logProgress("agent repair loop succeeded after %d attempt(s)", loopResult.Attempts)
		} else {
			logProgress("agent repair loop exhausted %d attempt(s) without success", loopResult.Attempts)
			if finalValidation.After == nil && lastValidationErr != nil {
				return lastValidationErr
			}
		}
	}

	if finalValidation.After == nil {
		if validationErr != nil {
			return validationErr
		}
		return wrapWithExitCode(ExitCodePatchFailed, errors.New("unable to produce post-fix vulnerability report"))
	}

	summary := report.BuildSummary(before, finalValidation.After, allPatches)
	if len(finalValidation.Verification.Modules) > 0 {
		summary.Verification = report.SummarizeVerification(finalValidation.Verification)
	}

	logProgress("writing summary report")
	if err := report.WriteSummary(repo, summary); err != nil {
		return err
	}
	report.PrintSummary(os.Stdout, summary)
	if len(finalValidation.Verification.Modules) > 0 {
		verifycheck.PrintSummary(os.Stdout, finalValidation.Verification)
	}
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
	commands := make([]string, 0, len(standard)+len(cfg.Verification.Commands))
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
