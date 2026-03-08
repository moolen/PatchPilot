package cmd

import (
	"errors"
	"strings"

	"github.com/moolen/patchpilot/internal/report"
)

const (
	failureCategoryTooling      = "tooling_failure"
	failureCategoryPolicy       = "policy_blocked"
	failureCategoryNoFix        = "no_fix_available"
	failureCategoryPartialFix   = "partial_fix"
	failureCategoryVerification = "verification_regression"
	failureCategoryConfig       = "invalid_configuration"
	failureCategoryAgent        = "agent_failure"
	failureCategoryUnknown      = "unknown_failure"
)

func classifyRunFailure(err error, summary *report.Summary, agentEnabled bool, agentSucceeded bool, deterministicIssues []string) *report.RunFailure {
	if err == nil {
		return nil
	}
	exitCode := ExitCodeFromError(err)
	message := strings.TrimSpace(err.Error())
	lower := strings.ToLower(message)

	if errors.Is(err, errInvalidRuntimeConfig) {
		return &report.RunFailure{Category: failureCategoryConfig, Code: "invalid_runtime_configuration", ExitCode: exitCode, Message: message}
	}
	if strings.Contains(lower, "docker policy violation") || strings.Contains(lower, "policy violation") {
		return &report.RunFailure{Category: failureCategoryPolicy, Code: "policy_violation", ExitCode: exitCode, Message: message}
	}
	if exitCode == int(ExitCodeScanFailed) {
		return &report.RunFailure{Category: failureCategoryTooling, Code: "scan_failed", ExitCode: exitCode, Message: message}
	}
	if exitCode == int(ExitCodeVerificationRegressed) {
		return &report.RunFailure{Category: failureCategoryVerification, Code: "verification_regressed", ExitCode: exitCode, Message: message}
	}
	if exitCode == int(ExitCodePatchFailed) {
		if agentEnabled && !agentSucceeded && (len(deterministicIssues) > 0 || strings.Contains(lower, "agent")) {
			return &report.RunFailure{Category: failureCategoryAgent, Code: "agent_remediation_failed", ExitCode: exitCode, Message: message}
		}
		return &report.RunFailure{Category: failureCategoryTooling, Code: "patch_failed", ExitCode: exitCode, Message: message}
	}
	if exitCode == int(ExitCodeVulnsRemain) {
		if summary != nil {
			if summary.Fixed == 0 {
				return &report.RunFailure{Category: failureCategoryNoFix, Code: "no_automated_fix_available", ExitCode: exitCode, Message: message}
			}
			return &report.RunFailure{Category: failureCategoryPartialFix, Code: "partial_fix_applied", ExitCode: exitCode, Message: message}
		}
		return &report.RunFailure{Category: failureCategoryPartialFix, Code: "vulnerabilities_remain", ExitCode: exitCode, Message: message}
	}
	return &report.RunFailure{Category: failureCategoryUnknown, Code: "unclassified_failure", ExitCode: exitCode, Message: message}
}
