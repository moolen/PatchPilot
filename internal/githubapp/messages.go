package githubapp

import "fmt"

func remediationStartedComment() string {
	return "PatchPilot started remediation with `patchpilot fix`."
}

func invalidCommandComment(err error) string {
	return fmt.Sprintf("Invalid PatchPilot command: %v", err)
}

func remediationFailedComment(err error) string {
	return fmt.Sprintf("PatchPilot remediation failed: %v", err)
}

func remediationBlockedComment(reason string, riskScore int) string {
	return fmt.Sprintf("PatchPilot blocked PR creation due to safety policy: %s (risk score: %d).", reason, riskScore)
}

func remediationNoChangesComment(exitCode int) string {
	return fmt.Sprintf("PatchPilot finished. No file changes were needed (PatchPilot exit code `%d`).", exitCode)
}

func remediationPRUpsertFailedComment(err error) string {
	return fmt.Sprintf("PatchPilot applied changes but failed to create PR: %v", err)
}

func remediationPRReadyComment(action, prURL string, autoMergeRequested, autoMergeEnabled bool, autoMergeErr error) string {
	message := fmt.Sprintf("PatchPilot %s remediation PR: %s", action, prURL)
	if !autoMergeRequested {
		return message
	}
	if !autoMergeEnabled {
		return message + "\n\n`--auto-merge` was requested, but PP_ENABLE_AUTO_MERGE is disabled."
	}
	if autoMergeErr != nil {
		return message + fmt.Sprintf("\n\n`--auto-merge` requested, but enabling auto-merge failed: %v", autoMergeErr)
	}
	return message + "\n\n`--auto-merge` requested and enabled."
}
