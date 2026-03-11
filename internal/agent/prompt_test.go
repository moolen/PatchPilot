package agent

import (
	"strings"
	"testing"
)

func TestBuildPromptIncludesCoreSections(t *testing.T) {
	prompt := BuildPrompt(AttemptRequest{
		RepoPath:          "/repo",
		AttemptNumber:     2,
		TaskKind:          TaskKindFixVulnerabilities,
		Goal:              "Fix vulnerabilities with minimal changes and keep the build passing.",
		CurrentStateLabel: "Remaining vulnerabilities (grype JSON)",
		CurrentState:      "{\"matches\":[]}",
	})

	checks := []string{
		"Repository path:",
		"/repo",
		"Task:",
		TaskKindFixVulnerabilities,
		"Goal:",
		"Remaining vulnerabilities (grype JSON):",
		"{\"matches\":[]}",
		"Previous attempts:",
		"- none",
		"Validation plan:",
		"go build ./...",
		"go test -run=^$ ./...",
		"Constraints:",
		"do not modify .patchpilot/ artifacts or .patchpilot.yaml",
		"Attempt number: 2",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Fatalf("expected prompt to contain %q, got:\n%s", check, prompt)
		}
	}
}

func TestBuildPromptUsesProvidedCommandsAndAttemptHistory(t *testing.T) {
	prompt := BuildPrompt(AttemptRequest{
		RepoPath:                 "/repo",
		AttemptNumber:            1,
		TaskKind:                 TaskKindBaselineScanRepair,
		Goal:                     "Repair the repository so the baseline scan succeeds.",
		CurrentStateLabel:        "Current baseline state",
		CurrentState:             "{}",
		FailureStage:             "scan_baseline",
		FailureError:             "artifact target build failed",
		PreviousAttemptSummaries: []string{"attempt 1 failed"},
		ValidationPlan:           []string{"make verify"},
		Constraints:              []string{"do not disable artifact scanning"},
		CustomGuidance:           []string{"follow org escalation policy"},
	})

	if !strings.Contains(prompt, "- attempt 1 failed") {
		t.Fatalf("expected previous attempts in prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- make verify") {
		t.Fatalf("expected custom validation command in prompt, got:\n%s", prompt)
	}
	if strings.Contains(prompt, "go build ./...") {
		t.Fatalf("expected default commands to be omitted when explicit commands are set, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- failing stage: scan_baseline") {
		t.Fatalf("expected failure stage in prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- last error: artifact target build failed") {
		t.Fatalf("expected failure error in prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- do not disable artifact scanning") {
		t.Fatalf("expected custom constraints in prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Custom remediation guidance:") {
		t.Fatalf("expected custom guidance section, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- follow org escalation policy") {
		t.Fatalf("expected custom guidance entry in prompt, got:\n%s", prompt)
	}
}
