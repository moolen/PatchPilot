package agent

import (
	"strings"
	"testing"
)

func TestBuildPromptIncludesCoreSections(t *testing.T) {
	prompt, err := BuildPrompt(AttemptRequest{
		RepoPath:          "/repo",
		AttemptNumber:     2,
		TaskKind:          TaskKindFixVulnerabilities,
		Goal:              "Fix vulnerabilities with minimal changes and keep the build passing.",
		CurrentStateLabel: "Remaining vulnerabilities (grype JSON)",
		CurrentState:      "{\"matches\":[]}",
	})
	if err != nil {
		t.Fatalf("BuildPrompt returned error: %v", err)
	}

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
	prompt, err := BuildPrompt(AttemptRequest{
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
	})
	if err != nil {
		t.Fatalf("BuildPrompt returned error: %v", err)
	}

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
}

func TestBuildPromptAppliesRemediationPromptsSequentially(t *testing.T) {
	prompt, err := BuildPrompt(AttemptRequest{
		RepoPath:                 "/repo",
		AttemptNumber:            3,
		TaskKind:                 TaskKindBaselineScanRepair,
		Goal:                     "Repair the repository so the baseline scan succeeds.",
		CurrentStateLabel:        "Current baseline state",
		CurrentState:             "{}",
		FailureStage:             "scan_baseline",
		FailureError:             "artifact target build failed",
		PreviousAttemptSummaries: []string{"attempt 2 failed"},
		ValidationPlan:           []string{"make verify"},
		Constraints:              []string{"do not disable artifact scanning"},
		RemediationPrompts: []RemediationPrompt{
			{Mode: "extend", Template: "Org guidance for {{ .RepoPath }}"},
			{Mode: "replace", Template: "REPLACED\n{{ .PromptSoFar }}\nFailure={{ .FailureStage }}"},
			{Mode: "extend", Template: "Attempt {{ .AttemptNumber }}"},
		},
	})
	if err != nil {
		t.Fatalf("BuildPrompt returned error: %v", err)
	}

	if !strings.Contains(prompt, "REPLACED") {
		t.Fatalf("expected replace prompt output, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Org guidance for /repo") {
		t.Fatalf("expected extend prompt output to survive replace via PromptSoFar, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Failure=scan_baseline") {
		t.Fatalf("expected failure stage variable in prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Attempt 3") {
		t.Fatalf("expected trailing extend prompt output, got:\n%s", prompt)
	}
}

func TestBuildPromptReturnsErrorForInvalidRemediationTemplate(t *testing.T) {
	_, err := BuildPrompt(AttemptRequest{
		RepoPath: "/repo",
		RemediationPrompts: []RemediationPrompt{
			{Mode: "extend", Template: "{{ .MissingVariable }}"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid remediation template")
	}
	if !strings.Contains(err.Error(), "render remediation prompt 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}
