package agent

import (
	"strings"
	"testing"
)

func TestBuildPromptIncludesCoreSections(t *testing.T) {
	prompt := BuildPrompt(AttemptRequest{
		RepoPath:                 "/repo",
		AttemptNumber:            2,
		RemainingVulnerabilities: "{\"matches\":[]}",
	})

	checks := []string{
		"Repository path:",
		"/repo",
		"Goal:",
		"Remaining vulnerabilities (grype JSON):",
		"{\"matches\":[]}",
		"Previous attempts:",
		"- none",
		"Verification commands:",
		"go build ./...",
		"go test -run=^$ ./...",
		"go vet ./...",
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
		RemainingVulnerabilities: "{}",
		PreviousAttemptSummaries: []string{"attempt 1 failed"},
		ValidationCommands:       []string{"make verify"},
		PromptFilePath:           "/repo/.cvefix/agent/attempt-1/prompt.txt",
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
	if !strings.Contains(prompt, "Prompt file path: /repo/.cvefix/agent/attempt-1/prompt.txt") {
		t.Fatalf("expected prompt file path in prompt, got:\n%s", prompt)
	}
}
