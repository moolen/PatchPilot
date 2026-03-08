package agent

import (
	"fmt"
	"strings"
)

var defaultValidationCommands = []string{
	"go build ./...",
	"go test -run=^$ ./...",
	"go vet ./...",
}

// BuildPrompt returns a structured prompt for an external coding agent.
func BuildPrompt(req AttemptRequest) string {
	var builder strings.Builder

	builder.WriteString("Repository path:\n")
	builder.WriteString(req.RepoPath)
	builder.WriteString("\n\n")

	builder.WriteString("Goal:\n")
	builder.WriteString("Fix vulnerabilities with minimal changes and keep the build passing.\n\n")

	builder.WriteString("Constraints:\n")
	builder.WriteString("- prioritize minimal dependency upgrades\n")
	builder.WriteString("- prefer fixing vulnerabilities over introducing new functionality\n")
	builder.WriteString("- ensure repository builds successfully\n\n")

	builder.WriteString("Remaining vulnerabilities (grype JSON):\n")
	builder.WriteString("```json\n")
	remaining := strings.TrimSpace(req.RemainingVulnerabilities)
	if remaining == "" {
		builder.WriteString("{}")
	} else {
		builder.WriteString(remaining)
	}
	builder.WriteString("\n```\n\n")

	builder.WriteString("Previous attempts:\n")
	if len(req.PreviousAttemptSummaries) == 0 {
		builder.WriteString("- none\n")
	} else {
		for _, summary := range req.PreviousAttemptSummaries {
			summary = strings.TrimSpace(summary)
			if summary == "" {
				continue
			}
			builder.WriteString("- ")
			builder.WriteString(summary)
			builder.WriteString("\n")
		}
	}
	builder.WriteString("\n")

	builder.WriteString("Verification commands:\n")
	commands := req.ValidationCommands
	if len(commands) == 0 {
		commands = defaultValidationCommands
	}
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		builder.WriteString("- ")
		builder.WriteString(command)
		builder.WriteString("\n")
	}
	builder.WriteString("\n")

	builder.WriteString("Instructions to the agent:\n")
	builder.WriteString("- modify the repository directly\n")
	builder.WriteString("- run verification commands after each change\n")
	builder.WriteString("- iterate until vulnerabilities are fixed and build passes\n")
	builder.WriteString("- do not stop until verification commands succeed or attempts exhausted\n\n")

	builder.WriteString(fmt.Sprintf("Attempt number: %d\n", req.AttemptNumber))
	if strings.TrimSpace(req.PromptFilePath) != "" {
		builder.WriteString("Prompt file path: ")
		builder.WriteString(req.PromptFilePath)
		builder.WriteString("\n")
	}

	return builder.String()
}
