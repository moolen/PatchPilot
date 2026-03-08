package agent

import "github.com/moolen/patchpilot/internal/agent/prompts"

// BuildPrompt returns a structured prompt for an external coding agent.
func BuildPrompt(req AttemptRequest) string {
	return prompts.Build(prompts.Request{
		RepoPath:                 req.RepoPath,
		AttemptNumber:            req.AttemptNumber,
		RemainingVulnerabilities: req.RemainingVulnerabilities,
		PreviousAttemptSummaries: req.PreviousAttemptSummaries,
		ValidationCommands:       req.ValidationCommands,
		PromptFilePath:           req.PromptFilePath,
	})
}
