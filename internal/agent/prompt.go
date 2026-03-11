package agent

import "github.com/moolen/patchpilot/internal/agent/prompts"

// BuildPrompt returns a structured prompt for an external coding agent.
func BuildPrompt(req AttemptRequest) string {
	return prompts.Build(prompts.Request{
		RepoPath:                 req.RepoPath,
		AttemptNumber:            req.AttemptNumber,
		TaskKind:                 req.TaskKind,
		Goal:                     req.Goal,
		CurrentStateLabel:        req.CurrentStateLabel,
		CurrentState:             req.CurrentState,
		FailureStage:             req.FailureStage,
		FailureError:             req.FailureError,
		PreviousAttemptSummaries: req.PreviousAttemptSummaries,
		ValidationPlan:           req.ValidationPlan,
		Constraints:              req.Constraints,
		CustomGuidance:           req.CustomGuidance,
	})
}
