package agent

import "github.com/moolen/patchpilot/internal/agent/prompts"

// BuildPrompt returns a structured prompt for an external coding agent.
func BuildPrompt(req AttemptRequest) (string, error) {
	remediationPrompts := make([]prompts.RemediationPrompt, 0, len(req.RemediationPrompts))
	for _, prompt := range req.RemediationPrompts {
		remediationPrompts = append(remediationPrompts, prompts.RemediationPrompt{
			Mode:     prompt.Mode,
			Template: prompt.Template,
		})
	}
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
		RemediationPrompts:       remediationPrompts,
	})
}
