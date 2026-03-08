package agent

import "context"

// Agent is an external coding harness that can attempt repository repairs.
type Agent interface {
	RunAttempt(ctx context.Context, req AttemptRequest) (AttemptResult, error)
}

// AttemptRequest describes the context provided to a single agent attempt.
type AttemptRequest struct {
	RepoPath                 string
	AttemptNumber            int
	RemainingVulnerabilities string
	PreviousAttemptSummaries []string
	ValidationCommands       []string
	WorkingDirectory         string
	PromptFilePath           string
}

// AttemptResult captures the immediate external agent command outcome.
type AttemptResult struct {
	Success bool
	Summary string
	Logs    string
}
