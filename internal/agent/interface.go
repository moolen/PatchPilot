package agent

import "context"

// Agent is an external coding harness that can attempt repository repairs.
type Agent interface {
	RunAttempt(ctx context.Context, req AttemptRequest) (AttemptResult, error)
}

const (
	TaskKindFixVulnerabilities = "fix_vulnerabilities"
	TaskKindBaselineScanRepair = "baseline_scan_repair"
)

// AttemptRequest describes the context provided to a single agent attempt.
type AttemptRequest struct {
	RepoPath                 string
	AttemptNumber            int
	TaskKind                 string
	Goal                     string
	CurrentStateLabel        string
	CurrentState             string
	FailureStage             string
	FailureError             string
	PreviousAttemptSummaries []string
	ValidationPlan           []string
	Constraints              []string
	CustomGuidance           []string
	WorkingDirectory         string
	PromptFilePath           string
}

// AttemptResult captures the immediate external agent command outcome.
type AttemptResult struct {
	Success bool
	Summary string
	Logs    string
}
