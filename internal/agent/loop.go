package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultMaxAttempts = 5

// ValidationResult captures the orchestrator's validation state after an attempt.
type ValidationResult struct {
	ValidationPassed bool
	GoalMet          bool
	ProgressCount    int
	CurrentState     string
	Summary          string
	Logs             string
}

// LoopRequest configures the repair loop.
type LoopRequest struct {
	RepoPath                 string
	WorkingDirectory         string
	ArtifactDirectory        string
	MaxAttempts              int
	TaskKind                 string
	Goal                     string
	CurrentStateLabel        string
	Constraints              []string
	InitialProgressCount     int
	InitialCurrentState      string
	PreviousAttemptSummaries []string
	ValidationPlan           []string
	Validate                 func(ctx context.Context, attemptNumber int) (ValidationResult, error)
}

// AttemptSummary describes one agent iteration and is written to summary.json.
type AttemptSummary struct {
	AttemptNumber     int    `json:"attempt_number"`
	Succeeded         bool   `json:"succeeded"`
	AgentSuccess      bool   `json:"agent_success"`
	AgentSummary      string `json:"agent_summary,omitempty"`
	AgentError        string `json:"agent_error,omitempty"`
	ValidationPassed  bool   `json:"validation_passed"`
	GoalMet           bool   `json:"goal_met"`
	ValidationError   string `json:"validation_error,omitempty"`
	ProgressBefore    int    `json:"progress_before"`
	ProgressAfter     int    `json:"progress_after"`
	ProgressReduced   bool   `json:"progress_reduced"`
	ValidationSummary string `json:"validation_summary,omitempty"`
	StartedAt         string `json:"started_at"`
	CompletedAt       string `json:"completed_at"`
}

// LoopResult is returned when the repair loop ends.
type LoopResult struct {
	Success          bool
	Attempts         int
	AttemptSummaries []AttemptSummary
	LastValidation   *ValidationResult
}

// Loop runs repeated agent attempts with validation between each run.
type Loop struct {
	Agent Agent
}

func (loop Loop) Run(ctx context.Context, req LoopRequest) (LoopResult, error) {
	if loop.Agent == nil {
		return LoopResult{}, fmt.Errorf("agent runner is nil")
	}
	if req.Validate == nil {
		return LoopResult{}, fmt.Errorf("validation callback is nil")
	}
	if strings.TrimSpace(req.RepoPath) == "" {
		return LoopResult{}, fmt.Errorf("repo path is empty")
	}

	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}

	artifactDir := strings.TrimSpace(req.ArtifactDirectory)
	if artifactDir == "" {
		artifactDir = filepath.Join(req.RepoPath, ".patchpilot", "agent")
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return LoopResult{}, fmt.Errorf("create agent artifact dir: %w", err)
	}

	workingDir := strings.TrimSpace(req.WorkingDirectory)
	if workingDir == "" {
		workingDir = req.RepoPath
	}

	currentProgressCount := req.InitialProgressCount
	if currentProgressCount < 0 {
		currentProgressCount = 0
	}
	currentState := strings.TrimSpace(req.InitialCurrentState)
	if currentState == "" {
		currentState = "{}"
	}

	previousSummaries := append([]string(nil), req.PreviousAttemptSummaries...)
	result := LoopResult{AttemptSummaries: make([]AttemptSummary, 0, maxAttempts)}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		started := time.Now().UTC()
		attemptDir := filepath.Join(artifactDir, fmt.Sprintf("attempt-%d", attempt))
		if err := os.MkdirAll(attemptDir, 0o755); err != nil {
			return result, fmt.Errorf("create attempt dir %d: %w", attempt, err)
		}

		promptPath := filepath.Join(attemptDir, "prompt.txt")
		agentLogPath := filepath.Join(attemptDir, "agent.log")
		validationLogPath := filepath.Join(attemptDir, "validation.log")
		summaryPath := filepath.Join(attemptDir, "summary.json")

		attemptReq := AttemptRequest{
			RepoPath:                 req.RepoPath,
			AttemptNumber:            attempt,
			TaskKind:                 req.TaskKind,
			Goal:                     req.Goal,
			CurrentStateLabel:        req.CurrentStateLabel,
			CurrentState:             currentState,
			PreviousAttemptSummaries: append([]string(nil), previousSummaries...),
			ValidationPlan:           append([]string(nil), req.ValidationPlan...),
			Constraints:              append([]string(nil), req.Constraints...),
			WorkingDirectory:         workingDir,
			PromptFilePath:           promptPath,
		}

		attemptResult, agentErr := loop.Agent.RunAttempt(ctx, attemptReq)
		if agentErr != nil && ctx.Err() != nil {
			return result, ctx.Err()
		}

		agentLog := strings.TrimSpace(attemptResult.Logs)
		if agentErr != nil {
			if agentLog == "" {
				agentLog = agentErr.Error()
			} else {
				agentLog += "\n" + agentErr.Error()
			}
		}
		if err := os.WriteFile(agentLogPath, []byte(agentLog+"\n"), 0o644); err != nil {
			return result, fmt.Errorf("write agent log for attempt %d: %w", attempt, err)
		}

		progressBefore := currentProgressCount
		validationResult, validationErr := req.Validate(ctx, attempt)
		if validationErr != nil && ctx.Err() != nil {
			return result, ctx.Err()
		}

		validationLog := strings.TrimSpace(validationResult.Logs)
		if validationErr != nil {
			if validationLog == "" {
				validationLog = validationErr.Error()
			} else {
				validationLog += "\n" + validationErr.Error()
			}
		}
		if err := os.WriteFile(validationLogPath, []byte(validationLog+"\n"), 0o644); err != nil {
			return result, fmt.Errorf("write validation log for attempt %d: %w", attempt, err)
		}

		progressAfter := progressBefore
		progressReduced := false
		if validationErr == nil {
			progressAfter = validationResult.ProgressCount
			if progressBefore == 0 {
				progressReduced = progressAfter == 0
			} else {
				progressReduced = progressAfter < progressBefore
			}
			currentProgressCount = progressAfter
			if trimmed := strings.TrimSpace(validationResult.CurrentState); trimmed != "" {
				currentState = trimmed
			}
			copyValidation := validationResult
			result.LastValidation = &copyValidation
		}

		summary := AttemptSummary{
			AttemptNumber:     attempt,
			Succeeded:         validationErr == nil && validationResult.GoalMet,
			AgentSuccess:      attemptResult.Success,
			AgentSummary:      strings.TrimSpace(attemptResult.Summary),
			ValidationPassed:  validationErr == nil && validationResult.ValidationPassed,
			GoalMet:           validationErr == nil && validationResult.GoalMet,
			ProgressBefore:    progressBefore,
			ProgressAfter:     progressAfter,
			ProgressReduced:   progressReduced,
			ValidationSummary: strings.TrimSpace(validationResult.Summary),
			StartedAt:         started.Format(time.RFC3339),
			CompletedAt:       time.Now().UTC().Format(time.RFC3339),
		}
		if agentErr != nil {
			summary.AgentError = agentErr.Error()
		}
		if validationErr != nil {
			summary.ValidationError = validationErr.Error()
		}
		if summary.ValidationSummary == "" {
			summary.ValidationSummary = fmt.Sprintf(
				"validation_passed=%t goal_met=%t progress_before=%d progress_after=%d",
				summary.ValidationPassed,
				summary.GoalMet,
				summary.ProgressBefore,
				summary.ProgressAfter,
			)
		}

		if err := writeAttemptSummary(summaryPath, summary); err != nil {
			return result, fmt.Errorf("write attempt summary for attempt %d: %w", attempt, err)
		}

		result.AttemptSummaries = append(result.AttemptSummaries, summary)
		previousSummaries = append(previousSummaries, summarizeForPrompt(summary))
		result.Attempts = attempt

		if summary.Succeeded {
			result.Success = true
			return result, nil
		}
	}

	result.Success = false
	result.Attempts = maxAttempts
	return result, nil
}

func summarizeForPrompt(summary AttemptSummary) string {
	status := "failed"
	if summary.Succeeded {
		status = "succeeded"
	}
	return fmt.Sprintf(
		"attempt %d %s (agent_success=%t, validation_passed=%t, goal_met=%t, progress=%d->%d)",
		summary.AttemptNumber,
		status,
		summary.AgentSuccess,
		summary.ValidationPassed,
		summary.GoalMet,
		summary.ProgressBefore,
		summary.ProgressAfter,
	)
}

func writeAttemptSummary(path string, summary AttemptSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal attempt summary: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
