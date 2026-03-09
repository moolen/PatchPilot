package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const runFile = "run.json"

type RunRecord struct {
	RunID          string       `json:"run_id"`
	Command        string       `json:"command"`
	Repository     string       `json:"repository"`
	Status         string       `json:"status"`
	StartedAt      string       `json:"started_at"`
	CompletedAt    string       `json:"completed_at"`
	DurationMillis int64        `json:"duration_millis"`
	Stages         []RunStage   `json:"stages,omitempty"`
	Failure        *RunFailure  `json:"failure,omitempty"`
	Labels         []RunLabel   `json:"labels,omitempty"`
	Counters       []RunCounter `json:"counters,omitempty"`
}

type RunStage struct {
	Name           string         `json:"name"`
	Status         string         `json:"status"`
	StartedAt      string         `json:"started_at"`
	CompletedAt    string         `json:"completed_at"`
	DurationMillis int64          `json:"duration_millis"`
	Error          string         `json:"error,omitempty"`
	Details        map[string]any `json:"details,omitempty"`
}

type RunFailure struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	ExitCode int    `json:"exit_code"`
	Message  string `json:"message"`
}

type RunLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type RunCounter struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func WriteRunRecord(repo string, record RunRecord) error {
	if err := ensureStateDir(repo); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run record: %w", err)
	}
	path := filepath.Join(repo, ".patchpilot", runFile)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write run record: %w", err)
	}
	return nil
}
