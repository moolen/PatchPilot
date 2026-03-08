package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/moolen/patchpilot/internal/report"
)

type runTracker struct {
	repo       string
	jsonOutput bool
	record     report.RunRecord
	startedAt  time.Time
}

func newRunTracker(command, repo string, jsonOutput bool) *runTracker {
	started := time.Now().UTC()
	runID := newRunID()
	configureProgressLogging(jsonOutput, command, repo, runID)
	return &runTracker{
		repo:       repo,
		jsonOutput: jsonOutput,
		startedAt:  started,
		record: report.RunRecord{
			RunID:      runID,
			Command:    command,
			Repository: repo,
			Status:     "running",
			StartedAt:  started.Format(time.RFC3339Nano),
		},
	}
}

func (tracker *runTracker) beginStage(name string) int {
	stage := report.RunStage{
		Name:      name,
		Status:    "running",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	tracker.record.Stages = append(tracker.record.Stages, stage)
	return len(tracker.record.Stages) - 1
}

func (tracker *runTracker) endStageSuccess(index int, details map[string]any) {
	if index < 0 || index >= len(tracker.record.Stages) {
		return
	}
	now := time.Now().UTC()
	stage := tracker.record.Stages[index]
	stage.Status = "success"
	stage.CompletedAt = now.Format(time.RFC3339Nano)
	started, err := time.Parse(time.RFC3339Nano, stage.StartedAt)
	if err == nil {
		stage.DurationMillis = now.Sub(started).Milliseconds()
	}
	if len(details) > 0 {
		stage.Details = details
	}
	tracker.record.Stages[index] = stage
}

func (tracker *runTracker) endStageFailure(index int, stageErr error, details map[string]any) {
	if index < 0 || index >= len(tracker.record.Stages) {
		return
	}
	now := time.Now().UTC()
	stage := tracker.record.Stages[index]
	stage.Status = "failed"
	stage.CompletedAt = now.Format(time.RFC3339Nano)
	started, err := time.Parse(time.RFC3339Nano, stage.StartedAt)
	if err == nil {
		stage.DurationMillis = now.Sub(started).Milliseconds()
	}
	if stageErr != nil {
		stage.Error = stageErr.Error()
	}
	if len(details) > 0 {
		stage.Details = details
	}
	tracker.record.Stages[index] = stage
}

func (tracker *runTracker) addCounter(name string, value int) {
	tracker.record.Counters = append(tracker.record.Counters, report.RunCounter{Name: name, Value: value})
}

func (tracker *runTracker) addLabel(key, value string) {
	tracker.record.Labels = append(tracker.record.Labels, report.RunLabel{Key: key, Value: value})
}

func (tracker *runTracker) complete(err error, failure *report.RunFailure) error {
	finished := time.Now().UTC()
	tracker.record.CompletedAt = finished.Format(time.RFC3339Nano)
	tracker.record.DurationMillis = finished.Sub(tracker.startedAt).Milliseconds()
	if err == nil {
		tracker.record.Status = "success"
	} else {
		tracker.record.Status = "failed"
	}
	if failure != nil {
		tracker.record.Failure = failure
	}

	configureProgressLogging(tracker.jsonOutput, tracker.record.Command, tracker.repo, tracker.record.RunID)
	return report.WriteRunRecord(tracker.repo, tracker.record)
}

func newRunID() string {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("run-%d-%s", time.Now().UTC().Unix(), hex.EncodeToString(random))
}
