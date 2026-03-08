package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRecordGolden(t *testing.T) {
	record := RunRecord{
		RunID:          "run-1234-abcd",
		Command:        "fix",
		Repository:     "/tmp/repo",
		Status:         "failed",
		StartedAt:      "2026-03-08T10:00:00Z",
		CompletedAt:    "2026-03-08T10:00:12Z",
		DurationMillis: 12000,
		Stages: []RunStage{
			{
				Name:           "scan_baseline",
				Status:         "success",
				StartedAt:      "2026-03-08T10:00:00Z",
				CompletedAt:    "2026-03-08T10:00:03Z",
				DurationMillis: 3000,
				Details: map[string]any{
					"findings": 4,
				},
			},
			{
				Name:           "apply_deterministic_fixes",
				Status:         "success",
				StartedAt:      "2026-03-08T10:00:03Z",
				CompletedAt:    "2026-03-08T10:00:09Z",
				DurationMillis: 6000,
				Details: map[string]any{
					"patches_total": 2,
					"issues":        0,
				},
			},
			{
				Name:           "validate_post_fix",
				Status:         "failed",
				StartedAt:      "2026-03-08T10:00:09Z",
				CompletedAt:    "2026-03-08T10:00:12Z",
				DurationMillis: 3000,
				Error:          "verification regressed: 1 check(s) changed from passing to failing/timeout",
			},
		},
		Failure: &RunFailure{
			Category: "verification_regression",
			Code:     "verification_regressed",
			ExitCode: 22,
			Message:  "verification regressed: 1 check(s) changed from passing to failing/timeout",
		},
		Labels: []RunLabel{
			{Key: "trigger", Value: "issue_comment"},
		},
		Counters: []RunCounter{
			{Name: "findings_before", Value: 4},
			{Name: "findings_after", Value: 1},
		},
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	path := filepath.Join("testdata", "golden", "run_record.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(expected) != string(append(data, '\n')) {
		t.Fatalf("golden mismatch for %s\nset UPDATE_GOLDEN=1 to update", path)
	}
}
