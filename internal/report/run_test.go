package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRunRecordCreatesRunFile(t *testing.T) {
	repo := t.TempDir()
	record := RunRecord{
		RunID:       "run-test",
		Command:     "fix",
		Repository:  repo,
		Status:      "success",
		StartedAt:   "2026-01-01T00:00:00Z",
		CompletedAt: "2026-01-01T00:00:01Z",
		Stages: []RunStage{{
			Name:   "scan",
			Status: "success",
		}},
	}
	if err := WriteRunRecord(repo, record); err != nil {
		t.Fatalf("WriteRunRecord returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(repo, ".cvefix", runFile))
	if err != nil {
		t.Fatalf("read run record: %v", err)
	}
	var decoded RunRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode run record: %v", err)
	}
	if decoded.RunID != "run-test" || decoded.Command != "fix" {
		t.Fatalf("unexpected decoded record: %#v", decoded)
	}
}
