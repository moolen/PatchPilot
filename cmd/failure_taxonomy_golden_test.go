package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/moolen/patchpilot/internal/report"
)

type failureGoldenCase struct {
	Name    string             `json:"name"`
	Failure *report.RunFailure `json:"failure"`
}

func TestFailureTaxonomyGolden(t *testing.T) {
	cases := []failureGoldenCase{
		{
			Name: "no_fix_available",
			Failure: classifyRunFailure(
				vulnsRemainError(3),
				&report.Summary{Before: 3, Fixed: 0, After: 3},
				false,
				false,
				nil,
			),
		},
		{
			Name: "partial_fix_applied",
			Failure: classifyRunFailure(
				vulnsRemainError(1),
				&report.Summary{Before: 6, Fixed: 5, After: 1},
				false,
				false,
				nil,
			),
		},
		{
			Name:    "verification_regressed",
			Failure: classifyRunFailure(verificationRegressedError(2), nil, false, false, nil),
		},
		{
			Name: "policy_violation",
			Failure: classifyRunFailure(
				wrapWithExitCode(ExitCodePatchFailed, errors.New("docker policy violation in Dockerfile")),
				nil,
				false,
				false,
				nil,
			),
		},
		{
			Name: "agent_failure",
			Failure: classifyRunFailure(
				wrapWithExitCode(ExitCodePatchFailed, errors.New("deterministic patching failed and agent loop did not resolve all issues")),
				nil,
				true,
				false,
				[]string{"go module fixes failed: something"},
			),
		},
	}

	data, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}
	goldenPath := filepath.Join("testdata", "golden", "failure_taxonomy.golden.json")
	assertGolden(t, goldenPath, data)
}

func assertGolden(t *testing.T, path string, data []byte) {
	t.Helper()
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
