package githubapp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIssueCommentMessagesGolden(t *testing.T) {
	autoMergeErr := errors.New("merge policy blocked")
	payload := map[string]string{
		"started":                   remediationStartedComment(),
		"invalid_command":           invalidCommandComment(errors.New("unknown option")),
		"failed":                    remediationFailedComment(errors.New("cvefix failed")),
		"blocked":                   remediationBlockedComment("risk score too high", 42),
		"no_changes":                remediationNoChangesComment(0),
		"pr_upsert_failed":          remediationPRUpsertFailedComment(errors.New("api unavailable")),
		"pr_ready_opened":           remediationPRReadyComment("opened", "https://example.com/pr/1", false, true, nil),
		"pr_ready_updated_enabled":  remediationPRReadyComment("updated", "https://example.com/pr/1", true, true, nil),
		"pr_ready_updated_disabled": remediationPRReadyComment("updated", "https://example.com/pr/1", true, false, nil),
		"pr_ready_updated_error":    remediationPRReadyComment("updated", "https://example.com/pr/1", true, true, autoMergeErr),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal messages: %v", err)
	}
	assertGolden(t, filepath.Join("testdata", "golden", "messages.golden.json"), data)
}

func TestRemediationPRBodyGolden(t *testing.T) {
	service := &Service{}
	body := service.remediationPRBody("issue comment by @alice", "/cvefix fix", fixRunResult{
		ExitCode:     23,
		Stdout:       "stdout line",
		Stderr:       "stderr line",
		RiskScore:    7,
		ChangedFiles: []string{"go.mod", "go.sum"},
	})
	assertGolden(t, filepath.Join("testdata", "golden", "remediation_pr_body.golden.txt"), []byte(body))
}

func assertGolden(t *testing.T, path string, data []byte) {
	t.Helper()
	expectedData := append([]byte(nil), data...)
	if len(expectedData) == 0 || expectedData[len(expectedData)-1] != '\n' {
		expectedData = append(expectedData, '\n')
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, expectedData, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(actual) != string(expectedData) {
		t.Fatalf("golden mismatch for %s (set UPDATE_GOLDEN=1 to refresh)", path)
	}
}
