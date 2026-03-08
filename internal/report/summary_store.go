package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moolen/patchpilot/internal/vuln"
)

func WriteBaseline(repo string, baseline *vuln.Report) error {
	if err := ensureStateDir(repo); err != nil {
		return err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	path := filepath.Join(repo, ".cvefix", baselineFile)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func ReadBaseline(repo string) (*vuln.Report, error) {
	data, err := os.ReadFile(filepath.Join(repo, ".cvefix", baselineFile))
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var report vuln.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode baseline: %w", err)
	}
	return &report, nil
}

func WriteSummary(repo string, summary Summary) error {
	if err := ensureStateDir(repo); err != nil {
		return err
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	path := filepath.Join(repo, ".cvefix", summaryFile)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

func ensureStateDir(repo string) error {
	if err := os.MkdirAll(filepath.Join(repo, ".cvefix"), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	return nil
}
