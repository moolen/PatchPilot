package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moolen/patchpilot/verifycheck"
)

const (
	verificationBaselineFile = "verification-baseline.json"
	verificationFile         = "verification.json"
)

func WriteVerificationBaseline(repo string, verification verifycheck.Report) error {
	return writeVerificationFile(filepath.Join(repo, ".cvefix", verificationBaselineFile), verification)
}

func ReadVerificationBaseline(repo string) (*verifycheck.Report, error) {
	return readVerificationFile(filepath.Join(repo, ".cvefix", verificationBaselineFile), "verification baseline")
}

func WriteVerification(repo string, verification verifycheck.Report) error {
	return writeVerificationFile(filepath.Join(repo, ".cvefix", verificationFile), verification)
}

func readVerificationFile(path, label string) (*verifycheck.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	var verification verifycheck.Report
	if err := json.Unmarshal(data, &verification); err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return &verification, nil
}

func writeVerificationFile(path string, verification verifycheck.Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create verification dir: %w", err)
	}
	data, err := json.MarshalIndent(verification, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal verification: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write verification: %w", err)
	}
	return nil
}
