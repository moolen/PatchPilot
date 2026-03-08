package cmd

import (
	"context"

	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/sbom"
	"github.com/moolen/patchpilot/internal/vuln"
)

func generateSBOM(ctx context.Context, repo string, cfg *policy.Config) error {
	if _, err := sbom.GenerateWithOptions(ctx, repo, sbomOptionsFromPolicy(cfg)); err != nil {
		return wrapWithExitCode(ExitCodeScanFailed, err)
	}
	return nil
}

func scanVulnerabilities(ctx context.Context, repo string, cfg *policy.Config) (*vuln.Report, error) {
	report, err := vuln.ScanWithOptions(ctx, repo, vulnOptionsFromPolicy(cfg))
	if err != nil {
		return nil, wrapWithExitCode(ExitCodeScanFailed, err)
	}
	return report, nil
}

func generateSBOMAndScan(ctx context.Context, repo string, cfg *policy.Config) (*vuln.Report, error) {
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		return nil, err
	}
	return scanVulnerabilities(ctx, repo, cfg)
}
