package cmd

import (
	"context"
	"os"

	"github.com/moolen/patchpilot/policy"
	"github.com/moolen/patchpilot/report"
)

func runScan(ctx context.Context, repo string, cfg *policy.Config) error {
	vulnReport, err := generateSBOMAndScan(ctx, repo, cfg)
	if err != nil {
		return err
	}

	report.PrintCurrent(os.Stdout, repo, vulnReport)
	if len(vulnReport.Findings) > 0 {
		return vulnsRemainError(len(vulnReport.Findings))
	}
	return nil
}
