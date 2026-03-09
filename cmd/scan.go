package cmd

import (
	"context"
	"os"

	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/report"
)

func runScan(ctx context.Context, repo string, cfg *policy.Config, jsonOutput bool) (runErr error) {
	tracker := newRunTracker("scan", repo, jsonOutput)
	defer func() {
		failure := classifyRunFailure(runErr, nil, false, false, nil)
		if err := tracker.complete(runErr, failure); err != nil && runErr == nil {
			runErr = err
		}
	}()

	stage := tracker.beginStage("generate_sbom")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, nil)

	stage = tracker.beginStage("scan_vulnerabilities")
	vulnReport, err := scanVulnerabilities(ctx, repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{
		"findings":             len(vulnReport.Findings),
		"ignored_without_fix":  vulnReport.IgnoredWithoutFix,
		"ignored_by_policy":    vulnReport.IgnoredByPolicy,
		"raw_match_candidates": vulnReport.RawMatches,
	})
	tracker.addCounter("findings", len(vulnReport.Findings))
	tracker.addCounter("ignored_without_fix", vulnReport.IgnoredWithoutFix)
	tracker.addCounter("ignored_by_policy", vulnReport.IgnoredByPolicy)

	stage = tracker.beginStage("write_sarif")
	if err := report.WriteSARIF(repo, vulnReport.Findings); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{"path": ".patchpilot/findings.sarif"})

	stage = tracker.beginStage("print_report")
	report.PrintCurrent(os.Stdout, repo, vulnReport)
	tracker.endStageSuccess(stage, nil)

	if len(vulnReport.Findings) > 0 {
		return vulnsRemainError(len(vulnReport.Findings))
	}
	return nil
}
