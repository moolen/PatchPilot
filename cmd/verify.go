package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/moolen/patchpilot/policy"
	"github.com/moolen/patchpilot/report"
	"github.com/moolen/patchpilot/verifycheck"
)

func runVerify(ctx context.Context, repo string, cfg *policy.Config, jsonOutput bool) (runErr error) {
	tracker := newRunTracker("verify", repo, jsonOutput)
	defer func() {
		failure := classifyRunFailure(runErr, nil, false, false, nil)
		if err := tracker.complete(runErr, failure); err != nil && runErr == nil {
			runErr = err
		}
	}()

	stage := tracker.beginStage("load_baseline")
	baseline, err := report.ReadBaseline(repo)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, nil)

	stage = tracker.beginStage("generate_sbom")
	if err := generateSBOM(ctx, repo, cfg); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, nil)

	stage = tracker.beginStage("scan_vulnerabilities")
	after, err := scanVulnerabilities(ctx, repo, cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{"findings_after": len(after.Findings)})
	tracker.addCounter("findings_after", len(after.Findings))

	stage = tracker.beginStage("build_summary")
	summary := report.BuildSummary(baseline, after, nil)
	report.PrintSummary(os.Stdout, summary)
	tracker.endStageSuccess(stage, map[string]any{
		"before": summary.Before,
		"fixed":  summary.Fixed,
		"after":  summary.After,
	})
	tracker.addCounter("findings_before", summary.Before)
	tracker.addCounter("findings_fixed", summary.Fixed)

	stage = tracker.beginStage("load_verification_baseline")
	verificationBaseline, err := report.ReadVerificationBaseline(repo)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			tracker.endStageSuccess(stage, map[string]any{"verification_baseline": "missing"})
			fmt.Fprintln(os.Stdout, "Verification mode: standard (skipped: no baseline available)")
			if summary.After > 0 {
				return vulnsRemainError(summary.After)
			}
			return nil
		}
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	tracker.endStageSuccess(stage, map[string]any{"modules": len(verificationBaseline.Modules)})

	stage = tracker.beginStage("run_verification")
	verificationAfter, err := runVerificationChecks(ctx, repo, verifycheck.ModuleDirs(*verificationBaseline), cfg)
	if err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	verificationAfter.Regressions = verifycheck.Compare(*verificationBaseline, verificationAfter)
	if err := report.WriteVerification(repo, verificationAfter); err != nil {
		tracker.endStageFailure(stage, err, nil)
		return err
	}
	verifycheck.PrintSummary(os.Stdout, verificationAfter)
	tracker.endStageSuccess(stage, map[string]any{
		"modules":     len(verificationAfter.Modules),
		"regressions": len(verificationAfter.Regressions),
	})
	tracker.addCounter("verification_regressions", len(verificationAfter.Regressions))

	if len(verificationAfter.Regressions) > 0 {
		return verificationRegressedError(len(verificationAfter.Regressions))
	}
	if summary.After > 0 {
		return vulnsRemainError(summary.After)
	}
	return nil
}
