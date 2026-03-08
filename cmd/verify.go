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

func runVerify(ctx context.Context, repo string, cfg *policy.Config) error {
	baseline, err := report.ReadBaseline(repo)
	if err != nil {
		return err
	}

	after, err := generateSBOMAndScan(ctx, repo, cfg)
	if err != nil {
		return err
	}

	summary := report.BuildSummary(baseline, after, nil)
	report.PrintSummary(os.Stdout, summary)

	verificationBaseline, err := report.ReadVerificationBaseline(repo)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stdout, "Verification mode: standard (skipped: no baseline available)")
			if summary.After > 0 {
				return vulnsRemainError(summary.After)
			}
			return nil
		}
		return err
	}
	verificationAfter, err := runVerificationChecks(ctx, repo, verifycheck.ModuleDirs(*verificationBaseline), cfg)
	if err != nil {
		return err
	}
	verificationAfter.Regressions = verifycheck.Compare(*verificationBaseline, verificationAfter)
	if err := report.WriteVerification(repo, verificationAfter); err != nil {
		return err
	}
	verifycheck.PrintSummary(os.Stdout, verificationAfter)

	if len(verificationAfter.Regressions) > 0 {
		return verificationRegressedError(len(verificationAfter.Regressions))
	}
	if summary.After > 0 {
		return vulnsRemainError(summary.After)
	}
	return nil
}
