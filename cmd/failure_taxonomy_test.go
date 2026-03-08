package cmd

import (
	"errors"
	"testing"

	"github.com/moolen/patchpilot/report"
)

func TestClassifyRunFailureVulnsRemainNoFix(t *testing.T) {
	summary := &report.Summary{Fixed: 0, After: 2}
	failure := classifyRunFailure(vulnsRemainError(2), summary, false, false, nil)
	if failure == nil {
		t.Fatal("expected failure classification")
	}
	if failure.Category != failureCategoryNoFix {
		t.Fatalf("unexpected category: %#v", failure)
	}
}

func TestClassifyRunFailureVerificationRegression(t *testing.T) {
	failure := classifyRunFailure(verificationRegressedError(1), nil, false, false, nil)
	if failure == nil || failure.Category != failureCategoryVerification {
		t.Fatalf("unexpected failure classification: %#v", failure)
	}
}

func TestClassifyRunFailureInvalidRuntimeConfig(t *testing.T) {
	err := wrapWithExitCode(ExitCodePatchFailed, errors.Join(errInvalidRuntimeConfig, errors.New("bad flag")))
	failure := classifyRunFailure(err, nil, false, false, nil)
	if failure == nil || failure.Category != failureCategoryConfig {
		t.Fatalf("unexpected failure classification: %#v", failure)
	}
}
