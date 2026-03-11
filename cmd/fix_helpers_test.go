package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/verifycheck"
	"github.com/moolen/patchpilot/internal/vuln"
)

type stubFixEngine struct {
	name    string
	patches []fixer.Patch
	err     error
}

func (engine stubFixEngine) Name() string {
	return engine.name
}

func (engine stubFixEngine) Apply(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
	return engine.patches, engine.err
}

func TestApplyFixEnginesLogsPerEngineProgress(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stderr = writer
	t.Cleanup(func() {
		os.Stderr = originalStderr
	})

	configureProgressLogging(false, "fix", "/tmp/repo", "run-test")

	engines := []fixer.Engine{
		stubFixEngine{
			name: "noop",
		},
		stubFixEngine{
			name: "patchy",
			patches: []fixer.Patch{{
				Manager: "npm",
				Target:  "package.json",
				Package: "left-pad",
				From:    "1.0.0",
				To:      "1.1.0",
			}},
		},
		stubFixEngine{
			name: "broken",
			err:  errors.New("boom"),
		},
	}

	patches, issues, details, err := applyFixEngines(context.Background(), "/tmp/repo", nil, engines, true)
	if err != nil {
		t.Fatalf("applyFixEngines returned error: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	logs := string(data)

	for _, want := range []string{
		"running noop fixer",
		"noop fixer made no changes",
		"running patchy fixer",
		"patchy fixer applied 1 patch(es)",
		"running broken fixer",
		"broken fixes failed: boom",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected logs to contain %q, got:\n%s", want, logs)
		}
	}

	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
	if len(issues) != 1 || issues[0] != "broken fixes failed: boom" {
		t.Fatalf("unexpected issues: %#v", issues)
	}

	noop, ok := details["noop"].(map[string]any)
	if !ok {
		t.Fatalf("expected noop details map, got %#v", details["noop"])
	}
	if noop["status"] != "no_changes" {
		t.Fatalf("expected noop status no_changes, got %#v", noop["status"])
	}

	patchy, ok := details["patchy"].(map[string]any)
	if !ok {
		t.Fatalf("expected patchy details map, got %#v", details["patchy"])
	}
	if patchy["status"] != "applied" {
		t.Fatalf("expected patchy status applied, got %#v", patchy["status"])
	}
	if patchy["patches"] != 1 {
		t.Fatalf("expected patchy patches 1, got %#v", patchy["patches"])
	}
}

func TestBaselineRemediationPromptGuidance(t *testing.T) {
	cfg := &policy.Config{
		Agent: policy.AgentPolicy{
			RemediationPrompts: policy.AgentRemediationPromptsPolicy{
				All: []string{"global"},
				BaselineScanRepair: policy.AgentBaselineScanRepairPromptsPolicy{
					All:                  []string{"baseline-all"},
					GenerateBaselineSBOM: []string{"baseline-sbom"},
					ScanBaseline:         []string{"baseline-scan"},
				},
			},
		},
	}

	gotSBOM := baselineRemediationPromptGuidance(cfg, "generate_baseline_sbom")
	wantSBOM := []string{"global", "baseline-all", "baseline-sbom"}
	if !reflect.DeepEqual(gotSBOM, wantSBOM) {
		t.Fatalf("unexpected baseline SBOM prompts: got %#v want %#v", gotSBOM, wantSBOM)
	}

	gotScan := baselineRemediationPromptGuidance(cfg, "scan_baseline")
	wantScan := []string{"global", "baseline-all", "baseline-scan"}
	if !reflect.DeepEqual(gotScan, wantScan) {
		t.Fatalf("unexpected baseline scan prompts: got %#v want %#v", gotScan, wantScan)
	}
}

func TestFixRemediationPromptGuidance(t *testing.T) {
	cfg := &policy.Config{
		Agent: policy.AgentPolicy{
			RemediationPrompts: policy.AgentRemediationPromptsPolicy{
				All: []string{"global"},
				FixVulnerabilities: policy.AgentFixVulnerabilitiesPromptsPolicy{
					All:                      []string{"fix-all"},
					DeterministicFixFailed:   []string{"fix-deterministic"},
					ValidationFailed:         []string{"fix-validation"},
					VulnerabilitiesRemaining: []string{"fix-remaining"},
					VerificationRegressed:    []string{"fix-regression"},
				},
			},
		},
	}
	validation := validationCycle{
		After: &vuln.Report{
			Findings: []vuln.Finding{{VulnerabilityID: "CVE-1"}},
		},
		Verification: verifycheck.Report{
			Regressions: []verifycheck.Regression{{Dir: ".", Check: "build"}},
		},
	}
	got := fixRemediationPromptGuidance(cfg, []string{"npm fixes failed"}, validation, errors.New("verification command failed"))
	want := []string{"global", "fix-all", "fix-deterministic", "fix-validation", "fix-remaining", "fix-regression"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected fix prompts: got %#v want %#v", got, want)
	}
}
