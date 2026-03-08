package report

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/verifycheck"
	"github.com/moolen/patchpilot/internal/vuln"
)

func TestBuildSummaryIncludesUnsupportedStdlibFindings(t *testing.T) {
	before := &vuln.Report{Findings: []vuln.Finding{{
		VulnerabilityID: "CVE-1",
		Package:         "stdlib",
		Installed:       "go1.24.10",
		FixedVersion:    "v1.24.12",
		Ecosystem:       "golang",
		Locations:       []string{"/repo/bin"},
	}}}
	after := &vuln.Report{Findings: before.Findings}

	summary := BuildSummary(before, after, nil)
	if summary.Fixed != 0 {
		t.Fatalf("expected no fixed findings, got %d", summary.Fixed)
	}
	if len(summary.Unsupported) != 1 {
		t.Fatalf("expected 1 unsupported finding, got %#v", summary.Unsupported)
	}
	if summary.Unsupported[0].Reason != "requires Go toolchain upgrade" {
		t.Fatalf("unexpected unsupported reason: %+v", summary.Unsupported[0])
	}
}

func TestPrintCurrentShowsUnsupportedCount(t *testing.T) {
	report := &vuln.Report{Findings: []vuln.Finding{{
		VulnerabilityID: "CVE-1",
		Package:         "stdlib",
		Installed:       "go1.24.10",
		FixedVersion:    "v1.24.12",
		Ecosystem:       "golang",
		Locations:       []string{"/repo/bin"},
	}}}

	var out strings.Builder
	PrintCurrent(&out, "/repo", report)
	text := out.String()
	if !strings.Contains(text, "Unsupported by cvefix: 1") {
		t.Fatalf("expected unsupported count in output, got:\n%s", text)
	}
	if !strings.Contains(text, "File Location") || !strings.Contains(text, "Fixable") {
		t.Fatalf("expected table headers in output, got:\n%s", text)
	}
	if !containsCompactedLine(text, "CVE-1 stdlib unknown no") {
		t.Fatalf("expected row with CVE/package/location/fixable, got:\n%s", text)
	}
}

func TestPrintSummaryShowsUnsupportedSection(t *testing.T) {
	summary := BuildSummary(
		&vuln.Report{Findings: []vuln.Finding{{
			VulnerabilityID: "CVE-1",
			Package:         "stdlib",
			Installed:       "go1.24.10",
			FixedVersion:    "v1.24.12",
			Ecosystem:       "golang",
			Locations:       []string{"/repo/bin"},
		}}},
		&vuln.Report{Findings: []vuln.Finding{{
			VulnerabilityID: "CVE-1",
			Package:         "stdlib",
			Installed:       "go1.24.10",
			FixedVersion:    "v1.24.12",
			Ecosystem:       "golang",
			Locations:       []string{"/repo/bin"},
		}}},
		nil,
	)

	var out strings.Builder
	PrintSummary(&out, summary)
	text := out.String()
	if !strings.Contains(text, "Fix results:") {
		t.Fatalf("expected fix results section, got:\n%s", text)
	}
	if !containsCompactedLine(text, "CVE-1 stdlib unknown not fixed requires Go toolchain upgrade") {
		t.Fatalf("expected not-fixed table row with reason, got:\n%s", text)
	}
	if !strings.Contains(text, "Unsupported by cvefix (still actionable):") {
		t.Fatalf("expected unsupported section, got:\n%s", text)
	}
	if !strings.Contains(text, "requires Go toolchain upgrade") {
		t.Fatalf("expected unsupported reason, got:\n%s", text)
	}
}

func TestBuildSummaryMarksFixedFindings(t *testing.T) {
	before := &vuln.Report{Findings: []vuln.Finding{{
		VulnerabilityID: "CVE-fixed",
		Package:         "github.com/example/lib",
		Installed:       "v1.0.0",
		FixedVersion:    "v1.1.0",
		Ecosystem:       "golang",
		Locations:       []string{"/repo/go.mod"},
	}}}
	after := &vuln.Report{}

	summary := BuildSummary(before, after, nil)
	if len(summary.Findings) != 1 {
		t.Fatalf("expected 1 result row, got %#v", summary.Findings)
	}
	if !summary.Findings[0].Fixed {
		t.Fatalf("expected finding to be marked fixed, got %#v", summary.Findings[0])
	}
	if summary.Findings[0].Reason != "" {
		t.Fatalf("expected empty reason for fixed finding, got %q", summary.Findings[0].Reason)
	}
}

func TestBuildSummaryTreatsNpmAndPythonLockLocationsAsFixable(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		location  string
	}{
		{name: "npm package-lock", ecosystem: "npm", location: "/repo/package-lock.json"},
		{name: "npm pnpm lock", ecosystem: "npm", location: "/repo/pnpm-lock.yaml"},
		{name: "npm yarn lock", ecosystem: "npm", location: "/repo/yarn.lock"},
		{name: "python pyproject", ecosystem: "pypi", location: "/repo/pyproject.toml"},
		{name: "python poetry lock", ecosystem: "pypi", location: "/repo/poetry.lock"},
		{name: "python uv lock", ecosystem: "pypi", location: "/repo/uv.lock"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := &vuln.Report{Findings: []vuln.Finding{{
				VulnerabilityID: "CVE-1",
				Package:         "demo",
				Installed:       "1.0.0",
				FixedVersion:    "1.2.3",
				Ecosystem:       tc.ecosystem,
				Locations:       []string{tc.location},
			}}}
			after := &vuln.Report{Findings: before.Findings}

			summary := BuildSummary(before, after, nil)
			if len(summary.Findings) != 1 {
				t.Fatalf("expected one finding row, got %#v", summary.Findings)
			}
			if summary.Findings[0].Reason != "no automated patch was applied" {
				t.Fatalf("expected fixable reason for %s, got %#v", tc.location, summary.Findings[0])
			}
		})
	}
}

func TestPrintSummaryShowsUnsupportedSectionManualSummary(t *testing.T) {
	summary := Summary{
		Before: 1,
		After:  1,
		Unsupported: []UnsupportedFinding{{
			VulnerabilityID: "CVE-1",
			Package:         "stdlib",
			Installed:       "go1.24.10",
			FixedVersion:    "v1.24.12",
			Target:          "/repo/bin",
			Reason:          "requires Go toolchain upgrade",
		}},
	}

	var out strings.Builder
	PrintSummary(&out, summary)
	text := out.String()
	if !strings.Contains(text, "Unsupported by cvefix (still actionable):") {
		t.Fatalf("expected unsupported section, got:\n%s", text)
	}
	if !strings.Contains(text, "requires Go toolchain upgrade") {
		t.Fatalf("expected unsupported reason, got:\n%s", text)
	}
}

func TestSummarizeVerificationBuildsCompactSummary(t *testing.T) {
	verification := verifycheck.Report{
		Mode:        verifycheck.ModeStandard,
		Modules:     []verifycheck.ModuleResult{{Dir: "a", Checks: []verifycheck.CheckResult{{Name: "build", Status: verifycheck.StatusOK}, {Name: "vet", Status: verifycheck.StatusFailed}}}},
		Regressions: []verifycheck.Regression{{Dir: "a", Check: "vet"}},
	}
	summary := SummarizeVerification(verification)
	if summary == nil || summary.Mode != verifycheck.ModeStandard || summary.Modules != 1 || summary.Checks != 2 || summary.OK != 1 || summary.Failed != 1 || summary.Regressions != 1 {
		t.Fatalf("unexpected verification summary: %#v", summary)
	}
}

func TestWriteSummaryCreatesStateDir(t *testing.T) {
	repo := t.TempDir()
	if err := WriteSummary(repo, Summary{Before: 1}); err != nil {
		t.Fatalf("WriteSummary returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".cvefix", summaryFile)); err != nil {
		t.Fatalf("expected summary file to exist: %v", err)
	}
}

func TestBuildFixExplanationsIncludesPatchAndVerificationImpact(t *testing.T) {
	before := &vuln.Report{Findings: []vuln.Finding{{
		VulnerabilityID: "CVE-1",
		Package:         "github.com/example/lib",
		FixedVersion:    "v1.2.3",
		Ecosystem:       "golang",
		Locations:       []string{"/repo/go.mod"},
	}}}
	after := &vuln.Report{}
	verification := &VerificationSummary{Regressions: 0}
	patches := []fixer.Patch{{
		Manager: "gomod",
		Target:  "/repo/go.mod",
		Package: "github.com/example/lib",
		From:    "v1.0.0",
		To:      "v1.2.3",
	}}

	explanations := BuildFixExplanations(before, after, patches, verification)
	if len(explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %#v", explanations)
	}
	if explanations[0].Decision != "fixed" {
		t.Fatalf("expected fixed decision, got %#v", explanations[0])
	}
	if !strings.Contains(explanations[0].Patch, "gomod") {
		t.Fatalf("expected patch detail, got %#v", explanations[0])
	}
	if !strings.Contains(explanations[0].VerificationImpact, "no verification regressions") {
		t.Fatalf("unexpected verification impact: %#v", explanations[0])
	}
}

func containsCompactedLine(text, expected string) bool {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		compacted := strings.Join(strings.Fields(line), " ")
		if compacted == expected {
			return true
		}
	}
	return slices.Contains(lines, expected)
}
