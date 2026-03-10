package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/verifycheck"
	"github.com/moolen/patchpilot/internal/vuln"
)

const (
	baselineFile       = "baseline-findings.json"
	summaryFile        = "summary.json"
	maxPrintedIssues   = 50
	locationGoMod      = "go.mod"
	locationDocker     = "dockerfile"
	locationNPM        = "package.json"
	locationNPMLock    = "package-lock.json"
	locationPnpmLock   = "pnpm-lock.yaml"
	locationYarnLock   = "yarn.lock"
	locationPIP        = "requirements.txt"
	locationPyProject  = "pyproject.toml"
	locationPoetryLock = "poetry.lock"
	locationUVLock     = "uv.lock"
	locationMaven      = "pom.xml"
	locationGradle     = "build.gradle"
	locationCargo      = "Cargo.toml"
	locationNuGet      = ".csproj"
	locationComposer   = "composer.json"
)

type Summary struct {
	Before       int                  `json:"before"`
	Fixed        int                  `json:"fixed"`
	After        int                  `json:"after"`
	Patches      []fixer.Patch        `json:"patches,omitempty"`
	Findings     []FindingResult      `json:"findings,omitempty"`
	Explanations []FixExplanation     `json:"explanations,omitempty"`
	Unsupported  []UnsupportedFinding `json:"unsupported,omitempty"`
	Verification *VerificationSummary `json:"verification,omitempty"`
}

type FindingResult struct {
	VulnerabilityID string `json:"vulnerability_id"`
	Package         string `json:"package"`
	FileLocation    string `json:"file_location"`
	Fixed           bool   `json:"fixed"`
	Reason          string `json:"reason,omitempty"`
}

type VerificationSummary struct {
	Mode        string `json:"mode"`
	Modules     int    `json:"modules"`
	Checks      int    `json:"checks"`
	OK          int    `json:"ok"`
	Failed      int    `json:"failed"`
	Timeouts    int    `json:"timeouts"`
	Regressions int    `json:"regressions"`
}

type UnsupportedFinding struct {
	VulnerabilityID string `json:"vulnerability_id"`
	Package         string `json:"package"`
	Installed       string `json:"installed,omitempty"`
	FixedVersion    string `json:"fixed_version,omitempty"`
	Ecosystem       string `json:"ecosystem"`
	Target          string `json:"target,omitempty"`
	Reason          string `json:"reason"`
}

type FixExplanation struct {
	VulnerabilityID    string `json:"vulnerability_id"`
	Package            string `json:"package"`
	FileLocation       string `json:"file_location"`
	Decision           string `json:"decision"`
	Patch              string `json:"patch,omitempty"`
	Rationale          string `json:"rationale"`
	VerificationImpact string `json:"verification_impact"`
}

func SummarizeVerification(verification verifycheck.Report) *VerificationSummary {
	if verification.Mode == "" && len(verification.Modules) == 0 && len(verification.Regressions) == 0 {
		return nil
	}
	summary := verifycheck.Summarize(verification)
	return &VerificationSummary{
		Mode:        verification.Mode,
		Modules:     summary.Modules,
		Checks:      summary.Checks,
		OK:          summary.OK,
		Failed:      summary.Failed,
		Timeouts:    summary.Timeouts,
		Regressions: summary.Regressions,
	}
}

func BuildSummary(before, after *vuln.Report, patches []fixer.Patch) Summary {
	fixed := len(before.Findings) - len(after.Findings)
	if fixed < 0 {
		fixed = 0
	}
	unique := dedupePatches(patches)
	results := buildFindingResults(before.Findings, after.Findings, unique)
	unsupported := collectUnsupportedFindings(after.Findings)
	return Summary{
		Before:      len(before.Findings),
		Fixed:       fixed,
		After:       len(after.Findings),
		Patches:     unique,
		Findings:    results,
		Unsupported: unsupported,
	}
}

func ApplyVerificationRegressions(summary Summary, before, after *vuln.Report, verification *VerificationSummary) Summary {
	if verification == nil || verification.Regressions == 0 {
		return summary
	}

	summary.Verification = verification
	for index := range summary.Findings {
		if summary.Findings[index].Fixed {
			summary.Findings[index].Fixed = false
			summary.Findings[index].Reason = "verification regressed after patch"
		}
	}
	summary.Fixed = 0
	summary.After = verificationAdjustedAfterCount(before, after)
	return summary
}

func verificationAdjustedAfterCount(before, after *vuln.Report) int {
	if before == nil {
		if after == nil {
			return 0
		}
		return len(after.Findings)
	}

	beforeKeys := findingKeys(before.Findings)
	afterKeys := findingKeys(nil)
	if after != nil {
		afterKeys = findingKeys(after.Findings)
	}

	newAfter := 0
	for key := range afterKeys {
		if _, ok := beforeKeys[key]; ok {
			continue
		}
		newAfter++
	}

	return len(before.Findings) + newAfter
}

func findingKeys(findings []vuln.Finding) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, finding := range findings {
		keys[findingIdentityKey(finding)] = struct{}{}
	}
	return keys
}

func findingIdentityKey(finding vuln.Finding) string {
	locations := findingLocationSet(finding.Locations)
	return finding.VulnerabilityID + "|" + finding.Package + "|" + finding.Ecosystem + "|" + joinLocations(locations)
}

func joinLocations(locations []string) string {
	if len(locations) == 0 {
		return ""
	}
	return strings.Join(locations, "\x1f")
}

func buildFindingResults(beforeFindings, afterFindings []vuln.Finding, patches []fixer.Patch) []FindingResult {
	beforeRows := buildFindingRows(beforeFindings)
	afterRows := buildFindingRows(afterFindings)

	afterByKey := map[string]findingRow{}
	for _, row := range afterRows {
		afterByKey[findingRowKey(row)] = row
	}

	beforeKeys := map[string]struct{}{}
	patchAttempts := buildPatchAttemptSet(patches)
	results := make([]FindingResult, 0, len(beforeRows))
	for _, row := range beforeRows {
		key := findingRowKey(row)
		beforeKeys[key] = struct{}{}
		after, stillPresent := afterByKey[key]
		if !stillPresent {
			results = append(results, FindingResult{
				VulnerabilityID: row.VulnerabilityID,
				Package:         row.Package,
				FileLocation:    row.FileLocation,
				Fixed:           true,
			})
			continue
		}

		reason := after.Reason
		if reason == "" {
			if patchAttempts[patchAttemptKey(row.Package, row.LocationPath, row.FileLocation)] {
				reason = "patched package but vulnerability still reported"
			} else if !row.Fixable {
				reason = "not supported by automated fixer"
			} else {
				reason = "no automated patch was applied"
			}
		}

		results = append(results, FindingResult{
			VulnerabilityID: row.VulnerabilityID,
			Package:         row.Package,
			FileLocation:    row.FileLocation,
			Fixed:           false,
			Reason:          reason,
		})
	}

	for _, row := range afterRows {
		key := findingRowKey(row)
		if _, existedBefore := beforeKeys[key]; existedBefore {
			continue
		}
		reason := "new vulnerability detected after fixes"
		if row.Reason != "" {
			reason = row.Reason
		}
		results = append(results, FindingResult{
			VulnerabilityID: row.VulnerabilityID,
			Package:         row.Package,
			FileLocation:    row.FileLocation,
			Fixed:           false,
			Reason:          reason,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		left, right := results[i], results[j]
		if left.VulnerabilityID != right.VulnerabilityID {
			return left.VulnerabilityID < right.VulnerabilityID
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.FileLocation != right.FileLocation {
			return left.FileLocation < right.FileLocation
		}
		if left.Fixed != right.Fixed {
			return left.Fixed
		}
		return left.Reason < right.Reason
	})
	return results
}

func patchAttemptKey(pkg, locationPath, fileLocation string) string {
	return pkg + "|" + locationPath + "|" + fileLocation
}

func findingRowKey(row findingRow) string {
	locationKey := row.LocationPath
	if locationKey == "" {
		locationKey = row.FileLocation
	}
	return row.VulnerabilityID + "|" + row.Package + "|" + locationKey
}

func collectUnsupportedFindings(findings []vuln.Finding) []UnsupportedFinding {
	seen := map[string]UnsupportedFinding{}
	for _, finding := range findings {
		reason := unsupportedReason(finding)
		if reason == "" {
			continue
		}
		target := ""
		if len(finding.Locations) > 0 {
			target = finding.Locations[0]
		}
		item := UnsupportedFinding{
			VulnerabilityID: finding.VulnerabilityID,
			Package:         finding.Package,
			Installed:       finding.Installed,
			FixedVersion:    finding.FixedVersion,
			Ecosystem:       finding.Ecosystem,
			Target:          target,
			Reason:          reason,
		}
		key := item.VulnerabilityID + "|" + item.Package + "|" + item.Target + "|" + item.FixedVersion
		seen[key] = item
	}

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]UnsupportedFinding, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func unsupportedReason(finding vuln.Finding) string {
	if finding.Ecosystem == "golang" && finding.Package == "stdlib" {
		return "requires Go toolchain upgrade"
	}
	return ""
}

func dedupePatches(patches []fixer.Patch) []fixer.Patch {
	seen := map[string]fixer.Patch{}
	for _, patch := range patches {
		key := patch.Manager + "|" + patch.Target + "|" + patch.Package + "|" + patch.From + "|" + patch.To
		seen[key] = patch
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]fixer.Patch, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func BuildFixExplanations(before, after *vuln.Report, patches []fixer.Patch, verification *VerificationSummary) []FixExplanation {
	if before == nil {
		return nil
	}

	afterRows := buildFindingRows(nil)
	if after != nil {
		afterRows = buildFindingRows(after.Findings)
	}
	afterKeys := map[string]struct{}{}
	for _, row := range afterRows {
		afterKeys[findingRowKey(row)] = struct{}{}
	}

	patchesByPackage := map[string][]fixer.Patch{}
	for _, patch := range dedupePatches(patches) {
		patchesByPackage[patch.Package] = append(patchesByPackage[patch.Package], patch)
	}

	verificationImpact := "no verification regressions detected"
	verificationRegressed := false
	if verification != nil && verification.Regressions > 0 {
		verificationRegressed = true
		verificationImpact = fmt.Sprintf("%d verification regression(s) detected", verification.Regressions)
	}

	rows := buildFindingRows(before.Findings)
	explanations := make([]FixExplanation, 0, len(rows))
	for _, row := range rows {
		key := findingRowKey(row)
		_, stillPresent := afterKeys[key]
		decision := "fixed"
		if stillPresent || verificationRegressed {
			decision = "not fixed"
		}

		patchDescription := ""
		candidates := patchesByPackage[row.Package]
		if len(candidates) > 0 {
			patch := candidates[0]
			patchDescription = fmt.Sprintf("[%s] %s -> %s", patch.Manager, patch.From, patch.To)
		}

		rationale := "selected minimal fixed version reported by scanner"
		if decision == "not fixed" && patchDescription == "" {
			rationale = "no compatible automated patch was available for this finding"
		}

		explanations = append(explanations, FixExplanation{
			VulnerabilityID:    row.VulnerabilityID,
			Package:            row.Package,
			FileLocation:       row.FileLocation,
			Decision:           decision,
			Patch:              patchDescription,
			Rationale:          rationale,
			VerificationImpact: verificationImpact,
		})
	}

	sort.Slice(explanations, func(i, j int) bool {
		left := explanations[i]
		right := explanations[j]
		if left.VulnerabilityID != right.VulnerabilityID {
			return left.VulnerabilityID < right.VulnerabilityID
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		return left.FileLocation < right.FileLocation
	})
	return explanations
}
