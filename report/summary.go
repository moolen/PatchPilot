package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/moolen/patchpilot/fixer"
	"github.com/moolen/patchpilot/verifycheck"
	"github.com/moolen/patchpilot/vuln"
)

const (
	baselineFile     = "baseline-findings.json"
	summaryFile      = "summary.json"
	maxPrintedIssues = 50
	locationGoMod    = "go.mod"
	locationDocker   = "dockerfile"
)

type Summary struct {
	Before       int                  `json:"before"`
	Fixed        int                  `json:"fixed"`
	After        int                  `json:"after"`
	Patches      []fixer.Patch        `json:"patches,omitempty"`
	Findings     []FindingResult      `json:"findings,omitempty"`
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

func PrintCurrent(w io.Writer, repo string, report *vuln.Report) {
	rows := buildFindingRows(report.Findings)
	unsupported := 0
	for _, row := range rows {
		if !row.Fixable {
			unsupported++
		}
	}

	fmt.Fprintf(w, "Repository: %s\n", repo)
	fmt.Fprintf(w, "Findings with fix version: %d\n", len(report.Findings))
	fmt.Fprintf(w, "Unsupported by cvefix: %d\n", unsupported)
	fmt.Fprintf(w, "Ignored without fix version: %d\n", report.IgnoredWithoutFix)
	fmt.Fprintf(w, "Ignored by policy: %d\n", report.IgnoredByPolicy)
	if len(rows) == 0 {
		return
	}

	fmt.Fprintln(w, "Findings:")
	limit := len(rows)
	if limit > maxPrintedIssues {
		limit = maxPrintedIssues
	}

	table := make([][]string, 0, limit)
	for _, row := range rows[:limit] {
		fixable := "yes"
		if !row.Fixable {
			fixable = "no"
		}
		table = append(table, []string{row.VulnerabilityID, row.Package, row.FileLocation, fixable})
	}
	printTable(w, []string{"CVE", "Package", "File Location", "Fixable"}, table)
	if len(rows) > limit {
		fmt.Fprintf(w, "... %d more findings written to .cvefix/findings.json\n", len(rows)-limit)
	}
}

func PrintSummary(w io.Writer, summary Summary) {
	fmt.Fprintf(w, "Vulnerabilities before: %d\n", summary.Before)
	fmt.Fprintf(w, "Vulnerabilities fixed: %d\n", summary.Fixed)
	fmt.Fprintf(w, "Remaining: %d\n", summary.After)
	if len(summary.Findings) > 0 {
		fmt.Fprintln(w, "Fix results:")
		table := make([][]string, 0, len(summary.Findings))
		for _, finding := range summary.Findings {
			status := "fixed"
			reason := "-"
			if !finding.Fixed {
				status = "not fixed"
				reason = finding.Reason
				if reason == "" {
					reason = "still vulnerable after fix attempt"
				}
			}
			table = append(table, []string{finding.VulnerabilityID, finding.Package, finding.FileLocation, status, reason})
		}
		printTable(w, []string{"CVE", "Package", "File Location", "Status", "Reason"}, table)
	}
	if len(summary.Patches) > 0 {
		fmt.Fprintln(w, "Patched dependencies:")
		for _, patch := range summary.Patches {
			fmt.Fprintf(w, "- [%s] %s: %s -> %s (%s)\n", patch.Manager, patch.Package, patch.From, patch.To, patch.Target)
		}
	}
	if len(summary.Unsupported) > 0 {
		fmt.Fprintln(w, "Unsupported by cvefix (still actionable):")
		for _, finding := range summary.Unsupported {
			target := finding.Target
			if target == "" {
				target = "unknown target"
			}
			fmt.Fprintf(w, "- [%s] %s %s -> %s (%s; %s)\n", finding.VulnerabilityID, finding.Package, finding.Installed, finding.FixedVersion, target, finding.Reason)
		}
	}
}

type findingRow struct {
	VulnerabilityID string
	Package         string
	FileLocation    string
	LocationPath    string
	Fixable         bool
	Reason          string
}

func buildFindingRows(findings []vuln.Finding) []findingRow {
	rows := make([]findingRow, 0)
	for _, finding := range findings {
		locations := findingLocationSet(finding.Locations)
		if len(locations) == 0 {
			locations = []string{""}
		}
		reason := unsupportedReason(finding)
		for _, location := range locations {
			fileLocation := classifyFileLocation(location)
			fixable := isFixable(finding, fileLocation, reason)
			rows = append(rows, findingRow{
				VulnerabilityID: finding.VulnerabilityID,
				Package:         finding.Package,
				FileLocation:    fileLocation,
				LocationPath:    location,
				Fixable:         fixable,
				Reason:          reason,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		if left.VulnerabilityID != right.VulnerabilityID {
			return left.VulnerabilityID < right.VulnerabilityID
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.FileLocation != right.FileLocation {
			return left.FileLocation < right.FileLocation
		}
		return left.LocationPath < right.LocationPath
	})
	return rows
}

func findingLocationSet(locations []string) []string {
	if len(locations) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(locations))
	for _, location := range locations {
		if _, ok := seen[location]; ok {
			continue
		}
		seen[location] = struct{}{}
		result = append(result, location)
	}
	sort.Strings(result)
	return result
}

func classifyFileLocation(location string) string {
	if location == "" {
		return "unknown"
	}
	base := filepath.Base(location)
	if base == locationGoMod {
		return locationGoMod
	}
	if strings.EqualFold(base, "Dockerfile") || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile") {
		return locationDocker
	}
	return "unknown"
}

func isFixable(finding vuln.Finding, fileLocation, reason string) bool {
	if reason != "" {
		return false
	}
	switch finding.Ecosystem {
	case "golang":
		return fileLocation == locationGoMod
	case "deb", "apk", "rpm":
		return fileLocation == locationDocker
	default:
		return false
	}
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

func buildPatchAttemptSet(patches []fixer.Patch) map[string]bool {
	attempts := map[string]bool{}
	for _, patch := range patches {
		fileLocation := classifyFileLocation(patch.Target)
		attempts[patchAttemptKey(patch.Package, patch.Target, fileLocation)] = true
	}
	return attempts
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

func printTable(w io.Writer, headers []string, rows [][]string) {
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(table, strings.Join(row, "\t"))
	}
	_ = table.Flush()
}

func WriteBaseline(repo string, baseline *vuln.Report) error {
	if err := ensureStateDir(repo); err != nil {
		return err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	path := filepath.Join(repo, ".cvefix", baselineFile)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func ReadBaseline(repo string) (*vuln.Report, error) {
	data, err := os.ReadFile(filepath.Join(repo, ".cvefix", baselineFile))
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var report vuln.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode baseline: %w", err)
	}
	return &report, nil
}

func WriteSummary(repo string, summary Summary) error {
	if err := ensureStateDir(repo); err != nil {
		return err
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	path := filepath.Join(repo, ".cvefix", summaryFile)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
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

func ensureStateDir(repo string) error {
	if err := os.MkdirAll(filepath.Join(repo, ".cvefix"), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	return nil
}
