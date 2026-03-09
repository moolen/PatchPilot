package report

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/vuln"
)

func PrintCurrent(w io.Writer, repo string, report *vuln.Report) {
	rows := buildFindingRows(report.Findings)
	unsupported := 0
	for _, row := range rows {
		if !row.Fixable {
			unsupported++
		}
	}

	_, _ = fmt.Fprintf(w, "Repository: %s\n", repo)
	_, _ = fmt.Fprintf(w, "Findings with fix version: %d\n", len(report.Findings))
	_, _ = fmt.Fprintf(w, "Unsupported by PatchPilot: %d\n", unsupported)
	_, _ = fmt.Fprintf(w, "Ignored without fix version: %d\n", report.IgnoredWithoutFix)
	_, _ = fmt.Fprintf(w, "Ignored by policy: %d\n", report.IgnoredByPolicy)
	if len(rows) == 0 {
		return
	}

	_, _ = fmt.Fprintln(w, "Findings:")
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
		_, _ = fmt.Fprintf(w, "... %d more findings written to .patchpilot/findings.json\n", len(rows)-limit)
	}
}

func PrintSummary(w io.Writer, summary Summary) {
	_, _ = fmt.Fprintf(w, "Vulnerabilities before: %d\n", summary.Before)
	_, _ = fmt.Fprintf(w, "Vulnerabilities fixed: %d\n", summary.Fixed)
	_, _ = fmt.Fprintf(w, "Remaining: %d\n", summary.After)
	if len(summary.Findings) > 0 {
		_, _ = fmt.Fprintln(w, "Fix results:")
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
		_, _ = fmt.Fprintln(w, "Patched dependencies:")
		for _, patch := range summary.Patches {
			_, _ = fmt.Fprintf(w, "- [%s] %s: %s -> %s (%s)\n", patch.Manager, patch.Package, patch.From, patch.To, patch.Target)
		}
	}
	if len(summary.Unsupported) > 0 {
		_, _ = fmt.Fprintln(w, "Unsupported by PatchPilot (still actionable):")
		for _, finding := range summary.Unsupported {
			target := finding.Target
			if target == "" {
				target = "unknown target"
			}
			_, _ = fmt.Fprintf(w, "- [%s] %s %s -> %s (%s; %s)\n", finding.VulnerabilityID, finding.Package, finding.Installed, finding.FixedVersion, target, finding.Reason)
		}
	}
	if len(summary.Explanations) > 0 {
		_, _ = fmt.Fprintln(w, "Fix explanations:")
		for _, explanation := range summary.Explanations {
			patch := explanation.Patch
			if patch == "" {
				patch = "no patch applied"
			}
			_, _ = fmt.Fprintf(w, "- %s %s (%s): %s; %s; verification=%s\n",
				explanation.VulnerabilityID,
				explanation.Package,
				explanation.FileLocation,
				explanation.Decision,
				patch,
				explanation.VerificationImpact,
			)
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
	if base == "package.json" {
		return locationNPM
	}
	if base == "package-lock.json" || base == "npm-shrinkwrap.json" {
		return locationNPMLock
	}
	if strings.EqualFold(base, "pnpm-lock.yaml") {
		return locationPnpmLock
	}
	if strings.EqualFold(base, "yarn.lock") {
		return locationYarnLock
	}
	if strings.EqualFold(base, "composer.json") {
		return locationComposer
	}
	if strings.EqualFold(base, "pom.xml") {
		return locationMaven
	}
	if strings.EqualFold(base, "build.gradle") || strings.EqualFold(base, "build.gradle.kts") {
		return locationGradle
	}
	if strings.EqualFold(base, "Cargo.toml") {
		return locationCargo
	}
	if strings.HasSuffix(strings.ToLower(base), ".csproj") {
		return locationNuGet
	}
	if strings.EqualFold(base, "pyproject.toml") {
		return locationPyProject
	}
	if strings.EqualFold(base, "poetry.lock") {
		return locationPoetryLock
	}
	if strings.EqualFold(base, "uv.lock") {
		return locationUVLock
	}
	if strings.EqualFold(base, "requirements.txt") || (strings.HasPrefix(strings.ToLower(base), "requirements") && strings.HasSuffix(strings.ToLower(base), ".txt")) {
		return locationPIP
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
	case "npm":
		return fileLocation == locationNPM || fileLocation == locationNPMLock || fileLocation == locationPnpmLock || fileLocation == locationYarnLock
	case "pypi", "pip", "python":
		return fileLocation == locationPIP || fileLocation == locationPyProject || fileLocation == locationPoetryLock || fileLocation == locationUVLock
	case "maven", "java":
		return fileLocation == locationMaven
	case "gradle":
		return fileLocation == locationGradle
	case "cargo", "rust":
		return fileLocation == locationCargo
	case "nuget", ".net", "dotnet", "csharp", "c#":
		return fileLocation == locationNuGet
	case "composer", "php":
		return fileLocation == locationComposer
	default:
		return false
	}
}

func buildPatchAttemptSet(patches []fixer.Patch) map[string]bool {
	attempts := map[string]bool{}
	for _, patch := range patches {
		fileLocation := classifyFileLocation(patch.Target)
		attempts[patchAttemptKey(patch.Package, patch.Target, fileLocation)] = true
	}
	return attempts
}

func printTable(w io.Writer, headers []string, rows [][]string) {
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, strings.Join(headers, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(table, strings.Join(row, "\t"))
	}
	_ = table.Flush()
}
