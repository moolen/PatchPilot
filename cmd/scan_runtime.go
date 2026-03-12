package cmd

import (
	"context"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/sbom"
	"github.com/moolen/patchpilot/internal/vuln"
)

type ociScanContext struct {
	RepositoryKey string
	MappingFile   string
}

func generateSBOM(ctx context.Context, repo string, cfg *policy.Config) error {
	if _, err := sbom.GenerateWithOptions(ctx, repo, sbomOptionsFromPolicy(cfg)); err != nil {
		return wrapWithExitCode(ExitCodeScanFailed, err)
	}
	return nil
}

func scanVulnerabilitiesForRun(ctx context.Context, repo string, cfg *policy.Config, runID, phase, command string, ociContext ociScanContext) (*vuln.Report, error) {
	report, err := vuln.ScanWithOptions(ctx, repo, vulnOptionsFromPolicy(cfg))
	if err != nil {
		return nil, wrapWithExitCode(ExitCodeScanFailed, err)
	}
	artifactReport, err := scanArtifactVulnerabilities(ctx, repo, cfg, artifactScanOptions{
		RunID:         runID,
		Phase:         phase,
		Command:       command,
		RepositoryKey: ociContext.RepositoryKey,
		MappingFile:   ociContext.MappingFile,
	})
	if err != nil {
		return nil, wrapWithExitCode(ExitCodeScanFailed, err)
	}
	return mergeVulnerabilityReports(report, artifactReport), nil
}

func mergeVulnerabilityReports(reports ...*vuln.Report) *vuln.Report {
	merged := &vuln.Report{}
	seen := map[string]struct{}{}
	for _, report := range reports {
		if report == nil {
			continue
		}
		merged.RawMatches += report.RawMatches
		merged.IgnoredWithoutFix += report.IgnoredWithoutFix
		merged.IgnoredByPolicy += report.IgnoredByPolicy
		if merged.RawPath == "" {
			merged.RawPath = report.RawPath
		}
		for _, finding := range report.Findings {
			key := findingMergeKey(finding)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged.Findings = append(merged.Findings, finding)
		}
	}

	sort.Slice(merged.Findings, func(i, j int) bool {
		left := merged.Findings[i]
		right := merged.Findings[j]
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.VulnerabilityID != right.VulnerabilityID {
			return left.VulnerabilityID < right.VulnerabilityID
		}
		return left.FixedVersion < right.FixedVersion
	})
	return merged
}

func findingMergeKey(finding vuln.Finding) string {
	locations := append([]string(nil), finding.Locations...)
	sort.Strings(locations)
	return strings.Join([]string{
		finding.VulnerabilityID,
		finding.Package,
		finding.FixedVersion,
		finding.Ecosystem,
		strings.Join(locations, "|"),
	}, "::")
}
