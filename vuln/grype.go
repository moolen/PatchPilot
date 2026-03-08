package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/moolen/patchpilot/policy"
	"github.com/moolen/patchpilot/sbom"
)

const (
	rawFileName        = "vulns.json"
	normalizedFileName = "findings.json"
)

type Report struct {
	Findings          []Finding `json:"findings"`
	RawMatches        int       `json:"raw_matches"`
	IgnoredWithoutFix int       `json:"ignored_without_fix"`
	IgnoredByPolicy   int       `json:"ignored_by_policy,omitempty"`
	RawPath           string    `json:"raw_path"`
}

type IgnoreRule struct {
	ID        string
	Package   string
	Ecosystem string
	Path      string
}

type ScanOptions struct {
	IgnoreRules []IgnoreRule
	SkipPaths   []string
}

type Finding struct {
	VulnerabilityID string   `json:"vulnerability_id"`
	Package         string   `json:"package"`
	Installed       string   `json:"installed"`
	FixedVersion    string   `json:"fixed_version"`
	Ecosystem       string   `json:"ecosystem"`
	Locations       []string `json:"locations,omitempty"`
	PURL            string   `json:"purl,omitempty"`
	Type            string   `json:"type,omitempty"`
	Language        string   `json:"language,omitempty"`
	Namespace       string   `json:"namespace,omitempty"`
}

type rawReport struct {
	Matches []rawMatch `json:"matches"`
}

type rawMatch struct {
	Artifact      rawArtifact      `json:"artifact"`
	Vulnerability rawVulnerability `json:"vulnerability"`
}

type rawArtifact struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Type      string        `json:"type"`
	Language  string        `json:"language"`
	PURL      string        `json:"purl"`
	Locations []rawLocation `json:"locations"`
}

type rawLocation struct {
	Path string `json:"path"`
}

type rawVulnerability struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	Fix       rawFix `json:"fix"`
}

type rawFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

func Scan(ctx context.Context, repo string) (*Report, error) {
	return ScanWithOptions(ctx, repo, ScanOptions{})
}

func ScanWithOptions(ctx context.Context, repo string, options ScanOptions) (*Report, error) {
	if err := ensureTool("grype"); err != nil {
		return nil, err
	}

	stateDir := filepath.Join(repo, ".cvefix")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	rawPath := filepath.Join(stateDir, rawFileName)
	var rawBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	cmd := exec.CommandContext(ctx, "grype", "sbom:"+sbom.Path(repo), "-o", "json")
	cmd.Stdout = &rawBuffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuffer)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run grype: %w%s", err, formatCapturedStderr(stderrBuffer.String()))
	}

	rawData := rawBuffer.Bytes()
	decoded, err := parseRawReportBytes(rawData)
	if err != nil {
		if writeErr := os.WriteFile(rawPath, rawData, 0o644); writeErr == nil {
			return nil, fmt.Errorf("decode vuln output: %w (raw output at %s)%s", err, rawPath, formatCapturedStderr(stderrBuffer.String()))
		}
		return nil, fmt.Errorf("decode vuln output: %w%s", err, formatCapturedStderr(stderrBuffer.String()))
	}

	if err := os.WriteFile(rawPath, rawData, 0o644); err != nil {
		return nil, fmt.Errorf("write vuln output: %w", err)
	}

	result := normalizeReport(repo, decoded, options)
	result.RawPath = rawPath

	if err := writeNormalized(repo, result); err != nil {
		return nil, err
	}

	return result, nil
}

func parseRawReport(path string) (*rawReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vuln output: %w", err)
	}

	decoded, err := parseRawReportBytes(data)
	if err != nil {
		return nil, fmt.Errorf("decode vuln output: %w", err)
	}
	return decoded, nil
}

func parseRawReportBytes(data []byte) (*rawReport, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty JSON output")
	}

	var report rawReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

func formatCapturedStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return "\ngrype stderr:\n" + stderr
}

func normalizeReport(repo string, decoded *rawReport, options ScanOptions) *Report {
	result := &Report{RawMatches: len(decoded.Matches)}
	for _, match := range decoded.Matches {
		ecosystem := detectEcosystem(match.Artifact)
		if ecosystem == "" {
			continue
		}

		fixed := minimalFixedVersion(ecosystem, match.Vulnerability.Fix.Versions)
		if fixed == "" {
			result.IgnoredWithoutFix++
			continue
		}

		finding := Finding{
			VulnerabilityID: match.Vulnerability.ID,
			Package:         match.Artifact.Name,
			Installed:       match.Artifact.Version,
			FixedVersion:    fixed,
			Ecosystem:       ecosystem,
			Locations:       normalizeLocations(repo, match.Artifact.Locations),
			PURL:            match.Artifact.PURL,
			Type:            match.Artifact.Type,
			Language:        match.Artifact.Language,
			Namespace:       match.Vulnerability.Namespace,
		}
		if shouldSkipFindingByPath(repo, finding, options.SkipPaths) {
			result.IgnoredByPolicy++
			continue
		}
		if shouldIgnoreFinding(repo, finding, options.IgnoreRules) {
			result.IgnoredByPolicy++
			continue
		}
		result.Findings = append(result.Findings, finding)
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		left := result.Findings[i]
		right := result.Findings[j]
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

	return result
}

func shouldSkipFindingByPath(repo string, finding Finding, skipPaths []string) bool {
	if len(skipPaths) == 0 {
		return false
	}
	if len(finding.Locations) == 0 {
		return false
	}
	for _, location := range finding.Locations {
		if policy.ShouldSkipPath(repo, location, skipPaths) {
			return true
		}
	}
	return false
}

func shouldIgnoreFinding(repo string, finding Finding, rules []IgnoreRule) bool {
	for _, rule := range rules {
		if !strings.EqualFold(strings.TrimSpace(rule.ID), strings.TrimSpace(finding.VulnerabilityID)) {
			continue
		}
		if rule.Package != "" && !strings.EqualFold(rule.Package, finding.Package) {
			continue
		}
		if rule.Ecosystem != "" && !strings.EqualFold(rule.Ecosystem, finding.Ecosystem) {
			continue
		}
		if strings.TrimSpace(rule.Path) != "" {
			matched := false
			for _, location := range finding.Locations {
				if policy.LocationMatches(repo, location, rule.Path) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return true
	}
	return false
}

func writeNormalized(repo string, report *Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal normalized findings: %w", err)
	}

	outputPath := filepath.Join(repo, ".cvefix", normalizedFileName)
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write normalized findings: %w", err)
	}
	return nil
}

func ReadNormalized(repo string) (*Report, error) {
	data, err := os.ReadFile(filepath.Join(repo, ".cvefix", normalizedFileName))
	if err != nil {
		return nil, fmt.Errorf("read normalized findings: %w", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode normalized findings: %w", err)
	}
	return &report, nil
}

func detectEcosystem(artifact rawArtifact) string {
	if artifact.Language == "go" || artifact.Type == "go-module" || strings.HasPrefix(artifact.PURL, "pkg:golang/") {
		return "golang"
	}

	switch artifact.Type {
	case "deb", "apk", "rpm":
		return artifact.Type
	}

	if strings.HasPrefix(artifact.PURL, "pkg:deb/") {
		return "deb"
	}
	if strings.HasPrefix(artifact.PURL, "pkg:apk/") {
		return "apk"
	}
	if strings.HasPrefix(artifact.PURL, "pkg:rpm/") {
		return "rpm"
	}

	return ""
}

func minimalFixedVersion(ecosystem string, versions []string) string {
	trimmed := make([]string, 0, len(versions))
	for _, version := range versions {
		version = strings.TrimSpace(version)
		if version == "" {
			continue
		}
		trimmed = append(trimmed, version)
	}
	if len(trimmed) == 0 {
		return ""
	}

	if ecosystem != "golang" {
		sort.Strings(trimmed)
		return trimmed[0]
	}

	valid := make([]string, 0, len(trimmed))
	for _, version := range trimmed {
		canonical := canonicalSemver(version)
		if canonical == "" {
			continue
		}
		valid = append(valid, canonical)
	}
	if len(valid) == 0 {
		return ""
	}

	sort.Slice(valid, func(i, j int) bool {
		return semver.Compare(valid[i], valid[j]) < 0
	})
	return valid[0]
}

func canonicalSemver(version string) string {
	if version == "" {
		return ""
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	canonical := semver.Canonical(version)
	if canonical != "" {
		return canonical
	}
	if semver.IsValid(version) {
		return version
	}
	return ""
}

func normalizeLocations(repo string, locations []rawLocation) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(locations))
	for _, location := range locations {
		path := strings.TrimSpace(location.Path)
		if path == "" {
			continue
		}
		path = resolveLocation(repo, path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func resolveLocation(repo, location string) string {
	if !filepath.IsAbs(location) {
		return filepath.Clean(filepath.Join(repo, location))
	}

	if _, err := os.Stat(location); err == nil {
		return filepath.Clean(location)
	}

	candidate := filepath.Join(repo, strings.TrimPrefix(location, string(filepath.Separator)))
	if _, err := os.Stat(candidate); err == nil {
		return filepath.Clean(candidate)
	}

	return ""
}

func ensureTool(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required tool %q not found in PATH", name)
	}
	return nil
}
