package githubapp

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/sbom"
	"github.com/moolen/patchpilot/internal/vuln"
)

func vulnOptionsFromPolicy(cfg *policy.Config) vuln.ScanOptions {
	if cfg == nil {
		return vuln.ScanOptions{}
	}
	rules := make([]vuln.IgnoreRule, 0)
	for _, id := range cfg.Exclude.CVEs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		rules = append(rules, vuln.IgnoreRule{ID: id})
	}
	for _, selector := range cfg.Exclude.CVERules {
		rules = append(rules, vuln.IgnoreRule{
			ID:        selector.ID,
			Package:   selector.Package,
			Ecosystem: selector.Ecosystem,
			Path:      selector.Path,
		})
	}
	for _, selector := range cfg.Exclude.Vulnerabilities {
		rules = append(rules, vuln.IgnoreRule{
			ID:        selector.ID,
			Package:   selector.Package,
			Ecosystem: selector.Ecosystem,
			Path:      selector.Path,
		})
	}
	return vuln.ScanOptions{
		IgnoreRules: rules,
		SkipPaths:   append([]string(nil), cfg.Scan.SkipPaths...),
	}
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
			if _, exists := seen[key]; exists {
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

func relativizeFindingLocations(repoPath string, report *vuln.Report) {
	if report == nil {
		return
	}
	for index := range report.Findings {
		locations := make([]string, 0, len(report.Findings[index].Locations))
		seen := map[string]struct{}{}
		for _, location := range report.Findings[index].Locations {
			location = strings.TrimSpace(location)
			if location == "" {
				continue
			}
			if filepath.IsAbs(location) {
				if relative, err := filepath.Rel(repoPath, location); err == nil {
					location = filepath.ToSlash(relative)
				}
			}
			location = filepath.ToSlash(strings.TrimSpace(location))
			if _, exists := seen[location]; exists {
				continue
			}
			seen[location] = struct{}{}
			locations = append(locations, location)
		}
		sort.Strings(locations)
		report.Findings[index].Locations = locations
	}
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

func (service *Service) scanMappedOCIImage(ctx context.Context, repoPath, repoKey string, cfg *policy.Config) (*vuln.Report, string, string, string, error) {
	if service.runtime == nil {
		return nil, "", "", "", nil
	}
	entry, ok := service.runtime.RepositoryConfig(repoKey)
	if !ok {
		return nil, "", "", "", nil
	}
	imageRepository := strings.TrimSpace(entry.ImageRepository)
	if imageRepository == "" {
		return nil, "", "", "", nil
	}
	tag, err := fixer.ResolveLatestSemverImageTag(ctx, imageRepository)
	if err != nil {
		return nil, "", "", imageRepository, fmt.Errorf("resolve latest semver OCI tag: %w", err)
	}
	resolvedImage := imageRepository + ":" + tag
	if _, stderr, err := runCommand(ctx, repoPath, nil, "docker", "pull", resolvedImage); err != nil {
		return nil, "", tag, imageRepository, fmt.Errorf("docker pull %s: %w\nstderr:\n%s", resolvedImage, err, truncateForComment(stderr))
	}
	sbomPath := filepath.Join(repoPath, ".patchpilot", "oci-image-sbom.json")
	if _, err := sbom.GenerateForSourceWithOptions(ctx, repoPath, "image:"+resolvedImage, sbomPath, sbom.Options{}); err != nil {
		return nil, resolvedImage, tag, imageRepository, fmt.Errorf("generate image sbom: %w", err)
	}
	options := vulnOptionsFromPolicy(cfg)
	options.OutputPrefix = "oci-image"
	report, err := vuln.ScanSBOMWithOptions(ctx, repoPath, sbomPath, options)
	if err != nil {
		return nil, resolvedImage, tag, imageRepository, fmt.Errorf("scan image sbom: %w", err)
	}
	targetDockerfiles := entry.Dockerfiles
	if len(targetDockerfiles) == 0 {
		targetDockerfiles, err = discoverDockerfiles(repoPath, cfg)
		if err != nil {
			return nil, resolvedImage, tag, imageRepository, err
		}
	}
	if len(targetDockerfiles) == 0 {
		targetDockerfiles = []string{"Dockerfile"}
	}
	mapped := make([]vuln.Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if !isContainerPackageEcosystem(finding.Ecosystem) {
			continue
		}
		finding.Locations = append([]string(nil), targetDockerfiles...)
		mapped = append(mapped, finding)
	}
	report.Findings = mapped
	return report, resolvedImage, tag, imageRepository, nil
}

func discoverDockerfiles(repoPath string, cfg *policy.Config) ([]string, error) {
	skipPaths := []string(nil)
	if cfg != nil {
		skipPaths = append(skipPaths, cfg.Scan.SkipPaths...)
	}
	result := make([]string, 0)
	err := filepath.WalkDir(repoPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(repoPath, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(relative)
		if normalized == ".git" || strings.HasPrefix(normalized, ".git/") || isPatchPilotArtifactPath(normalized) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		for _, skip := range skipPaths {
			if matchesSkipPath(normalized, skip) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") || strings.HasSuffix(name, ".Dockerfile") {
			result = append(result, normalized)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover dockerfiles: %w", err)
	}
	sort.Strings(result)
	return result, nil
}

func matchesSkipPath(path, pattern string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	if path == pattern {
		return true
	}
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	return false
}

func isContainerPackageEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "deb", "apk", "rpm":
		return true
	default:
		return false
	}
}
