package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/sbom"
	"github.com/moolen/patchpilot/internal/vuln"
	"gopkg.in/yaml.v3"
)

type artifactScanOptions struct {
	RunID         string
	Phase         string
	Command       string
	RepositoryKey string
	MappingFile   string
}

type externalImageScanTarget struct {
	Source      string
	Dockerfiles []string
	TagStrategy string
	Origin      string
}

type ociMappingFile struct {
	OCI ociMappingSection `yaml:"oci"`
}

type ociMappingSection struct {
	Mappings []ociRepositoryMapping `yaml:"mappings"`
}

type ociRepositoryMapping struct {
	Repo   string                        `yaml:"repo"`
	Images []policy.OCIExternalImageSpec `yaml:"images"`
}

func scanArtifactVulnerabilities(ctx context.Context, repo string, cfg *policy.Config, options artifactScanOptions) (*vuln.Report, error) {
	targets, err := resolveExternalImageScanTargets(repo, cfg, options)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		logProgress("external OCI scan mapping: no configured images")
		return nil, nil
	}
	logProgress("external OCI scan mapping: resolved %d image target(s)", len(targets))

	reports := make([]*vuln.Report, 0, len(targets))
	for index, target := range targets {
		tag, err := resolveExternalImageTag(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("resolve tag for external OCI image %q: %w", target.Source, err)
		}
		resolvedImage := target.Source + ":" + tag
		logProgress(
			"external OCI image %q (%s): selected tag=%q dockerfiles=%s",
			target.Source,
			target.Origin,
			tag,
			strings.Join(target.Dockerfiles, ","),
		)

		if _, stderr, err := runBinaryCommand(ctx, repo, nil, 10*time.Minute, "docker", "pull", resolvedImage); err != nil {
			return nil, fmt.Errorf("pull external OCI image %q: %w%s", resolvedImage, err, formatCommandStderr(stderr))
		}

		sbomName := fmt.Sprintf("%02d-%s-sbom.json", index+1, sanitizeArtifactName(target.Source))
		sbomPath := filepath.Join(repo, ".patchpilot", "oci", sbomName)
		if _, err := sbom.GenerateForSourceWithOptions(ctx, repo, "image:"+resolvedImage, sbomPath, sbom.Options{}); err != nil {
			return nil, fmt.Errorf("generate SBOM for external OCI image %q: %w", resolvedImage, err)
		}

		scanOptions := vulnOptionsFromPolicy(cfg)
		scanOptions.OutputPrefix = fmt.Sprintf("oci-external-%02d", index+1)
		imageReport, err := vuln.ScanSBOMWithOptions(ctx, repo, sbomPath, scanOptions)
		if err != nil {
			return nil, fmt.Errorf("scan SBOM for external OCI image %q: %w", resolvedImage, err)
		}

		mappedFindings := make([]vuln.Finding, 0, len(imageReport.Findings))
		for _, finding := range imageReport.Findings {
			if !isContainerPackageEcosystem(finding.Ecosystem) {
				continue
			}
			finding.Locations = append([]string(nil), target.Dockerfiles...)
			mappedFindings = append(mappedFindings, finding)
		}
		imageReport.Findings = mappedFindings
		logProgress("external OCI image %q: mapped %d container finding(s)", resolvedImage, len(mappedFindings))
		reports = append(reports, imageReport)
	}
	return mergeVulnerabilityReports(reports...), nil
}

func resolveExternalImageTag(ctx context.Context, target externalImageScanTarget) (string, error) {
	strategy := strings.TrimSpace(target.TagStrategy)
	if strategy == "" || strings.EqualFold(strategy, policy.OCITagStrategyLatestSemver) {
		tag, err := fixer.ResolveLatestSemverImageTag(ctx, target.Source)
		if err != nil {
			return "", err
		}
		return tag, nil
	}
	return strategy, nil
}

func resolveExternalImageScanTargets(repo string, cfg *policy.Config, options artifactScanOptions) ([]externalImageScanTarget, error) {
	repositoryKey := normalizeRepositoryKey(options.RepositoryKey)
	if strings.TrimSpace(options.MappingFile) != "" && repositoryKey == "" {
		return nil, errors.New("repository key is required when --oci-mapping-file is set")
	}

	fromMapping, err := loadExternalImageSpecsFromMappingFile(options.MappingFile, repositoryKey)
	if err != nil {
		return nil, err
	}

	fromPolicy := []policy.OCIExternalImageSpec(nil)
	if cfg != nil {
		fromPolicy = append(fromPolicy, cfg.OCI.ExternalImages...)
	}

	merged := mergeExternalImageSpecs(fromMapping, fromPolicy)
	if len(merged) == 0 {
		return nil, nil
	}

	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}

	targets := make([]externalImageScanTarget, 0, len(merged))
	for index, mergedSpec := range merged {
		spec := mergedSpec.Spec
		if strings.TrimSpace(spec.Source) == "" {
			return nil, fmt.Errorf("external OCI image source at index %d must not be empty", index)
		}
		if len(spec.Dockerfiles) == 0 {
			return nil, fmt.Errorf("external OCI image %q must configure at least one dockerfile", spec.Source)
		}

		dockerfiles := make([]string, 0, len(spec.Dockerfiles))
		seen := map[string]struct{}{}
		for fileIndex, dockerfile := range spec.Dockerfiles {
			resolved, err := resolvePathInsideRepo(repoAbs, dockerfile)
			if err != nil {
				return nil, fmt.Errorf("external OCI image %q dockerfiles[%d]: %w", spec.Source, fileIndex, err)
			}
			if _, err := os.Stat(resolved); err != nil {
				return nil, fmt.Errorf("external OCI image %q dockerfiles[%d]: %w", spec.Source, fileIndex, err)
			}
			relative, err := filepath.Rel(repoAbs, resolved)
			if err != nil {
				return nil, fmt.Errorf("external OCI image %q dockerfiles[%d]: %w", spec.Source, fileIndex, err)
			}
			normalized := filepath.ToSlash(relative)
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			dockerfiles = append(dockerfiles, normalized)
		}
		sort.Strings(dockerfiles)
		if len(dockerfiles) == 0 {
			return nil, fmt.Errorf("external OCI image %q has no usable dockerfiles", spec.Source)
		}

		tagStrategy := strings.TrimSpace(spec.Tag)
		if tagStrategy == "" {
			tagStrategy = policy.OCITagStrategyLatestSemver
		}
		targets = append(targets, externalImageScanTarget{
			Source:      strings.TrimSpace(spec.Source),
			Dockerfiles: dockerfiles,
			TagStrategy: tagStrategy,
			Origin:      mergedSpec.Origin,
		})
	}
	return targets, nil
}

type mappedExternalImageSpec struct {
	Spec   policy.OCIExternalImageSpec
	Origin string
}

func mergeExternalImageSpecs(base []policy.OCIExternalImageSpec, overlay []policy.OCIExternalImageSpec) []mappedExternalImageSpec {
	result := make([]mappedExternalImageSpec, 0, mergedExternalImageSpecCapacity(len(base), len(overlay)))
	indexBySource := map[string]int{}
	add := func(spec policy.OCIExternalImageSpec, origin string) {
		key := normalizeImageSourceKey(spec.Source)
		if key == "" {
			return
		}
		if index, exists := indexBySource[key]; exists {
			logProgress("external OCI mapping: source=%q overridden by %s (previous=%s)", strings.TrimSpace(spec.Source), origin, result[index].Origin)
			result[index] = mappedExternalImageSpec{Spec: spec, Origin: origin}
			return
		}
		indexBySource[key] = len(result)
		result = append(result, mappedExternalImageSpec{Spec: spec, Origin: origin})
	}
	for _, spec := range base {
		add(spec, "mapping-file")
	}
	for _, spec := range overlay {
		add(spec, "repo-policy")
	}
	return result
}

func mergedExternalImageSpecCapacity(baseLen, overlayLen int) int {
	if overlayLen >= 0 && baseLen <= math.MaxInt-overlayLen {
		return baseLen + overlayLen
	}
	return baseLen
}

func normalizeImageSourceKey(source string) string {
	return strings.ToLower(strings.TrimSpace(source))
}

func loadExternalImageSpecsFromMappingFile(path, repoKey string) ([]policy.OCIExternalImageSpec, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OCI mapping file %s: %w", path, err)
	}

	var cfg ociMappingFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode OCI mapping file %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode OCI mapping file %s: %w", path, err)
	}
	if extra != nil {
		return nil, fmt.Errorf("decode OCI mapping file %s: expected a single YAML document", path)
	}

	normalizedRepo := normalizeRepositoryKey(repoKey)
	if normalizedRepo == "" {
		return nil, fmt.Errorf("invalid repository key %q for OCI mapping lookup", repoKey)
	}

	result := []policy.OCIExternalImageSpec(nil)
	for index, mapping := range cfg.OCI.Mappings {
		rawRepo := strings.TrimSpace(mapping.Repo)
		if containsWildcard(rawRepo) {
			return nil, fmt.Errorf("oci.mappings[%d].repo must be an exact owner/repo match (wildcards are not allowed)", index)
		}
		normalizedMappingRepo := normalizeRepositoryKey(rawRepo)
		if normalizedMappingRepo == "" {
			return nil, fmt.Errorf("oci.mappings[%d].repo must be an exact owner/repo match", index)
		}
		if normalizedMappingRepo != normalizedRepo {
			continue
		}
		for imageIndex, image := range mapping.Images {
			image.Source = strings.TrimSpace(image.Source)
			if image.Source == "" {
				return nil, fmt.Errorf("oci.mappings[%d].images[%d].source must not be empty", index, imageIndex)
			}
			if len(image.Dockerfiles) == 0 {
				return nil, fmt.Errorf("oci.mappings[%d].images[%d].dockerfiles must not be empty", index, imageIndex)
			}
			image.Tag = strings.TrimSpace(image.Tag)
			result = append(result, image)
		}
	}
	return result, nil
}

func containsWildcard(value string) bool {
	return strings.ContainsAny(value, "*?[]")
}

func normalizeRepositoryKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return ""
	}
	owner := strings.TrimSpace(parts[0])
	repo := strings.TrimSpace(parts[1])
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}

func resolvePathInsideRepo(repoAbs, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is empty")
	}
	resolved := filepath.Clean(path)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(repoAbs, resolved)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(repoAbs, abs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes repository", path)
	}
	return abs, nil
}

func runBinaryCommand(ctx context.Context, dir string, env map[string]string, timeout time.Duration, name string, args ...string) (string, string, error) {
	runCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	command := exec.CommandContext(runCtx, name, args...)
	command.Dir = dir
	command.Env = append([]string{}, os.Environ()...)
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for key := range env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			command.Env = append(command.Env, key+"="+env[key])
		}
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	err := command.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return stdoutBuffer.String(), stderrBuffer.String(), fmt.Errorf("timed out after %s", timeout)
	}
	return stdoutBuffer.String(), stderrBuffer.String(), err
}

func formatCommandStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return "\ncommand stderr:\n" + stderr
}

func isContainerPackageEcosystem(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deb", "apk", "rpm":
		return true
	default:
		return false
	}
}
