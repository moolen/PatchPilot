package fixer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	pathpkg "path"
	"sort"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"golang.org/x/mod/semver"

	"github.com/moolen/patchpilot/internal/vuln"
)

func ApplyDockerfileFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyDockerfileFixesWithOptions(ctx, repo, findings, DockerfileOptions{
		BaseImagePatching: true,
		OSPackagePatching: true,
	})
}

type DockerfileOptions struct {
	SkipPaths            []string
	AllowedBaseImages    []string
	DisallowedBaseImages []string
	BaseImageRules       []BaseImageRule
	OCIPolicies          []OCIImagePolicy
	BaseImagePatching    bool
	OSPackagePatching    bool
}

type BaseImageRule struct {
	Image   string
	TagSets []BaseImageTagSet
	Deny    []string
}

type BaseImageTagSet struct {
	SemverRange string
	Allow       []string
}

func ApplyDockerfileFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options DockerfileOptions) ([]Patch, error) {
	normalizedOptions := normalizeDockerfileOptions(options)
	dockerfiles, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		name := entry.Name()
		return name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") || strings.HasSuffix(name, ".Dockerfile")
	}, FileOptions{SkipPaths: normalizedOptions.SkipPaths})
	if err != nil {
		return nil, err
	}

	requirements := collectDockerRequirements(dockerfiles, findings)
	patches := make([]Patch, 0)
	for _, path := range dockerfiles {
		need := requirements[path]
		filePatches, changed, err := patchDockerfileWithOptions(ctx, path, need, normalizedOptions)
		if err != nil {
			return nil, err
		}
		if changed {
			patches = append(patches, filePatches...)
		}
	}

	return patches, nil
}

func normalizeDockerfileOptions(options DockerfileOptions) DockerfileOptions {
	return options
}

type dockerNeeds struct {
	BasePackages map[string]string
	DebPackages  map[string]string
	APKPackages  map[string]string
	RPMPackages  map[string]string
	NeedsDeb     bool
	NeedsAPK     bool
	NeedsRPM     bool
}

func collectDockerRequirements(dockerfiles []string, findings []vuln.Finding) map[string]dockerNeeds {
	known := map[string]struct{}{}
	for _, dockerfile := range dockerfiles {
		known[dockerfile] = struct{}{}
	}

	requirements := map[string]dockerNeeds{}
	for _, finding := range findings {
		for _, location := range finding.Locations {
			if _, ok := known[location]; !ok {
				continue
			}
			need := requirements[location]
			if need.BasePackages == nil {
				need.BasePackages = map[string]string{}
			}
			if finding.Package != "" && finding.FixedVersion != "" {
				need.BasePackages[finding.Package] = preferFixedVersion(need.BasePackages[finding.Package], finding.FixedVersion)
			}
			switch finding.Ecosystem {
			case "deb":
				need.NeedsDeb = true
				if need.DebPackages == nil {
					need.DebPackages = map[string]string{}
				}
				if finding.Package != "" {
					need.DebPackages[finding.Package] = preferFixedVersion(need.DebPackages[finding.Package], finding.FixedVersion)
				}
			case "apk":
				need.NeedsAPK = true
				if need.APKPackages == nil {
					need.APKPackages = map[string]string{}
				}
				if finding.Package != "" {
					need.APKPackages[finding.Package] = preferFixedVersion(need.APKPackages[finding.Package], finding.FixedVersion)
				}
			case "rpm":
				need.NeedsRPM = true
				if need.RPMPackages == nil {
					need.RPMPackages = map[string]string{}
				}
				if finding.Package != "" {
					need.RPMPackages[finding.Package] = preferFixedVersion(need.RPMPackages[finding.Package], finding.FixedVersion)
				}
			}
			requirements[location] = need
		}
	}
	return requirements
}

func patchDockerfile(ctx context.Context, path string, need dockerNeeds) ([]Patch, bool, error) {
	return patchDockerfileWithOptions(ctx, path, need, DockerfileOptions{
		BaseImagePatching: true,
		OSPackagePatching: true,
	})
}

func patchDockerfileWithOptions(ctx context.Context, path string, need dockerNeeds, options DockerfileOptions) ([]Patch, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("open %s: %w", path, err)
	}
	result, err := parser.Parse(file)
	closeErr := file.Close()
	if err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if closeErr != nil {
		return nil, false, fmt.Errorf("close %s: %w", path, closeErr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	original := content
	patches := make([]Patch, 0)

	fromNodes := collectInstructionNodes(result.AST, "from")
	for _, node := range fromNodes {
		image, ok := extractFromImage(node.Original)
		if !ok {
			continue
		}
		if err := validateBaseImagePolicy(image, path, options); err != nil {
			return nil, false, err
		}
	}

	if options.BaseImagePatching {
		for _, node := range fromNodes {
			updatedLine, patch, ok := maybePatchFrom(ctx, node.Original, path, options)
			if !ok {
				continue
			}
			content = strings.Replace(content, node.Original, updatedLine, 1)
			patches = append(patches, patch)
		}
	}

	runNodes := collectInstructionNodes(result.AST, "run")
	hasDebUpgrade := containsRun(runNodes, "apt-get upgrade") || containsRun(runNodes, "apt-get install --only-upgrade")
	hasAPKUpgrade := containsRun(runNodes, "apk upgrade") || containsRun(runNodes, "apk add --upgrade")
	hasRPMUpgrade := containsRun(runNodes, "microdnf upgrade") || containsRun(runNodes, "yum -y update") || containsRun(runNodes, "dnf upgrade")

	if options.OSPackagePatching {
		if len(need.DebPackages) > 0 && !hasDebUpgrade {
			packages := sortedPackageNames(need.DebPackages)
			content = strings.TrimRight(content, "\n") + "\n" + debUpgradeCommand(packages) + "\n"
			patches = append(patches, dockerPackagePatches(path, need.DebPackages)...)
		} else if need.NeedsDeb && !hasDebUpgrade {
			content = strings.TrimRight(content, "\n") + "\nRUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*\n"
			patches = append(patches, Patch{Manager: "dockerfile", Target: path, Package: "deb-packages", From: "", To: "apt-get upgrade"})
		}
		if len(need.APKPackages) > 0 && !hasAPKUpgrade {
			packages := sortedPackageNames(need.APKPackages)
			content = strings.TrimRight(content, "\n") + "\n" + apkUpgradeCommand(packages) + "\n"
			patches = append(patches, dockerPackagePatches(path, need.APKPackages)...)
		} else if need.NeedsAPK && !hasAPKUpgrade {
			content = strings.TrimRight(content, "\n") + "\nRUN apk upgrade --no-cache\n"
			patches = append(patches, Patch{Manager: "dockerfile", Target: path, Package: "apk-packages", From: "", To: "apk upgrade"})
		}
		if len(need.RPMPackages) > 0 && !hasRPMUpgrade {
			packages := sortedPackageNames(need.RPMPackages)
			content = strings.TrimRight(content, "\n") + "\n" + rpmUpgradeCommand(packages) + "\n"
			patches = append(patches, dockerPackagePatches(path, need.RPMPackages)...)
		} else if need.NeedsRPM && !hasRPMUpgrade {
			content = strings.TrimRight(content, "\n") + "\nRUN microdnf upgrade -y || yum -y update\n"
			patches = append(patches, Patch{Manager: "dockerfile", Target: path, Package: "rpm-packages", From: "", To: "microdnf upgrade -y || yum -y update"})
		}
	}

	if content == original {
		return nil, false, nil
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return nil, false, fmt.Errorf("write %s: %w", path, err)
	}
	return patches, true, nil
}

func debUpgradeCommand(packages []string) string {
	return "RUN apt-get update && apt-get install --only-upgrade -y " + strings.Join(packages, " ") + " && rm -rf /var/lib/apt/lists/*"
}

func apkUpgradeCommand(packages []string) string {
	return "RUN apk upgrade --no-cache " + strings.Join(packages, " ")
}

func rpmUpgradeCommand(packages []string) string {
	joined := strings.Join(packages, " ")
	return "RUN microdnf upgrade -y " + joined + " || yum -y update " + joined
}

func dockerPackagePatches(path string, packages map[string]string) []Patch {
	names := sortedPackageNames(packages)
	patches := make([]Patch, 0, len(names))
	for _, name := range names {
		patches = append(patches, Patch{Manager: "dockerfile", Target: path, Package: name, From: "", To: packages[name]})
	}
	return patches
}

func sortedPackageNames(packages map[string]string) []string {
	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func preferFixedVersion(current, candidate string) string {
	if current == "" {
		return candidate
	}
	if candidate == "" {
		return current
	}
	if left, right := canonicalImageSemver(current), canonicalImageSemver(candidate); left != "" && right != "" {
		if semver.Compare(left, right) >= 0 {
			return current
		}
		return candidate
	}
	if candidate > current {
		return candidate
	}
	return current
}

func maybePatchFrom(ctx context.Context, line, path string, options DockerfileOptions) (string, Patch, bool) {
	image, ok := extractFromImage(line)
	if !ok {
		return "", Patch{}, false
	}
	imageWithoutDigest, currentDigest := splitImageDigest(image)
	repo, tag := splitImageRef(image)
	if tag == "" {
		return "", Patch{}, false
	}

	updatedTag, reason := resolveOCIBaseImageTag(ctx, image, options.OCIPolicies)
	if updatedTag == "" {
		if rule, ok := findMatchingBaseImageRule(repo, options.BaseImageRules); ok {
			updatedTag = resolveRuleDrivenImageTag(ctx, image, rule)
			reason = repo
		}
	}
	if updatedTag == "" || updatedTag == tag {
		return "", Patch{}, false
	}
	return buildPatchedFromLine(ctx, line, path, image, imageWithoutDigest, repo, tag, currentDigest, updatedTag, reason)
}

func buildPatchedFromLine(ctx context.Context, line, path, image, imageWithoutDigest, repo, currentTag, currentDigest, updatedTag, patchPackage string) (string, Patch, bool) {
	fromRef := currentTag
	toRef := updatedTag
	updatedImage := imageWithoutDigest
	if colon := strings.LastIndex(updatedImage, ":"); colon != -1 && !strings.Contains(updatedImage[colon+1:], "/") {
		updatedImage = updatedImage[:colon] + ":" + updatedTag
	} else {
		updatedImage = repo + ":" + updatedTag
	}
	if currentDigest != "" {
		updatedDigest := resolveUpdatedImageDigest(ctx, image, updatedTag)
		if updatedDigest == "" {
			return "", Patch{}, false
		}
		updatedImage = updatedImage + "@" + updatedDigest
		fromRef = currentTag + "@" + currentDigest
		toRef = updatedTag + "@" + updatedDigest
	}
	updatedLine := strings.Replace(line, image, updatedImage, 1)
	return updatedLine, Patch{Manager: "dockerfile", Target: path, Package: patchPackage, From: fromRef, To: toRef}, true
}

func canonicalImageSemver(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	version = strings.TrimPrefix(version, "v")
	parts := strings.SplitN(version, "+", 2)
	version = parts[0]
	base := strings.SplitN(version, "-", 2)[0]
	segments := strings.Split(base, ".")
	for len(segments) < 3 {
		segments = append(segments, "0")
	}
	if len(segments) != 3 {
		return ""
	}
	canonical := "v" + strings.Join(segments, ".")
	if !semver.IsValid(canonical) {
		return ""
	}
	return canonical
}

func splitImageRef(image string) (string, string) {
	image, _ = splitImageDigest(image)
	index := strings.LastIndex(image, ":")
	if index == -1 || strings.Contains(image[index+1:], "/") {
		return image, ""
	}
	return image[:index], image[index+1:]
}

func splitImageDigest(image string) (string, string) {
	parts := strings.SplitN(image, "@", 2)
	if len(parts) < 2 {
		return image, ""
	}
	digest := strings.TrimSpace(parts[1])
	if digest == "" {
		return parts[0], ""
	}
	return parts[0], digest
}

func extractFromImage(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
		return "", false
	}
	index := 1
	for index < len(fields) && strings.HasPrefix(fields[index], "--") {
		index++
	}
	if index >= len(fields) {
		return "", false
	}
	return fields[index], true
}

func validateBaseImagePolicy(image, dockerfilePath string, options DockerfileOptions) error {
	if len(options.DisallowedBaseImages) > 0 {
		for _, pattern := range options.DisallowedBaseImages {
			if imageMatchesPattern(image, pattern) {
				return fmt.Errorf("docker policy violation in %s: base image %q matches disallowed pattern %q", dockerfilePath, image, pattern)
			}
		}
	}
	if len(options.AllowedBaseImages) == 0 {
		return nil
	}
	for _, pattern := range options.AllowedBaseImages {
		if imageMatchesPattern(image, pattern) {
			return nil
		}
	}
	return fmt.Errorf("docker policy violation in %s: base image %q does not match allowed patterns", dockerfilePath, image)
}

func imageMatchesPattern(image, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if image == pattern {
		return true
	}
	imageRepo, _ := splitImageRef(image)
	patternRepo, _ := splitImageRef(pattern)
	if imageRepo == pattern || imageRepo == patternRepo {
		return true
	}
	if strings.ContainsAny(pattern, "*?[") {
		if matched, _ := pathpkg.Match(pattern, image); matched {
			return true
		}
		if matched, _ := pathpkg.Match(pattern, imageRepo); matched {
			return true
		}
	}
	return false
}

func collectInstructionNodes(node *parser.Node, instruction string) []*parser.Node {
	result := make([]*parser.Node, 0)
	var walk func(*parser.Node)
	walk = func(current *parser.Node) {
		if current == nil {
			return
		}
		if strings.EqualFold(current.Value, instruction) {
			result = append(result, current)
		}
		for _, child := range current.Children {
			walk(child)
		}
		walk(current.Next)
	}
	walk(node)
	return result
}

func containsRun(nodes []*parser.Node, fragment string) bool {
	fragment = strings.ToLower(fragment)
	for _, node := range nodes {
		if strings.Contains(strings.ToLower(node.Original), fragment) {
			return true
		}
	}
	return false
}
