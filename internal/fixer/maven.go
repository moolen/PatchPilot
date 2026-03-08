package fixer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/vuln"
)

var (
	mavenDependencyPattern = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	mavenArtifactPattern   = regexp.MustCompile(`<artifactId>\s*([^<\s]+)\s*</artifactId>`)
	mavenGroupPattern      = regexp.MustCompile(`<groupId>\s*([^<\s]+)\s*</groupId>`)
	mavenVersionPattern    = regexp.MustCompile(`<version>\s*([^<\s]+)\s*</version>`)
)

func ApplyMavenFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyMavenFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyMavenFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return strings.EqualFold(entry.Name(), "pom.xml")
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectMavenRequirements(manifests, findings)
	patches := make([]Patch, 0)
	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}
		filePatches, err := patchPomXML(manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
	}
	return patches, nil
}

func collectMavenRequirements(manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if finding.Package == "" || finding.FixedVersion == "" || !isMavenEcosystem(finding.Ecosystem) {
			continue
		}
		for _, location := range finding.Locations {
			if _, ok := known[location]; !ok {
				continue
			}
			if requirements[location] == nil {
				requirements[location] = map[string]string{}
			}
			pkg := strings.TrimSpace(finding.Package)
			requirements[location][pkg] = preferHigherVersion(requirements[location][pkg], finding.FixedVersion)
		}
	}
	return requirements
}

func patchPomXML(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	patches := make([]Patch, 0)

	updated := mavenDependencyPattern.ReplaceAllStringFunc(content, func(block string) string {
		artifactMatch := mavenArtifactPattern.FindStringSubmatch(block)
		if len(artifactMatch) != 2 {
			return block
		}
		artifact := strings.TrimSpace(artifactMatch[1])
		groupMatch := mavenGroupPattern.FindStringSubmatch(block)
		group := ""
		if len(groupMatch) == 2 {
			group = strings.TrimSpace(groupMatch[1])
		}

		versionMatch := mavenVersionPattern.FindStringSubmatch(block)
		if len(versionMatch) != 2 {
			return block
		}
		currentVersion := strings.TrimSpace(versionMatch[1])
		if strings.Contains(currentVersion, "${") {
			return block
		}

		targetPackage := artifact
		fixedVersion, ok := requirements[targetPackage]
		if !ok && group != "" {
			targetPackage = group + ":" + artifact
			fixedVersion, ok = requirements[targetPackage]
		}
		if !ok {
			return block
		}
		if compareLooseVersions(currentVersion, fixedVersion) >= 0 {
			return block
		}

		newVersion := normalizeVersionToken(fixedVersion)
		if newVersion == "" {
			return block
		}
		patches = append(patches, Patch{
			Manager: "maven",
			Target:  path,
			Package: targetPackage,
			From:    currentVersion,
			To:      newVersion,
		})
		return mavenVersionPattern.ReplaceAllString(block, "<version>"+newVersion+"</version>")
	})

	if len(patches) == 0 {
		return nil, nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}

	sort.Slice(patches, func(i, j int) bool {
		return patches[i].Package < patches[j].Package
	})
	return patches, nil
}

func isMavenEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "maven", "java":
		return true
	default:
		return false
	}
}
