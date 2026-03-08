package fixer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/vuln"
)

var gradleCoordinatePattern = regexp.MustCompile(`(["'])([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"']+)(["'])`)

func ApplyGradleFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyGradleFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyGradleFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		name := strings.ToLower(entry.Name())
		return name == "build.gradle" || name == "build.gradle.kts"
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectGradleRequirements(manifests, findings)
	patches := make([]Patch, 0)
	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}
		filePatches, err := patchGradleBuild(manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
	}
	return patches, nil
}

func collectGradleRequirements(manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.Package) == "" || strings.TrimSpace(finding.FixedVersion) == "" || !isGradleEcosystem(finding.Ecosystem) {
			continue
		}
		pkg := strings.TrimSpace(finding.Package)
		for _, location := range finding.Locations {
			target := gradleTargetForLocation(location, known)
			if target == "" {
				continue
			}
			if requirements[target] == nil {
				requirements[target] = map[string]string{}
			}
			requirements[target][pkg] = preferHigherVersion(requirements[target][pkg], finding.FixedVersion)
		}
	}
	return requirements
}

func patchGradleBuild(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	patches := make([]Patch, 0)
	updated := gradleCoordinatePattern.ReplaceAllStringFunc(string(data), func(match string) string {
		sub := gradleCoordinatePattern.FindStringSubmatch(match)
		if len(sub) != 6 {
			return match
		}

		group := strings.TrimSpace(sub[2])
		artifact := strings.TrimSpace(sub[3])
		currentVersion := strings.TrimSpace(sub[4])
		pkg := group + ":" + artifact
		fixedVersion := requirements[pkg]
		if strings.TrimSpace(fixedVersion) == "" {
			fixedVersion = requirements[artifact]
			pkg = artifact
		}
		if strings.TrimSpace(fixedVersion) == "" {
			return match
		}

		updatedVersion, changed := updateNPMVersionConstraint(currentVersion, fixedVersion)
		if !changed {
			return match
		}
		patches = append(patches, Patch{
			Manager: "gradle",
			Target:  path,
			Package: pkg,
			From:    currentVersion,
			To:      updatedVersion,
		})
		return sub[1] + group + ":" + artifact + ":" + updatedVersion + sub[5]
	})

	if len(patches) == 0 {
		return nil, nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}

	sort.Slice(patches, func(i, j int) bool {
		if patches[i].Package == patches[j].Package {
			return patches[i].From < patches[j].From
		}
		return patches[i].Package < patches[j].Package
	})
	return patches, nil
}

func isGradleEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "maven", "gradle", "java":
		return true
	default:
		return false
	}
}

func gradleTargetForLocation(location string, known map[string]struct{}) string {
	if _, ok := known[location]; ok {
		return location
	}
	name := strings.ToLower(filepath.Base(location))
	if name == "gradle.lockfile" || name == "settings.gradle" || name == "settings.gradle.kts" {
		target := filepath.Join(filepath.Dir(location), "build.gradle")
		if _, ok := known[target]; ok {
			return target
		}
		target = filepath.Join(filepath.Dir(location), "build.gradle.kts")
		if _, ok := known[target]; ok {
			return target
		}
	}
	return ""
}
