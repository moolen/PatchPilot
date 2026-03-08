package fixer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/vuln"
)

func ApplyNPMFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyNPMFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyNPMFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return entry.Name() == "package.json"
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectNPMRequirements(manifests, findings)
	patches := make([]Patch, 0)

	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}

		filePatches, err := patchPackageJSON(manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
	}

	return patches, nil
}

func collectNPMRequirements(manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	byDir := map[string]string{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
		byDir[filepath.Dir(manifest)] = manifest
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if finding.Package == "" || finding.FixedVersion == "" || !isNPMEcosystem(finding.Ecosystem) {
			continue
		}
		targets := npmTargetsForFinding(finding, known, byDir)
		for _, target := range targets {
			if requirements[target] == nil {
				requirements[target] = map[string]string{}
			}
			requirements[target][finding.Package] = preferHigherVersion(requirements[target][finding.Package], finding.FixedVersion)
		}
	}
	return requirements
}

func npmTargetsForFinding(finding vuln.Finding, known map[string]struct{}, byDir map[string]string) []string {
	targets := make([]string, 0, len(finding.Locations))
	seen := map[string]struct{}{}
	for _, location := range finding.Locations {
		base := filepath.Base(location)
		switch base {
		case "package.json":
			if _, ok := known[location]; ok {
				if _, exists := seen[location]; !exists {
					seen[location] = struct{}{}
					targets = append(targets, location)
				}
			}
		case "package-lock.json", "npm-shrinkwrap.json":
			if target := byDir[filepath.Dir(location)]; target != "" {
				if _, exists := seen[target]; !exists {
					seen[target] = struct{}{}
					targets = append(targets, target)
				}
			}
		}
	}
	return targets
}

func patchPackageJSON(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	sections := []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
	patches := make([]Patch, 0)

	for _, section := range sections {
		sectionMap, ok := manifest[section].(map[string]interface{})
		if !ok {
			continue
		}
		for pkg, fixed := range requirements {
			currentValue, exists := sectionMap[pkg]
			if !exists {
				continue
			}
			current, ok := currentValue.(string)
			if !ok {
				continue
			}
			updated, changed := updateNPMVersionConstraint(current, fixed)
			if !changed {
				continue
			}
			sectionMap[pkg] = updated
			patches = append(patches, Patch{
				Manager: "npm",
				Target:  path,
				Package: pkg,
				From:    current,
				To:      updated,
			})
		}
		manifest[section] = sectionMap
	}

	if len(patches) == 0 {
		return nil, nil
	}

	formatted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("format %s: %w", path, err)
	}
	formatted = append(formatted, '\n')
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}

	sort.Slice(patches, func(i, j int) bool {
		return patches[i].Package < patches[j].Package
	})
	return patches, nil
}

func updateNPMVersionConstraint(currentConstraint, fixedVersion string) (string, bool) {
	currentConstraint = strings.TrimSpace(currentConstraint)
	fixedVersion = strings.TrimSpace(fixedVersion)
	if currentConstraint == "" || fixedVersion == "" {
		return currentConstraint, false
	}

	prefix := ""
	if strings.HasPrefix(currentConstraint, "^") {
		prefix = "^"
	} else if strings.HasPrefix(currentConstraint, "~") {
		prefix = "~"
	}

	currentVersion := normalizeVersionToken(currentConstraint)
	if compareLooseVersions(currentVersion, fixedVersion) >= 0 {
		return currentConstraint, false
	}

	updated := prefix + normalizeVersionToken(fixedVersion)
	if updated == "" {
		updated = fixedVersion
	}
	if updated == currentConstraint {
		return currentConstraint, false
	}
	return updated, true
}

func isNPMEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return true
	default:
		return false
	}
}
