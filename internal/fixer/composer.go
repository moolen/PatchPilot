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

func ApplyComposerFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyComposerFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyComposerFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return strings.EqualFold(entry.Name(), "composer.json")
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectComposerRequirements(manifests, findings)
	patches := make([]Patch, 0)
	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}
		filePatches, err := patchComposerJSON(manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
	}
	return patches, nil
}

func collectComposerRequirements(manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.Package) == "" || strings.TrimSpace(finding.FixedVersion) == "" || !isComposerEcosystem(finding.Ecosystem) {
			continue
		}
		for _, location := range finding.Locations {
			target := composerTargetForLocation(location, known)
			if target == "" {
				continue
			}
			if requirements[target] == nil {
				requirements[target] = map[string]string{}
			}
			pkg := strings.TrimSpace(finding.Package)
			requirements[target][pkg] = preferHigherVersion(requirements[target][pkg], finding.FixedVersion)
		}
	}
	return requirements
}

func patchComposerJSON(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	sections := []string{"require", "require-dev"}
	patches := make([]Patch, 0)

	for _, section := range sections {
		sectionMap, ok := manifest[section].(map[string]any)
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
				Manager: "composer",
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

func isComposerEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "composer", "php":
		return true
	default:
		return false
	}
}

func composerTargetForLocation(location string, known map[string]struct{}) string {
	if _, ok := known[location]; ok {
		return location
	}
	if strings.EqualFold(filepath.Base(location), "composer.lock") {
		target := filepath.Join(filepath.Dir(location), "composer.json")
		if _, ok := known[target]; ok {
			return target
		}
	}
	return ""
}
