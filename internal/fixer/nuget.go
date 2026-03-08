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
	nugetIncludeVersionPattern = regexp.MustCompile(`(?i)<PackageReference([^>]*?)Include="([^"]+)"([^>]*?)Version="([^"]+)"([^>]*)>`)
	nugetVersionIncludePattern = regexp.MustCompile(`(?i)<PackageReference([^>]*?)Version="([^"]+)"([^>]*?)Include="([^"]+)"([^>]*)>`)
	nugetNestedVersionPattern  = regexp.MustCompile(`(?is)<PackageReference([^/>]*?)Include="([^"]+)"([^/>]*)>(.*?)<Version>\s*([^<\s]+)\s*</Version>(.*?)</PackageReference>`)
)

func ApplyNuGetFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyNuGetFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyNuGetFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	projects, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return strings.HasSuffix(strings.ToLower(entry.Name()), ".csproj")
	}, options)
	if err != nil {
		return nil, err
	}
	if len(projects) == 0 {
		return nil, nil
	}

	requirements := collectNuGetRequirements(projects, findings)
	patches := make([]Patch, 0)
	for _, projectPath := range projects {
		required := requirements[projectPath]
		if len(required) == 0 {
			continue
		}
		filePatches, err := patchCSProj(projectPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
	}
	return patches, nil
}

func collectNuGetRequirements(projects []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	for _, project := range projects {
		known[project] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.Package) == "" || strings.TrimSpace(finding.FixedVersion) == "" || !isNuGetEcosystem(finding.Ecosystem) {
			continue
		}
		pkg := strings.TrimSpace(finding.Package)
		for _, location := range finding.Locations {
			if _, ok := known[location]; !ok {
				continue
			}
			if requirements[location] == nil {
				requirements[location] = map[string]string{}
			}
			requirements[location][pkg] = preferHigherVersion(requirements[location][pkg], finding.FixedVersion)
		}
	}
	return requirements
}

func patchCSProj(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	patches := make([]Patch, 0)

	content = nugetNestedVersionPattern.ReplaceAllStringFunc(content, func(match string) string {
		sub := nugetNestedVersionPattern.FindStringSubmatch(match)
		if len(sub) != 7 {
			return match
		}
		pkg := strings.TrimSpace(sub[2])
		fixed := requirements[pkg]
		if fixed == "" {
			return match
		}
		current := strings.TrimSpace(sub[5])
		updated, changed := updateNPMVersionConstraint(current, fixed)
		if !changed {
			return match
		}
		patches = append(patches, Patch{Manager: "nuget", Target: path, Package: pkg, From: current, To: updated})
		return `<PackageReference` + sub[1] + `Include="` + pkg + `"` + sub[3] + `>` + sub[4] + `<Version>` + updated + `</Version>` + sub[6] + `</PackageReference>`
	})

	content = nugetIncludeVersionPattern.ReplaceAllStringFunc(content, func(match string) string {
		sub := nugetIncludeVersionPattern.FindStringSubmatch(match)
		if len(sub) != 6 {
			return match
		}
		pkg := strings.TrimSpace(sub[2])
		fixed := requirements[pkg]
		if fixed == "" {
			return match
		}
		current := strings.TrimSpace(sub[4])
		updated, changed := updateNPMVersionConstraint(current, fixed)
		if !changed {
			return match
		}
		patches = append(patches, Patch{Manager: "nuget", Target: path, Package: pkg, From: current, To: updated})
		return `<PackageReference` + sub[1] + `Include="` + pkg + `"` + sub[3] + `Version="` + updated + `"` + sub[5] + `>`
	})

	content = nugetVersionIncludePattern.ReplaceAllStringFunc(content, func(match string) string {
		sub := nugetVersionIncludePattern.FindStringSubmatch(match)
		if len(sub) != 6 {
			return match
		}
		pkg := strings.TrimSpace(sub[4])
		fixed := requirements[pkg]
		if fixed == "" {
			return match
		}
		current := strings.TrimSpace(sub[2])
		updated, changed := updateNPMVersionConstraint(current, fixed)
		if !changed {
			return match
		}
		patches = append(patches, Patch{Manager: "nuget", Target: path, Package: pkg, From: current, To: updated})
		return `<PackageReference` + sub[1] + `Version="` + updated + `"` + sub[3] + `Include="` + pkg + `"` + sub[5] + `>`
	})

	if len(patches) == 0 {
		return nil, nil
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
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

func isNuGetEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "nuget", ".net", "dotnet", "csharp", "c#":
		return true
	default:
		return false
	}
}
