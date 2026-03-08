package fixer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/vuln"
)

var requirementLinePattern = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*([<>=!~]{1,2})\s*([^\s#;]+)`)

func ApplyPIPFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyPIPFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyPIPFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		name := strings.ToLower(entry.Name())
		return name == "requirements.txt" || (strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"))
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectPIPRequirements(manifests, findings)
	patches := make([]Patch, 0)
	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}
		filePatches, err := patchRequirementsTXT(manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
	}
	return patches, nil
}

func collectPIPRequirements(manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if finding.Package == "" || finding.FixedVersion == "" || !isPIPEcosystem(finding.Ecosystem) {
			continue
		}
		for _, location := range finding.Locations {
			if _, ok := known[location]; !ok {
				continue
			}
			if requirements[location] == nil {
				requirements[location] = map[string]string{}
			}
			key := strings.ToLower(strings.TrimSpace(finding.Package))
			requirements[location][key] = preferHigherVersion(requirements[location][key], finding.FixedVersion)
		}
	}
	return requirements
}

func patchRequirementsTXT(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	patches := make([]Patch, 0)

	for index, line := range lines {
		prefix, base, comment := splitRequirementLine(line)
		match := requirementLinePattern.FindStringSubmatch(base)
		if len(match) != 4 {
			continue
		}
		pkg := strings.ToLower(strings.TrimSpace(match[1]))
		currentVersion := strings.TrimSpace(match[3])
		fixedVersion, ok := requirements[pkg]
		if !ok {
			continue
		}
		if compareLooseVersions(currentVersion, fixedVersion) >= 0 {
			continue
		}

		updatedRequirement := match[1] + ">=" + normalizeVersionToken(fixedVersion)
		updated := prefix + updatedRequirement
		if comment != "" {
			updated += " " + comment
		}
		lines[index] = updated
		patches = append(patches, Patch{
			Manager: "pip",
			Target:  path,
			Package: match[1],
			From:    currentVersion,
			To:      normalizeVersionToken(fixedVersion),
		})
	}

	if len(patches) == 0 {
		return nil, nil
	}
	updatedContent := strings.Join(lines, "\n")
	if !strings.HasSuffix(updatedContent, "\n") {
		updatedContent += "\n"
	}
	if err := os.WriteFile(path, []byte(updatedContent), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}

	sort.Slice(patches, func(i, j int) bool {
		return patches[i].Package < patches[j].Package
	})
	return patches, nil
}

func splitRequirementLine(line string) (string, string, string) {
	leading := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return leading, "", ""
	}
	comment := ""
	base := trimmed
	if index := strings.Index(trimmed, "#"); index >= 0 {
		base = strings.TrimSpace(trimmed[:index])
		comment = strings.TrimSpace(trimmed[index:])
	}
	return leading, base, comment
}

func isPIPEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi", "pip", "python":
		return true
	default:
		return false
	}
}
