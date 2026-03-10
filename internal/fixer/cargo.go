package fixer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/vuln"
)

var (
	cargoSimpleDependencyPattern = regexp.MustCompile(`^(\s*([A-Za-z0-9_.-]+)\s*=\s*")([^"]+)("\s*(?:#.*)?)$`)
	cargoInlineDependencyPattern = regexp.MustCompile(`^(\s*([A-Za-z0-9_.-]+)\s*=\s*\{[^\n#}]*\bversion\s*=\s*")([^"]+)("[^\n}]*\}\s*(?:#.*)?)$`)
)

var runCargoLockfileSyncFunc = runCargoLockfileSync

const cargoLockfilePatch = "cargo-lockfile"

func ApplyCargoFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyCargoFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyCargoFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	_ = ctx

	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return strings.EqualFold(entry.Name(), "Cargo.toml")
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectCargoRequirements(manifests, findings)
	patches := make([]Patch, 0)
	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}
		filePatches, err := patchCargoTOML(manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
		lockfilePatches, err := syncCargoLockfiles(ctx, repo, manifestPath, required)
		if err != nil {
			return nil, err
		}
		patches = append(patches, lockfilePatches...)
	}
	return patches, nil
}

func collectCargoRequirements(manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.Package) == "" || strings.TrimSpace(finding.FixedVersion) == "" || !isCargoEcosystem(finding.Ecosystem) {
			continue
		}
		pkg := strings.TrimSpace(finding.Package)
		for _, location := range finding.Locations {
			target := cargoTargetForLocation(location, known)
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

func patchCargoTOML(path string, requirements map[string]string) ([]Patch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	patches := make([]Patch, 0)
	for index, line := range lines {
		if updated, patch, changed := patchCargoLine(path, line, requirements); changed {
			lines[index] = updated
			patches = append(patches, patch)
		}
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
		if patches[i].Package == patches[j].Package {
			return patches[i].From < patches[j].From
		}
		return patches[i].Package < patches[j].Package
	})
	return patches, nil
}

func patchCargoLine(path, line string, requirements map[string]string) (string, Patch, bool) {
	if match := cargoSimpleDependencyPattern.FindStringSubmatch(line); len(match) == 5 {
		pkg := strings.TrimSpace(match[2])
		fixed, ok := requirements[pkg]
		if !ok {
			return line, Patch{}, false
		}
		current := strings.TrimSpace(match[3])
		updatedVersion, changed := updateNPMVersionConstraint(current, fixed)
		if !changed {
			return line, Patch{}, false
		}
		updated := match[1] + updatedVersion + match[4]
		return updated, Patch{Manager: "cargo", Target: path, Package: pkg, From: current, To: updatedVersion}, true
	}
	if match := cargoInlineDependencyPattern.FindStringSubmatch(line); len(match) == 5 {
		pkg := strings.TrimSpace(match[2])
		fixed, ok := requirements[pkg]
		if !ok {
			return line, Patch{}, false
		}
		current := strings.TrimSpace(match[3])
		updatedVersion, changed := updateNPMVersionConstraint(current, fixed)
		if !changed {
			return line, Patch{}, false
		}
		updated := match[1] + updatedVersion + match[4]
		return updated, Patch{Manager: "cargo", Target: path, Package: pkg, From: current, To: updatedVersion}, true
	}
	return line, Patch{}, false
}

func isCargoEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "cargo", "rust":
		return true
	default:
		return false
	}
}

func cargoTargetForLocation(location string, known map[string]struct{}) string {
	if _, ok := known[location]; ok {
		return location
	}
	if strings.EqualFold(filepath.Base(location), "Cargo.lock") {
		target := filepath.Join(filepath.Dir(location), "Cargo.toml")
		if _, ok := known[target]; ok {
			return target
		}
	}
	return ""
}

func syncCargoLockfiles(ctx context.Context, repo, manifestPath string, requirements map[string]string) ([]Patch, error) {
	lockfiles := cargoLockfilesForManifest(repo, manifestPath)
	before := make(map[string][]byte, len(lockfiles))
	for _, path := range lockfiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		before[path] = data
	}
	if len(before) == 0 {
		return nil, nil
	}

	if err := runCargoLockfileSyncFunc(ctx, manifestPath, requirements); err != nil {
		return nil, fmt.Errorf("sync cargo lockfile for %s: %w", manifestPath, err)
	}

	patches := make([]Patch, 0, len(before))
	for path, previous := range before {
		updated, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if string(updated) == string(previous) {
			continue
		}
		patches = append(patches, Patch{
			Manager: cargoLockfilePatch,
			Target:  path,
			Package: filepath.Base(path),
			From:    "stale",
			To:      "synced",
		})
	}
	sort.Slice(patches, func(i, j int) bool {
		return patches[i].Target < patches[j].Target
	})
	return patches, nil
}

func cargoLockfilesForManifest(repo, manifestPath string) []string {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return nil
	}
	dir := filepath.Dir(manifestPath)
	current, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}

	lockfiles := make([]string, 0)
	seen := map[string]struct{}{}
	for {
		rel, relErr := filepath.Rel(repoAbs, current)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			break
		}
		candidate := filepath.Join(current, "Cargo.lock")
		if _, err := os.Stat(candidate); err == nil {
			if _, ok := seen[candidate]; !ok {
				seen[candidate] = struct{}{}
				lockfiles = append(lockfiles, candidate)
			}
		}
		if current == repoAbs {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	sort.Strings(lockfiles)
	return lockfiles
}

func runCargoLockfileSync(ctx context.Context, manifestPath string, requirements map[string]string) error {
	if _, err := exec.LookPath("cargo"); err != nil {
		return fmt.Errorf("required tool %q not found in PATH", "cargo")
	}

	packages := make([]string, 0, len(requirements))
	for pkg, fixed := range requirements {
		if strings.TrimSpace(pkg) == "" || strings.TrimSpace(fixed) == "" {
			continue
		}
		packages = append(packages, pkg)
	}
	sort.Strings(packages)

	dir := filepath.Dir(manifestPath)
	for _, pkg := range packages {
		fixed := strings.TrimSpace(requirements[pkg])
		command := exec.CommandContext(ctx, "cargo", "update", "--manifest-path", manifestPath, "-p", pkg, "--precise", fixed)
		command.Dir = dir
		output, err := command.CombinedOutput()
		if err == nil {
			continue
		}
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("cargo update --manifest-path %s -p %s --precise %s: %w", manifestPath, pkg, fixed, err)
		}
		return fmt.Errorf("cargo update --manifest-path %s -p %s --precise %s: %w: %s", manifestPath, pkg, fixed, err, message)
	}
	return nil
}
