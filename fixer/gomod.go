package fixer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/moolen/patchpilot/internal/goenv"
	"github.com/moolen/patchpilot/policy"
	"github.com/moolen/patchpilot/vuln"
)

type Patch struct {
	Manager string `json:"manager"`
	Target  string `json:"target"`
	Package string `json:"package"`
	From    string `json:"from"`
	To      string `json:"to"`
}

var (
	runGoListModulesFunc = runGoListModules
	runGoGetFunc         = runGoGet
	runGoModTidyFunc     = runGoModTidy
	runGoModVendorFunc   = runGoModVendor
)

type FileOptions struct {
	SkipPaths []string
}

func ApplyGoModuleFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyGoModuleFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyGoModuleFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	goMods, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return entry.Name() == "go.mod"
	}, options)
	if err != nil {
		return nil, err
	}

	requirements := collectGoRequirements(goMods, findings)
	patches := make([]Patch, 0)
	modifiedDirs := map[string]struct{}{}
	vendorDirs := map[string]struct{}{}

	for _, goModPath := range goMods {
		desired := requirements[goModPath]
		if len(desired) == 0 {
			continue
		}

		directPatches, unresolved, directChanged, err := patchGoMod(goModPath, desired)
		if err != nil {
			return nil, err
		}
		patches = append(patches, directPatches...)
		moduleDir := filepath.Dir(goModPath)
		if directChanged {
			modifiedDirs[moduleDir] = struct{}{}
			if hasVendorDir(moduleDir) {
				vendorDirs[moduleDir] = struct{}{}
			}
		}
		if directChanged && len(unresolved) > 0 {
			if err := runGoModTidyFunc(ctx, moduleDir); err != nil {
				if isNonFatalGoModuleStateError(err) {
					warnGoFix("skipping tidy before transitive fixes in %s: %v", moduleDir, err)
				} else {
					return nil, fmt.Errorf("prepare %s for transitive fixes: %w", moduleDir, err)
				}
			}
		}

		transitivePatches, transitiveChanged, err := patchTransitiveModules(ctx, goModPath, unresolved)
		if err != nil {
			return nil, err
		}
		patches = append(patches, transitivePatches...)
		if transitiveChanged {
			moduleDir := filepath.Dir(goModPath)
			modifiedDirs[moduleDir] = struct{}{}
			if hasVendorDir(moduleDir) {
				vendorDirs[moduleDir] = struct{}{}
			}
		}
	}

	dirs := make([]string, 0, len(modifiedDirs))
	for dir := range modifiedDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		if err := runGoModTidyFunc(ctx, dir); err != nil {
			if isNonFatalGoModuleStateError(err) {
				warnGoFix("keeping applied fixes in %s without tidy: %v", dir, err)
				continue
			}
			return nil, fmt.Errorf("run go mod tidy in %s: %w", dir, err)
		}
		if _, ok := vendorDirs[dir]; ok {
			if err := runGoModVendorFunc(ctx, dir); err != nil {
				return nil, fmt.Errorf("run go mod vendor in %s: %w", dir, err)
			}
		}
	}

	return filterEffectiveGoModulePatches(ctx, patches), nil
}

func filterEffectiveGoModulePatches(ctx context.Context, patches []Patch) []Patch {
	if len(patches) == 0 {
		return nil
	}

	effective := make([]Patch, 0, len(patches))
	goModFiles := map[string]*modfile.File{}
	buildLists := map[string]map[string]string{}

	for _, patch := range patches {
		switch patch.Manager {
		case "gomod":
			parsed, ok := goModFiles[patch.Target]
			if !ok {
				var err error
				parsed, err = readGoModFile(patch.Target)
				if err != nil {
					continue
				}
				goModFiles[patch.Target] = parsed
			}
			if patchSatisfiedInGoMod(parsed, patch) {
				effective = append(effective, patch)
			}
		case "goget":
			moduleDir := filepath.Dir(patch.Target)
			buildList, ok := buildLists[moduleDir]
			if !ok {
				var err error
				buildList, err = listModules(ctx, moduleDir)
				if err != nil {
					continue
				}
				buildLists[moduleDir] = buildList
			}
			if patchSatisfiedInBuildList(buildList, patch) {
				effective = append(effective, patch)
			}
		default:
			effective = append(effective, patch)
		}
	}

	return effective
}

func readGoModFile(path string) (*modfile.File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	parsed, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return parsed, nil
}

func patchSatisfiedInGoMod(parsed *modfile.File, patch Patch) bool {
	target := canonicalSemver(patch.To)
	if target == "" {
		return false
	}
	for _, req := range parsed.Require {
		if req.Mod.Path != patch.Package {
			continue
		}
		current := canonicalSemver(req.Mod.Version)
		if current == "" {
			return false
		}
		return semver.Compare(current, target) >= 0
	}
	return false
}

func patchSatisfiedInBuildList(buildList map[string]string, patch Patch) bool {
	target := canonicalSemver(patch.To)
	if target == "" {
		return false
	}
	currentVersion, ok := buildList[patch.Package]
	if !ok {
		return false
	}
	current := canonicalSemver(currentVersion)
	if current == "" {
		return false
	}
	return semver.Compare(current, target) >= 0
}

func collectGoRequirements(goMods []string, findings []vuln.Finding) map[string]map[string]string {
	allGoMods := map[string]struct{}{}
	for _, goMod := range goMods {
		allGoMods[goMod] = struct{}{}
	}

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if finding.Ecosystem != "golang" {
			continue
		}

		targets := goModTargets(finding, allGoMods)
		for _, target := range targets {
			if requirements[target] == nil {
				requirements[target] = map[string]string{}
			}
			current := requirements[target][finding.Package]
			requirements[target][finding.Package] = maxSemver(current, finding.FixedVersion)
		}
	}
	return requirements
}

func goModTargets(finding vuln.Finding, allGoMods map[string]struct{}) []string {
	targets := make([]string, 0, len(finding.Locations))
	seen := map[string]struct{}{}
	for _, location := range finding.Locations {
		if filepath.Base(location) != "go.mod" {
			continue
		}
		if _, ok := allGoMods[location]; !ok {
			continue
		}
		if _, ok := seen[location]; ok {
			continue
		}
		seen[location] = struct{}{}
		targets = append(targets, location)
	}
	return targets
}

func patchGoMod(path string, desired map[string]string) ([]Patch, map[string]string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false, fmt.Errorf("read %s: %w", path, err)
	}

	parsed, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse %s: %w", path, err)
	}

	unresolved := map[string]string{}
	for modulePath, targetVersion := range desired {
		unresolved[modulePath] = targetVersion
	}

	patches := make([]Patch, 0)
	changed := false
	for _, req := range parsed.Require {
		targetVersion, ok := desired[req.Mod.Path]
		if !ok || targetVersion == "" {
			continue
		}

		currentVersion := canonicalSemver(req.Mod.Version)
		targetCanonical := canonicalSemver(targetVersion)
		targetResolved := preserveVersionForm(req.Mod.Version, targetCanonical)
		if currentVersion != "" && targetResolved != "" && semver.Compare(currentVersion, targetResolved) >= 0 {
			delete(unresolved, req.Mod.Path)
			continue
		}
		if currentVersion == "" || targetResolved == "" {
			continue
		}

		patches = append(patches, Patch{
			Manager: "gomod",
			Target:  path,
			Package: req.Mod.Path,
			From:    req.Mod.Version,
			To:      targetResolved,
		})
		if err := parsed.AddRequire(req.Mod.Path, targetResolved); err != nil {
			return nil, nil, false, fmt.Errorf("update %s in %s: %w", req.Mod.Path, path, err)
		}
		delete(unresolved, req.Mod.Path)
		changed = true
	}

	if changed {
		parsed.Cleanup()
		formatted, err := parsed.Format()
		if err != nil {
			return nil, nil, false, fmt.Errorf("format %s: %w", path, err)
		}
		if err := os.WriteFile(path, formatted, 0o644); err != nil {
			return nil, nil, false, fmt.Errorf("write %s: %w", path, err)
		}
	}

	return patches, unresolved, changed, nil
}

func patchTransitiveModules(ctx context.Context, goModPath string, desired map[string]string) ([]Patch, bool, error) {
	if len(desired) == 0 {
		return nil, false, nil
	}

	moduleDir := filepath.Dir(goModPath)
	buildList, err := listModules(ctx, moduleDir)
	if err != nil {
		if isNonFatalGoModuleStateError(err) {
			warnGoFix("skipping transitive fixes in %s: %v", moduleDir, err)
			return nil, false, nil
		}
		return nil, false, err
	}

	modulePaths := make([]string, 0, len(desired))
	for modulePath := range desired {
		modulePaths = append(modulePaths, modulePath)
	}
	sort.Strings(modulePaths)

	patches := make([]Patch, 0)
	changed := false
	for _, modulePath := range modulePaths {
		targetVersion := canonicalSemver(desired[modulePath])
		if targetVersion == "" {
			continue
		}

		currentVersion, ok := buildList[modulePath]
		if !ok {
			continue
		}
		targetResolved := preserveVersionForm(currentVersion, targetVersion)
		currentCanonical := canonicalSemver(currentVersion)
		if currentCanonical != "" && targetResolved != "" && semver.Compare(currentCanonical, targetResolved) >= 0 {
			continue
		}

		if err := runGoGetFunc(ctx, moduleDir, modulePath, targetResolved); err != nil {
			return nil, false, fmt.Errorf("run go get %s@%s in %s: %w", modulePath, targetResolved, moduleDir, err)
		}

		patches = append(patches, Patch{
			Manager: "goget",
			Target:  goModPath,
			Package: modulePath,
			From:    currentVersion,
			To:      targetResolved,
		})
		changed = true
	}

	return patches, changed, nil
}

func listModules(ctx context.Context, dir string) (map[string]string, error) {
	output, err := runGoListModulesFunc(ctx, dir)
	if err != nil && strings.Contains(err.Error(), "updates to go.mod needed") {
		if tidyErr := runGoModTidyFunc(ctx, dir); tidyErr != nil {
			return nil, fmt.Errorf("prepare %s for module listing: %w", dir, tidyErr)
		}
		output, err = runGoListModulesFunc(ctx, dir)
	}
	if err != nil {
		return nil, err
	}

	modules := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		modules[fields[0]] = fields[1]
	}
	return modules, nil
}

func runGoListModules(ctx context.Context, dir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=mod", "-m", "all")
	cmd.Dir = dir
	env, err := goCommandEnv(dir)
	if err != nil {
		return nil, err
	}
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list modules in %s: %w: %s", dir, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func runGoGet(ctx context.Context, dir, modulePath, version string) error {
	return runGoCommand(ctx, dir, "get", modulePath+"@"+version)
}

func runGoModTidy(ctx context.Context, dir string) error {
	return runGoCommand(ctx, dir, "mod", "tidy", "-e")
}

func runGoModVendor(ctx context.Context, dir string) error {
	return runGoCommand(ctx, dir, "mod", "vendor")
}

func runGoCommand(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	env, err := goCommandEnv(dir)
	if err != nil {
		return err
	}
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if trimmed != "" {
		fmt.Fprintln(os.Stderr, trimmed)
	}
	if err != nil {
		if trimmed == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, trimmed)
	}
	return nil
}

func goCommandEnv(dir string) ([]string, error) {
	return goenv.CommandEnv(dir)
}

func hasVendorDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "vendor"))
	return err == nil && info.IsDir()
}

func goStateDir(dir string) (string, error) {
	return goenv.StateDir(dir)
}

func isNonFatalGoModuleStateError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	if strings.Contains(message, "errors parsing go.mod:") {
		return true
	}
	if strings.Contains(message, "unknown revision v0.0.0") {
		return true
	}
	return strings.Contains(message, "go.mod at revision") && strings.Contains(message, "unknown revision")
}

func warnGoFix(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cvefix: warn: "+format+"\n", args...)
}

func maxSemver(left, right string) string {
	left = canonicalSemver(left)
	right = canonicalSemver(right)
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	if semver.Compare(left, right) >= 0 {
		return left
	}
	return right
}

func preserveVersionForm(currentVersion, targetVersion string) string {
	if targetVersion == "" {
		return ""
	}
	if strings.HasSuffix(currentVersion, "+incompatible") && !strings.HasSuffix(targetVersion, "+incompatible") {
		return targetVersion + "+incompatible"
	}
	return targetVersion
}

func canonicalSemver(version string) string {
	if version == "" {
		return ""
	}
	hasIncompatible := strings.HasSuffix(version, "+incompatible")
	base := strings.TrimSuffix(version, "+incompatible")
	if !strings.HasPrefix(base, "v") {
		base = "v" + base
	}
	canonical := semver.Canonical(base)
	if canonical == "" && semver.IsValid(base) {
		canonical = base
	}
	if canonical == "" {
		return ""
	}
	if hasIncompatible {
		return canonical + "+incompatible"
	}
	return canonical
}

func findFiles(root string, match func(path string, entry fs.DirEntry) bool) ([]string, error) {
	return findFilesWithOptions(root, match, FileOptions{})
}

func findFilesWithOptions(root string, match func(path string, entry fs.DirEntry) bool, options FileOptions) ([]string, error) {
	results := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if shouldSkipWalkPath(root, path, options.SkipPaths) {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case ".git", ".cvefix", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipWalkPath(root, path, options.SkipPaths) {
			return nil
		}
		if match(path, entry) {
			results = append(results, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	sort.Strings(results)
	return results, nil
}

func shouldSkipWalkPath(root, path string, skipPaths []string) bool {
	if len(skipPaths) == 0 {
		return false
	}
	return policy.ShouldSkipPath(root, path, skipPaths)
}
