package fixer

import (
	"context"
	"encoding/json"
	"errors"
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

var runNPMLockfileSyncFunc = runNPMLockfileSync
var runPNPMLockfileSyncFunc = runPNPMLockfileSync
var runYarnLockfileSyncFunc = runYarnLockfileSync

const (
	npmPackageLockFile  = "package-lock.json"
	npmShrinkwrapFile   = "npm-shrinkwrap.json"
	pnpmLockFile        = "pnpm-lock.yaml"
	yarnLockFile        = "yarn.lock"
	npmManagerPatch     = "npm"
	npmOverridePatch    = "npm-override"
	pnpmOverridePatch   = "pnpm-override"
	yarnResolutionPatch = "yarn-resolution"
	npmLockfilePatch    = "npm-lockfile"
	pnpmLockfilePatch   = "pnpm-lockfile"
	yarnLockfilePatch   = "yarn-lockfile"
	pnpmDirectPatch     = "pnpm-lockfile-direct"
)

type jsLockKinds struct {
	NPM  bool
	PNPM bool
	Yarn bool
}

func ApplyNPMFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyNPMFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyNPMFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	manifests, err := findFilesWithOptions(repo, func(path string, entry fs.DirEntry) bool {
		return entry.Name() == "package.json"
	}, options)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, nil
	}

	requirements := collectNPMRequirements(repo, manifests, findings)
	patches := make([]Patch, 0)
	manifestDirsToSync := map[string]map[string]string{}

	for _, manifestPath := range manifests {
		required := requirements[manifestPath]
		if len(required) == 0 {
			continue
		}

		lockKinds := detectJSLockKinds(filepath.Dir(manifestPath))
		filePatches, err := patchPackageJSON(manifestPath, required, lockKinds)
		if err != nil {
			return nil, err
		}
		patches = append(patches, filePatches...)
		if len(filePatches) > 0 {
			dir := filepath.Dir(manifestPath)
			if manifestDirsToSync[dir] == nil {
				manifestDirsToSync[dir] = map[string]string{}
			}
			for pkg, fixed := range required {
				manifestDirsToSync[dir][pkg] = preferHigherVersion(manifestDirsToSync[dir][pkg], fixed)
			}
		}
	}

	dirs := make([]string, 0, len(manifestDirsToSync))
	for dir := range manifestDirsToSync {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		lockfilePatches, err := syncJSLockfiles(ctx, dir, manifestDirsToSync[dir], options.UntrustedRepo)
		if err != nil {
			return nil, err
		}
		patches = append(patches, lockfilePatches...)
	}

	return patches, nil
}

func collectNPMRequirements(repo string, manifests []string, findings []vuln.Finding) map[string]map[string]string {
	known := map[string]struct{}{}
	byDir := map[string]string{}
	for _, manifest := range manifests {
		known[manifest] = struct{}{}
		byDir[filepath.Dir(manifest)] = manifest
	}
	fallbackTargets := defaultNPMFallbackTargets(repo, manifests)

	requirements := map[string]map[string]string{}
	for _, finding := range findings {
		if finding.Package == "" || finding.FixedVersion == "" || !isNPMEcosystem(finding.Ecosystem) {
			continue
		}
		targets := npmTargetsForFinding(finding, known, byDir)
		if len(targets) == 0 {
			targets = fallbackTargets
		}
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
		case npmPackageLockFile, npmShrinkwrapFile, pnpmLockFile, yarnLockFile:
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

func defaultNPMFallbackTargets(repo string, manifests []string) []string {
	if len(manifests) == 0 {
		return nil
	}
	if len(manifests) == 1 {
		return append([]string(nil), manifests[0])
	}

	withLockfile := make([]string, 0)
	for _, manifest := range manifests {
		if hasAnyJSLockfile(filepath.Dir(manifest)) {
			withLockfile = append(withLockfile, manifest)
		}
	}
	if len(withLockfile) > 0 {
		sort.Strings(withLockfile)
		return withLockfile
	}

	rootManifest := filepath.Join(repo, "package.json")
	for _, manifest := range manifests {
		if manifest == rootManifest {
			return []string{manifest}
		}
	}

	fallback := append([]string(nil), manifests...)
	sort.Strings(fallback)
	return fallback
}

func hasAnyJSLockfile(dir string) bool {
	kinds := detectJSLockKinds(dir)
	return kinds.NPM || kinds.PNPM || kinds.Yarn
}

func detectJSLockKinds(dir string) jsLockKinds {
	return jsLockKinds{
		NPM:  pathExists(filepath.Join(dir, npmPackageLockFile)) || pathExists(filepath.Join(dir, npmShrinkwrapFile)),
		PNPM: pathExists(filepath.Join(dir, pnpmLockFile)),
		Yarn: pathExists(filepath.Join(dir, yarnLockFile)),
	}
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func patchPackageJSON(path string, requirements map[string]string, lockKinds jsLockKinds) ([]Patch, error) {
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
	directPackages := map[string]bool{}

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
			directPackages[pkg] = true
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
				Manager: npmManagerPatch,
				Target:  path,
				Package: pkg,
				From:    current,
				To:      updated,
			})
		}
		manifest[section] = sectionMap
	}

	transitiveRequirements := make(map[string]string)
	for pkg, fixed := range requirements {
		if directPackages[pkg] {
			continue
		}
		transitiveRequirements[pkg] = fixed
	}

	overridePatches := applyTopLevelStringMap(manifest, "overrides", transitiveRequirements, npmOverridePatch, path)
	patches = append(patches, overridePatches...)
	if lockKinds.PNPM {
		pnpmPatches := applyNestedStringMap(manifest, "pnpm", "overrides", transitiveRequirements, pnpmOverridePatch, path)
		patches = append(patches, pnpmPatches...)
	}
	if lockKinds.Yarn {
		yarnPatches := applyTopLevelStringMap(manifest, "resolutions", transitiveRequirements, yarnResolutionPatch, path)
		patches = append(patches, yarnPatches...)
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

func applyTopLevelStringMap(manifest map[string]interface{}, key string, requirements map[string]string, manager string, target string) []Patch {
	if len(requirements) == 0 {
		return nil
	}
	raw, ok := manifest[key]
	if !ok {
		raw = map[string]interface{}{}
		manifest[key] = raw
	}
	table, ok := raw.(map[string]interface{})
	if !ok {
		table = map[string]interface{}{}
		manifest[key] = table
	}
	return applyRequirementMap(table, requirements, manager, target)
}

func applyNestedStringMap(manifest map[string]interface{}, parentKey string, childKey string, requirements map[string]string, manager string, target string) []Patch {
	if len(requirements) == 0 {
		return nil
	}
	parentRaw, ok := manifest[parentKey]
	if !ok {
		parentRaw = map[string]interface{}{}
		manifest[parentKey] = parentRaw
	}
	parentMap, ok := parentRaw.(map[string]interface{})
	if !ok {
		parentMap = map[string]interface{}{}
		manifest[parentKey] = parentMap
	}
	childRaw, ok := parentMap[childKey]
	if !ok {
		childRaw = map[string]interface{}{}
		parentMap[childKey] = childRaw
	}
	childMap, ok := childRaw.(map[string]interface{})
	if !ok {
		childMap = map[string]interface{}{}
		parentMap[childKey] = childMap
	}
	return applyRequirementMap(childMap, requirements, manager, target)
}

func applyRequirementMap(table map[string]interface{}, requirements map[string]string, manager string, target string) []Patch {
	patches := make([]Patch, 0)
	keys := make([]string, 0, len(requirements))
	for pkg := range requirements {
		keys = append(keys, pkg)
	}
	sort.Strings(keys)
	for _, pkg := range keys {
		fixed := normalizeVersionToken(requirements[pkg])
		if fixed == "" {
			continue
		}
		currentRaw, exists := table[pkg]
		current := ""
		if exists {
			current = strings.TrimSpace(fmt.Sprint(currentRaw))
		}
		if current != "" && compareLooseVersions(normalizeVersionToken(current), fixed) >= 0 {
			continue
		}
		table[pkg] = fixed
		patches = append(patches, Patch{
			Manager: manager,
			Target:  target,
			Package: pkg,
			From:    current,
			To:      fixed,
		})
	}
	return patches
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

func syncJSLockfiles(ctx context.Context, dir string, requirements map[string]string, untrustedRepo bool) ([]Patch, error) {
	lockfiles := []string{
		filepath.Join(dir, npmPackageLockFile),
		filepath.Join(dir, npmShrinkwrapFile),
		filepath.Join(dir, pnpmLockFile),
		filepath.Join(dir, yarnLockFile),
	}
	before := map[string][]byte{}
	for _, path := range lockfiles {
		data, err := os.ReadFile(path)
		if err == nil {
			before[path] = data
		}
	}
	if len(before) == 0 {
		return nil, nil
	}

	kinds := detectJSLockKinds(dir)
	if kinds.NPM {
		if err := runNPMLockfileSyncFunc(ctx, dir); err != nil {
			return nil, fmt.Errorf("sync npm lockfiles in %s: %w", dir, err)
		}
	}
	if kinds.PNPM {
		if err := runPNPMLockfileSyncFunc(ctx, dir); err != nil {
			fallbackPatches, fallbackErr := patchPNPMLockfileDirect(filepath.Join(dir, pnpmLockFile), requirements)
			if fallbackErr != nil {
				fmt.Fprintf(os.Stderr, "patchpilot: warn: skipping pnpm lockfile sync in %s: %v\n", dir, err)
				fmt.Fprintf(os.Stderr, "patchpilot: warn: pnpm direct lockfile fallback in %s also failed: %v\n", dir, fallbackErr)
			} else {
				patches := append(detectChangedLockfiles(before), fallbackPatches...)
				return dedupePatchList(patches), nil
			}
		}
	}
	if kinds.Yarn {
		if untrustedRepo {
			fmt.Fprintf(os.Stderr, "patchpilot: warn: skipping yarn lockfile sync in %s: untrusted repo mode disables yarn execution\n", dir)
		} else if err := runYarnLockfileSyncFunc(ctx, dir); err != nil {
			fmt.Fprintf(os.Stderr, "patchpilot: warn: skipping yarn lockfile sync in %s: %v\n", dir, err)
		}
	}

	patches := detectChangedLockfiles(before)
	sort.Slice(patches, func(i, j int) bool {
		return patches[i].Target < patches[j].Target
	})
	return patches, nil
}

func detectChangedLockfiles(before map[string][]byte) []Patch {
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
			Manager: lockfilePatchManager(filepath.Base(path)),
			Target:  path,
			Package: filepath.Base(path),
			From:    "stale",
			To:      "synced",
		})
	}
	return patches
}

func lockfilePatchManager(base string) string {
	switch base {
	case pnpmLockFile:
		return pnpmLockfilePatch
	case yarnLockFile:
		return yarnLockfilePatch
	default:
		return npmLockfilePatch
	}
}

func patchPNPMLockfileDirect(path string, requirements map[string]string) ([]Patch, error) {
	if len(requirements) == 0 {
		return nil, errors.New("no requirements for pnpm fallback")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	changed := false
	patches := make([]Patch, 0)

	keys := make([]string, 0, len(requirements))
	for pkg := range requirements {
		keys = append(keys, pkg)
	}
	sort.Strings(keys)

	for _, pkg := range keys {
		fixed := normalizeVersionToken(requirements[pkg])
		if fixed == "" {
			continue
		}

		headerPattern := regexp.MustCompile(`^(\s*)(['"]?)` + regexp.QuoteMeta(pkg) + `@([^'":\s]+)['"]?:\s*$`)
		depPattern := regexp.MustCompile(`^(\s*)` + regexp.QuoteMeta(pkg) + `:\s*([^\s#]+)\s*$`)
		for index, line := range lines {
			if match := headerPattern.FindStringSubmatch(line); len(match) == 4 {
				current := normalizeVersionToken(match[3])
				if current == "" || compareLooseVersions(current, fixed) >= 0 {
					continue
				}
				quote := match[2]
				lines[index] = match[1] + quote + pkg + "@" + fixed + quote + ":"
				patches = append(patches, Patch{
					Manager: pnpmDirectPatch,
					Target:  path,
					Package: pkg,
					From:    current,
					To:      fixed,
				})
				changed = true
				continue
			}

			if match := depPattern.FindStringSubmatch(line); len(match) == 3 {
				current := normalizeVersionToken(match[2])
				if current == "" || compareLooseVersions(current, fixed) >= 0 {
					continue
				}
				lines[index] = match[1] + pkg + ": " + fixed
				patches = append(patches, Patch{
					Manager: pnpmDirectPatch,
					Target:  path,
					Package: pkg,
					From:    current,
					To:      fixed,
				})
				changed = true
			}
		}
	}

	if !changed {
		return nil, errors.New("pnpm lockfile fallback produced no changes")
	}
	updated := strings.Join(lines, "\n")
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return nil, err
	}
	return dedupePatchList(patches), nil
}

func dedupePatchList(patches []Patch) []Patch {
	seen := make(map[string]Patch, len(patches))
	for _, patch := range patches {
		key := patch.Manager + "|" + patch.Target + "|" + patch.Package + "|" + patch.From + "|" + patch.To
		seen[key] = patch
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Patch, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func runNPMLockfileSync(ctx context.Context, dir string) error {
	if _, err := exec.LookPath("npm"); err != nil {
		return fmt.Errorf("required tool %q not found in PATH", "npm")
	}
	command := exec.CommandContext(
		ctx,
		"npm",
		"install",
		"--package-lock-only",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
	)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, message)
	}
	return nil
}

func runPNPMLockfileSync(ctx context.Context, dir string) error {
	args := []string{"install", "--lockfile-only", "--ignore-scripts", "--no-frozen-lockfile"}
	candidates := []struct {
		bin  string
		args []string
	}{
		{bin: "pnpm", args: args},
		{bin: "corepack", args: append([]string{"pnpm"}, args...)},
		{bin: "npx", args: append([]string{"--yes", "pnpm@9"}, args...)},
	}
	return runJSLockSyncCandidates(ctx, dir, candidates)
}

func runYarnLockfileSync(ctx context.Context, dir string) error {
	if yarnPath := detectYarnPathFromConfig(dir); yarnPath != "" {
		command := exec.CommandContext(ctx, "node", yarnPath, "install", "--mode=update-lockfile")
		command.Dir = dir
		output, err := command.CombinedOutput()
		if err == nil {
			return nil
		}
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("node %s install --mode=update-lockfile: %w", yarnPath, err)
		}
		// Fall through to other candidates to improve compatibility across mixed Yarn setups.
	}

	candidates := []struct {
		bin  string
		args []string
	}{
		{bin: "yarn", args: []string{"install", "--mode=update-lockfile"}},
		{bin: "yarn", args: []string{"install", "--mode=update-lockfile", "--ignore-scripts"}},
		{bin: "yarn", args: []string{"install", "--ignore-scripts"}},
		{bin: "npx", args: []string{"--yes", "yarn@1", "install"}},
		{bin: "npx", args: []string{"--yes", "yarn@1", "install", "--ignore-scripts"}},
	}
	return runJSLockSyncCandidates(ctx, dir, candidates)
}

func detectYarnPathFromConfig(dir string) string {
	configPath := filepath.Join(dir, ".yarnrc.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "yarnPath:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "yarnPath:"))
		value = strings.Trim(value, `"'`)
		if value == "" {
			return ""
		}
		candidate := value
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(dir, candidate)
		}
		if pathExists(candidate) {
			return candidate
		}
		return ""
	}
	return ""
}

func runJSLockSyncCandidates(ctx context.Context, dir string, candidates []struct {
	bin  string
	args []string
}) error {
	var lastErr error
	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate.bin); err != nil {
			continue
		}
		command := exec.CommandContext(ctx, candidate.bin, candidate.args...)
		command.Dir = dir
		output, err := command.CombinedOutput()
		if err == nil {
			return nil
		}
		message := strings.TrimSpace(string(output))
		if message == "" {
			lastErr = fmt.Errorf("%s %s: %w", candidate.bin, strings.Join(candidate.args, " "), err)
		} else {
			lastErr = fmt.Errorf("%s %s: %w: %s", candidate.bin, strings.Join(candidate.args, " "), err, message)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("no lockfile sync command available in PATH")
}
