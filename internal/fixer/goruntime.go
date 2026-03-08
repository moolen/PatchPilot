package fixer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

var (
	goReleaseHTTPClient               = &http.Client{Timeout: 10 * time.Second}
	goReleaseAPIURL                   = "https://go.dev/dl/?mode=json"
	fetchSupportedGoPatchVersionsFunc = fetchSupportedGoPatchVersions
)

type goPatchVersion struct {
	Major int
	Minor int
	Patch int
}

func (version goPatchVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)
}

func (version goPatchVersion) lineKey() string {
	return fmt.Sprintf("%d.%d", version.Major, version.Minor)
}

func (version goPatchVersion) compare(other goPatchVersion) int {
	if version.Major != other.Major {
		if version.Major < other.Major {
			return -1
		}
		return 1
	}
	if version.Minor != other.Minor {
		if version.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if version.Patch != other.Patch {
		if version.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

func ApplyGoRuntimeFixes(ctx context.Context, repo string) ([]Patch, error) {
	return ApplyGoRuntimeFixesWithOptions(ctx, repo, FileOptions{})
}

func ApplyGoRuntimeFixesWithOptions(ctx context.Context, repo string, options FileOptions) ([]Patch, error) {
	if goRuntimeBumpsDisabled() {
		return nil, nil
	}

	goMods, err := findFilesWithOptions(repo, func(path string, entry os.DirEntry) bool {
		return entry.Name() == "go.mod"
	}, options)
	if err != nil {
		return nil, err
	}
	if len(goMods) == 0 {
		return nil, nil
	}

	supportedByLine, err := fetchSupportedGoPatchVersionsFunc(ctx)
	if err != nil {
		warnGoFix("skipping Go runtime bumps: %v", err)
		return nil, nil
	}
	if len(supportedByLine) == 0 {
		return nil, nil
	}

	patches := make([]Patch, 0)
	modifiedDirs := map[string]struct{}{}
	vendorDirs := map[string]struct{}{}

	for _, goModPath := range goMods {
		patch, changed, err := patchGoRuntimeDirective(goModPath, supportedByLine)
		if err != nil {
			return nil, err
		}
		if !changed {
			continue
		}
		patches = append(patches, patch)
		moduleDir := filepath.Dir(goModPath)
		modifiedDirs[moduleDir] = struct{}{}
		if hasVendorDir(moduleDir) {
			vendorDirs[moduleDir] = struct{}{}
		}
	}

	if len(modifiedDirs) == 0 {
		return nil, nil
	}

	dirs := make([]string, 0, len(modifiedDirs))
	for dir := range modifiedDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		if err := runGoModTidyFunc(ctx, dir); err != nil {
			if isNonFatalGoModuleStateError(err) {
				warnGoFix("keeping Go runtime bump in %s without tidy: %v", dir, err)
			} else {
				return nil, fmt.Errorf("run go mod tidy in %s after Go runtime bump: %w", dir, err)
			}
		}
		if _, ok := vendorDirs[dir]; ok {
			if err := runGoModVendorFunc(ctx, dir); err != nil {
				return nil, fmt.Errorf("run go mod vendor in %s after Go runtime bump: %w", dir, err)
			}
		}
	}

	return patches, nil
}

func goRuntimeBumpsDisabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("CVEFIX_DISABLE_GO_RUNTIME_BUMPS")))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func patchGoRuntimeDirective(path string, supportedByLine map[string]goPatchVersion) (Patch, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Patch{}, false, fmt.Errorf("read %s: %w", path, err)
	}

	parsed, err := modfile.Parse(path, data, nil)
	if err != nil {
		return Patch{}, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if parsed.Go == nil {
		return Patch{}, false, nil
	}

	currentRaw := parsed.Go.Version
	current, ok := parseGoDirectiveVersion(currentRaw)
	if !ok {
		warnGoFix("skipping Go runtime bump for %s: cannot parse go directive %q", path, currentRaw)
		return Patch{}, false, nil
	}

	target, shouldBump := chooseTargetGoVersion(current, supportedByLine)
	if !shouldBump {
		return Patch{}, false, nil
	}

	if err := parsed.AddGoStmt(target.String()); err != nil {
		return Patch{}, false, fmt.Errorf("update go directive in %s: %w", path, err)
	}
	parsed.Cleanup()

	formatted, err := parsed.Format()
	if err != nil {
		return Patch{}, false, fmt.Errorf("format %s: %w", path, err)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return Patch{}, false, fmt.Errorf("write %s: %w", path, err)
	}

	return Patch{
		Manager: "goruntime",
		Target:  path,
		Package: "go",
		From:    currentRaw,
		To:      target.String(),
	}, true, nil
}

func fetchSupportedGoPatchVersions(ctx context.Context) (map[string]goPatchVersion, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, goReleaseAPIURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := goReleaseHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query Go releases: %s", response.Status)
	}

	var releases []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
	}
	if err := json.NewDecoder(response.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("decode Go releases: %w", err)
	}

	byLine := map[string]goPatchVersion{}
	for _, release := range releases {
		if !release.Stable {
			continue
		}
		version, ok := parseGoReleaseVersion(release.Version)
		if !ok {
			continue
		}
		key := version.lineKey()
		if existing, found := byLine[key]; !found || existing.compare(version) < 0 {
			byLine[key] = version
		}
	}
	if len(byLine) == 0 {
		return nil, fmt.Errorf("no stable Go releases found")
	}
	return byLine, nil
}

func chooseTargetGoVersion(current goPatchVersion, supportedByLine map[string]goPatchVersion) (goPatchVersion, bool) {
	if candidate, ok := supportedByLine[current.lineKey()]; ok {
		if candidate.compare(current) > 0 {
			return candidate, true
		}
		return goPatchVersion{}, false
	}

	lines := make([]goPatchVersion, 0, len(supportedByLine))
	for _, version := range supportedByLine {
		lines = append(lines, version)
	}
	sort.Slice(lines, func(i, j int) bool {
		return lines[i].compare(lines[j]) < 0
	})

	oldestSupported := lines[0]
	newestSupported := lines[len(lines)-1]
	if current.compare(oldestSupported) < 0 {
		return oldestSupported, true
	}
	if current.compare(newestSupported) > 0 {
		return goPatchVersion{}, false
	}
	return oldestSupported, true
}

var goReleaseVersionPattern = regexp.MustCompile(`^go(\d+)\.(\d+)(?:\.(\d+))?`)

func parseGoReleaseVersion(version string) (goPatchVersion, bool) {
	match := goReleaseVersionPattern.FindStringSubmatch(version)
	if len(match) < 3 {
		return goPatchVersion{}, false
	}

	major, err := strconv.Atoi(match[1])
	if err != nil {
		return goPatchVersion{}, false
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return goPatchVersion{}, false
	}
	patch := 0
	if len(match) >= 4 && match[3] != "" {
		patch, err = strconv.Atoi(match[3])
		if err != nil {
			return goPatchVersion{}, false
		}
	}

	return goPatchVersion{Major: major, Minor: minor, Patch: patch}, true
}

var goDirectiveVersionPattern = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)

func parseGoDirectiveVersion(version string) (goPatchVersion, bool) {
	match := goDirectiveVersionPattern.FindStringSubmatch(version)
	if len(match) < 3 {
		return goPatchVersion{}, false
	}

	major, err := strconv.Atoi(match[1])
	if err != nil {
		return goPatchVersion{}, false
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return goPatchVersion{}, false
	}
	patch := 0
	if len(match) >= 4 && match[3] != "" {
		patch, err = strconv.Atoi(match[3])
		if err != nil {
			return goPatchVersion{}, false
		}
	}
	return goPatchVersion{Major: major, Minor: minor, Patch: patch}, true
}
