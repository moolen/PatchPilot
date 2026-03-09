package verifycheck

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/pathmatch"
)

func DiscoverModuleDirs(repo string) ([]string, error) {
	return DiscoverModuleDirsWithOptions(repo, DiscoverOptions{})
}

func DiscoverModuleDirsWithOptions(repo string, options DiscoverOptions) ([]string, error) {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}

	dirs := make([]string, 0)
	err = filepath.WalkDir(repoAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if shouldSkipPath(repoAbs, path, options.SkipPaths) {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case ".git", ".patchpilot", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" {
			return nil
		}
		if shouldSkipPath(repoAbs, path, options.SkipPaths) {
			return nil
		}
		relDir, err := filepath.Rel(repoAbs, filepath.Dir(path))
		if err != nil {
			return fmt.Errorf("relativize module dir %s: %w", path, err)
		}
		dirs = append(dirs, filepath.Clean(relDir))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk repo for go.mod files: %w", err)
	}
	sort.Strings(dirs)
	return dedupeSorted(dirs), nil
}

func ModuleDirs(report Report) []string {
	dirs := make([]string, 0, len(report.Modules))
	for _, module := range report.Modules {
		dirs = append(dirs, module.Dir)
	}
	sort.Strings(dirs)
	return dirs
}

func discoverStandardTargetDirs(repoAbs string) ([]string, error) {
	dirs := make([]string, 0)
	err := filepath.WalkDir(repoAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".patchpilot", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !isStandardTargetFile(entry.Name()) {
			return nil
		}
		relDir, err := filepath.Rel(repoAbs, filepath.Dir(path))
		if err != nil {
			return err
		}
		dirs = append(dirs, filepath.Clean(relDir))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk repo for verification targets: %w", err)
	}
	return dedupeSorted(dirs), nil
}

func isStandardTargetFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".csproj") {
		return true
	}
	if strings.EqualFold(name, "go.mod") || strings.EqualFold(name, "package.json") || strings.EqualFold(name, "pom.xml") || strings.EqualFold(name, "build.gradle") || strings.EqualFold(name, "build.gradle.kts") || strings.EqualFold(name, "cargo.toml") || strings.EqualFold(name, "composer.json") {
		return true
	}
	return strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt")
}

func resolveModuleDir(repoAbs, dir string) (string, string, error) {
	candidate := filepath.Clean(dir)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(repoAbs, candidate)
	}
	absDir, err := filepath.Abs(candidate)
	if err != nil {
		return "", "", fmt.Errorf("resolve module dir %s: %w", dir, err)
	}
	relDir, err := filepath.Rel(repoAbs, absDir)
	if err != nil {
		return "", "", fmt.Errorf("relativize module dir %s: %w", dir, err)
	}
	if relDir == ".." || strings.HasPrefix(relDir, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("module dir %s escapes repo %s", dir, repoAbs)
	}
	info, err := os.Stat(absDir)
	if err != nil {
		return "", "", fmt.Errorf("stat module dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("module dir %s is not a directory", dir)
	}
	return absDir, filepath.Clean(relDir), nil
}

func dedupeSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	copyItems := append([]string(nil), items...)
	sort.Strings(copyItems)
	result := make([]string, 0, len(copyItems))
	for _, item := range copyItems {
		if len(result) > 0 && result[len(result)-1] == item {
			continue
		}
		result = append(result, item)
	}
	return result
}

func shouldSkipPath(repo, path string, skipPaths []string) bool {
	if len(skipPaths) == 0 {
		return false
	}
	return pathmatch.ShouldSkipPath(repo, path, skipPaths)
}
