package pathmatch

import (
	"path/filepath"
	"regexp"
	"strings"
)

func ShouldSkipPath(repo, candidate string, skipPaths []string) bool {
	relative, ok := repoRelativePath(repo, candidate)
	if !ok {
		return false
	}
	for _, pattern := range skipPaths {
		if matchPathPattern(pattern, relative) {
			return true
		}
	}
	return false
}

func LocationMatches(repo, location, wantedPath string) bool {
	wantedPath = cleanRelativePath(wantedPath)
	if wantedPath == "" {
		return false
	}
	locationRelative, ok := repoRelativePath(repo, location)
	if !ok {
		return false
	}
	return matchPathPattern(wantedPath, locationRelative)
}

func repoRelativePath(repo, candidate string) (string, bool) {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return "", false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(repoAbs, candidateAbs)
	if err != nil {
		return "", false
	}
	relative = filepath.ToSlash(filepath.Clean(relative))
	if relative == "." {
		return ".", true
	}
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return "", false
	}
	return relative, true
}

func matchPathPattern(pattern, relativePath string) bool {
	pattern = cleanRelativePath(pattern)
	relativePath = cleanRelativePath(relativePath)
	if pattern == "" || relativePath == "" {
		return false
	}

	if !hasGlob(pattern) {
		return relativePath == pattern || strings.HasPrefix(relativePath, pattern+"/")
	}

	if strings.HasSuffix(pattern, "/**") {
		base := strings.TrimSuffix(pattern, "/**")
		if relativePath == base || strings.HasPrefix(relativePath, base+"/") {
			return true
		}
	}

	regexPattern := globToRegex(pattern)
	matcher, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	return matcher.MatchString(relativePath)
}

func hasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func globToRegex(pattern string) string {
	var builder strings.Builder
	builder.WriteString("^")
	for index := 0; index < len(pattern); index++ {
		char := pattern[index]
		if char == '*' {
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				builder.WriteString(".*")
				index++
				continue
			}
			builder.WriteString("[^/]*")
			continue
		}
		if char == '?' {
			builder.WriteString("[^/]")
			continue
		}
		if strings.ContainsRune(`.+()|[]{}^$\`, rune(char)) {
			builder.WriteByte('\\')
		}
		builder.WriteByte(char)
	}
	builder.WriteString("$")
	return builder.String()
}

func cleanRelativePath(path string) string {
	path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "/")
	if path == "." {
		return ""
	}
	return path
}
