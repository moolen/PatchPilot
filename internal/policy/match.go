package policy

import "github.com/moolen/patchpilot/internal/pathmatch"

func ShouldSkipPath(repo, candidate string, skipPaths []string) bool {
	return pathmatch.ShouldSkipPath(repo, candidate, skipPaths)
}

func LocationMatches(repo, location, wantedPath string) bool {
	return pathmatch.LocationMatches(repo, location, wantedPath)
}
