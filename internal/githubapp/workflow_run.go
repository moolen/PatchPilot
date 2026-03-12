package githubapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moolen/patchpilot/internal/policy"
)

func (service *Service) runFixWorkflow(ctx context.Context, owner, repo, repoKey, defaultBranch, token, preferredBranch string, cfg *policy.Config, scan scanRunResult) (fixRunResult, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return fixRunResult{}, fmt.Errorf("owner and repo must not be empty")
	}
	if strings.TrimSpace(defaultBranch) == "" {
		defaultBranch = "master"
	}

	targetBranch := strings.TrimSpace(preferredBranch)
	if targetBranch == "" {
		targetBranch = defaultBranch
	}

	service.log("info", "starting fix workflow", map[string]interface{}{
		"owner":            owner,
		"repo":             repo,
		"default_branch":   defaultBranch,
		"preferred_branch": preferredBranch,
	})

	tempRoot, err := os.MkdirTemp(service.cfg.WorkDir, "patchpilot-repo-")
	if err != nil {
		return fixRunResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempRoot)
	}()

	repoPath := filepath.Join(tempRoot, "repo")
	cloneURL, err := repositoryCloneURL(service.cfg.GitHubBaseWebURL, owner, repo, token)
	if err != nil {
		return fixRunResult{}, err
	}

	service.log("info", "cloning repository", map[string]interface{}{
		"owner":  owner,
		"repo":   repo,
		"branch": targetBranch,
	})
	if _, _, err := runCommand(ctx, tempRoot, nil, "git", "clone", "--depth", "1", "--branch", targetBranch, cloneURL, repoPath); err != nil {
		return fixRunResult{}, fmt.Errorf("clone repository: %w", err)
	}
	headSHA, err := currentHeadSHA(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	normalizeFindingLocations(repoPath, scan.Report)

	patches, issues, err := service.applyDeterministicRepositoryFixes(ctx, repoPath, cfg, scan.Report)
	if err != nil {
		return fixRunResult{}, err
	}
	if err := service.applyContainerOSPatchingWithAI(ctx, repoPath, repoKey, scan.Report, scan); err != nil {
		issues = append(issues, fmt.Sprintf("container_os_patching: %v", err))
	}

	changed, err := hasRepositoryChanges(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	if !changed {
		service.log("info", "fix workflow detected no repository changes", map[string]interface{}{
			"owner":       owner,
			"repo":        repo,
			"head_sha":    headSHA,
			"issue_count": len(issues),
		})
		return fixRunResult{
			ExitCode: 0,
			Stdout:   strings.Join(issues, "\n"),
			Changed:  false,
			HeadSHA:  headSHA,
		}, nil
	}

	branch := strings.TrimSpace(preferredBranch)
	if branch == "" {
		branch = fmt.Sprintf("patchpilot/auto-fix-%s", time.Now().UTC().Format("20060102-150405"))
	}
	if _, _, err := runCommand(ctx, repoPath, nil, "git", "checkout", "-B", branch); err != nil {
		return fixRunResult{}, fmt.Errorf("checkout branch: %w", err)
	}
	if _, _, err := runCommand(ctx, repoPath, nil, "git", "add", "-A"); err != nil {
		return fixRunResult{}, fmt.Errorf("git add: %w", err)
	}
	if err := unstagePath(ctx, repoPath, ".patchpilot"); err != nil {
		return fixRunResult{}, err
	}
	changedFiles, err := stagedChangedFiles(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	if len(changedFiles) == 0 {
		return fixRunResult{ExitCode: 0, Stdout: strings.Join(issues, "\n"), Changed: false, HeadSHA: headSHA}, nil
	}
	for _, changed := range changedFiles {
		if pathBlocked(changed, service.cfg.DisallowedPaths) {
			return fixRunResult{
				ExitCode:      0,
				Stdout:        strings.Join(issues, "\n"),
				Changed:       false,
				HeadSHA:       headSHA,
				BlockedReason: fmt.Sprintf("changed path %q is blocked by PP_DISALLOWED_PATHS", changed),
				ChangedFiles:  changedFiles,
			}, nil
		}
	}

	commitEnv := map[string]string{
		"GIT_AUTHOR_NAME":     "patchpilot-app[bot]",
		"GIT_AUTHOR_EMAIL":    "patchpilot-app[bot]@users.noreply.github.com",
		"GIT_COMMITTER_NAME":  "patchpilot-app[bot]",
		"GIT_COMMITTER_EMAIL": "patchpilot-app[bot]@users.noreply.github.com",
	}
	if _, _, err := runCommand(ctx, repoPath, commitEnv, "git", "commit", "-m", remediationPRTitle); err != nil {
		if !strings.Contains(err.Error(), "nothing to commit") {
			return fixRunResult{}, fmt.Errorf("git commit: %w", err)
		}
	}

	pushArgs := []string{"push", "origin", branch}
	if strings.TrimSpace(preferredBranch) != "" {
		remoteRef := fmt.Sprintf("refs/heads/%s", branch)
		lsRemoteOutput, lsRemoteStderr, lsRemoteErr := runCommand(ctx, repoPath, nil, "git", "ls-remote", "--heads", "origin", remoteRef)
		if lsRemoteErr != nil {
			return fixRunResult{}, fmt.Errorf("git ls-remote remediation branch: %w\nstdout:\n%s\nstderr:\n%s", lsRemoteErr, truncateForComment(lsRemoteOutput), truncateForComment(lsRemoteStderr))
		}
		expectedHead := remoteBranchHeadFromLSRemote(lsRemoteOutput, remoteRef)
		if expectedHead != "" {
			pushArgs = []string{"push", fmt.Sprintf("--force-with-lease=%s:%s", remoteRef, expectedHead), "origin", branch}
		}
	}
	pushStdout, pushStderr, pushErr := runCommand(ctx, repoPath, nil, "git", pushArgs...)
	if pushErr != nil {
		return fixRunResult{}, fmt.Errorf("git push: %w\nstdout:\n%s\nstderr:\n%s", pushErr, truncateForComment(pushStdout), truncateForComment(pushStderr))
	}
	headSHA, err = currentHeadSHA(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}

	return fixRunResult{
		ExitCode:     0,
		Stdout:       strings.Join(issues, "\n"),
		Stderr:       "",
		Changed:      true,
		Branch:       branch,
		HeadSHA:      headSHA,
		RiskScore:    len(changedFiles) + len(patches),
		ChangedFiles: changedFiles,
	}, nil
}

func previewLogText(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ""
	}
	const max = 400
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "... (truncated)"
}

func remoteBranchHeadFromLSRemote(lsRemoteOutput, remoteRef string) string {
	for _, line := range strings.Split(lsRemoteOutput, "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 2 && parts[1] == remoteRef {
			return parts[0]
		}
	}
	return ""
}
