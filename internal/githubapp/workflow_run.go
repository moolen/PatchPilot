package githubapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	args := []string{
		"fix",
		"--dir", repoPath,
		"--untrusted-repo-policy",
		"--enable-agent=" + strconv.FormatBool(strings.TrimSpace(service.cfg.AgentCommand) != ""),
		"--repository-key", repoKey,
	}
	if command := strings.TrimSpace(service.cfg.AgentCommand); command != "" {
		args = append(args, "--agent-command", command)
	}
	service.log("info", "running patchpilot fix", map[string]interface{}{
		"owner": owner,
		"repo":  repo,
		"args":  args,
	})
	stdout, stderr, runErr := service.jobRunner.Run(ctx, repoPath, args)
	exitCode := commandExitCode(runErr)
	service.log("info", "patchpilot fix finished", map[string]interface{}{
		"owner":          owner,
		"repo":           repo,
		"exit_code":      exitCode,
		"stdout_bytes":   len(stdout),
		"stderr_bytes":   len(stderr),
		"stdout_preview": previewLogText(stdout),
		"stderr_preview": previewLogText(stderr),
	})
	if runErr != nil {
		return fixRunResult{}, fmt.Errorf("run PatchPilot fix (exit %d): %w\nstderr:\n%s", exitCode, runErr, truncateForComment(stderr))
	}

	changed, err := hasRepositoryChanges(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	if !changed {
		service.log("info", "fix workflow detected no repository changes", map[string]interface{}{
			"owner":    owner,
			"repo":     repo,
			"head_sha": headSHA,
		})
		return fixRunResult{
			ExitCode: exitCode,
			Stdout:   stdout,
			Stderr:   stderr,
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
	if err := unstagePatchPilotArtifacts(ctx, repoPath); err != nil {
		return fixRunResult{}, err
	}
	changedFiles, err := stagedChangedFiles(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	if len(changedFiles) == 0 {
		return fixRunResult{ExitCode: exitCode, Stdout: stdout, Stderr: stderr, Changed: false, HeadSHA: headSHA}, nil
	}
	for _, changed := range changedFiles {
		if pathBlocked(changed, service.cfg.DisallowedPaths) {
			return fixRunResult{
				ExitCode:      exitCode,
				Stdout:        stdout,
				Stderr:        stderr,
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
		ExitCode:     exitCode,
		Stdout:       stdout,
		Stderr:       stderr,
		Changed:      true,
		Branch:       branch,
		HeadSHA:      headSHA,
		RiskScore:    len(changedFiles),
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
