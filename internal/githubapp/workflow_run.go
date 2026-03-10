package githubapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (service *Service) runFixWorkflow(ctx context.Context, owner, repo, defaultBranch, token, preferredBranch string) (fixRunResult, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return fixRunResult{}, fmt.Errorf("owner and repo must not be empty")
	}
	if strings.TrimSpace(defaultBranch) == "" {
		defaultBranch = "master"
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
		"branch": defaultBranch,
	})

	if _, _, err := runCommand(ctx, tempRoot, nil, "git", "clone", "--depth", "1", "--branch", defaultBranch, cloneURL, repoPath); err != nil {
		return fixRunResult{}, fmt.Errorf("clone repository: %w", err)
	}
	headSHA, err := currentHeadSHA(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	service.log("info", "repository cloned", map[string]interface{}{
		"owner":    owner,
		"repo":     repo,
		"head_sha": headSHA,
	})

	args := []string{"fix", "--dir", repoPath, "--enable-agent=false", "--untrusted-repo-policy"}

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
	if runErr != nil && exitCode != 23 {
		return fixRunResult{}, fmt.Errorf("run PatchPilot (exit %d): %w\nstderr:\n%s", exitCode, runErr, truncateForComment(stderr))
	}

	changed, err := hasRepositoryChanges(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	if !changed {
		service.log("info", "fix workflow detected no repository changes", map[string]interface{}{
			"owner":     owner,
			"repo":      repo,
			"head_sha":  headSHA,
			"exit_code": exitCode,
		})
		return fixRunResult{ExitCode: exitCode, Stdout: stdout, Stderr: stderr, Changed: false, HeadSHA: headSHA}, nil
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
		service.log("info", "fix workflow excluded artifact-only changes", map[string]interface{}{
			"owner":     owner,
			"repo":      repo,
			"branch":    branch,
			"exit_code": exitCode,
		})
		return fixRunResult{ExitCode: exitCode, Stdout: stdout, Stderr: stderr, Changed: false, HeadSHA: headSHA}, nil
	}
	service.log("info", "staged remediation changes", map[string]interface{}{
		"owner":         owner,
		"repo":          repo,
		"branch":        branch,
		"changed_files": len(changedFiles),
		"files":         changedFiles,
	})
	safety, err := service.evaluateSafety(repoPath, changedFiles)
	if err != nil {
		return fixRunResult{}, fmt.Errorf("evaluate safety: %w", err)
	}
	if safety.Blocked {
		service.log("warn", "safety policy blocked remediation changes", map[string]interface{}{
			"owner":                    owner,
			"repo":                     repo,
			"branch":                   branch,
			"reason":                   safety.Reason,
			"risk_score":               safety.RiskScore,
			"verification_regressions": safety.VerificationRegressions,
		})
		return fixRunResult{
			ExitCode:        exitCode,
			Stdout:          stdout,
			Stderr:          stderr,
			Changed:         false,
			Branch:          "",
			HeadSHA:         headSHA,
			BlockedReason:   safety.Reason,
			RiskScore:       safety.RiskScore,
			ChangedFiles:    changedFiles,
			RegressionCount: safety.VerificationRegressions,
		}, nil
	}

	commitEnv := map[string]string{
		"GIT_AUTHOR_NAME":     "patchpilot-app[bot]",
		"GIT_AUTHOR_EMAIL":    "patchpilot-app[bot]@users.noreply.github.com",
		"GIT_COMMITTER_NAME":  "patchpilot-app[bot]",
		"GIT_COMMITTER_EMAIL": "patchpilot-app[bot]@users.noreply.github.com",
	}
	if _, _, err := runCommand(ctx, repoPath, commitEnv, "git", "commit", "-m", "chore: automated CVE remediation"); err != nil {
		if !strings.Contains(err.Error(), "nothing to commit") {
			return fixRunResult{}, fmt.Errorf("git commit: %w", err)
		}
	}
	service.log("info", "committed remediation changes", map[string]interface{}{
		"owner":  owner,
		"repo":   repo,
		"branch": branch,
	})

	pushArgs := []string{"push", "origin", branch}
	if strings.TrimSpace(preferredBranch) != "" {
		remoteRef := fmt.Sprintf("refs/heads/%s", branch)
		lsRemoteOutput, lsRemoteStderr, lsRemoteErr := runCommand(ctx, repoPath, nil, "git", "ls-remote", "--heads", "origin", remoteRef)
		if lsRemoteErr != nil {
			return fixRunResult{}, fmt.Errorf(
				"git ls-remote remediation branch: %w\nstdout:\n%s\nstderr:\n%s",
				lsRemoteErr,
				truncateForComment(lsRemoteOutput),
				truncateForComment(lsRemoteStderr),
			)
		}

		expectedHead := remoteBranchHeadFromLSRemote(lsRemoteOutput, remoteRef)
		if expectedHead != "" {
			pushArgs = []string{
				"push",
				fmt.Sprintf("--force-with-lease=%s:%s", remoteRef, expectedHead),
				"origin",
				branch,
			}
		} else {
			pushArgs = []string{"push", "origin", branch}
		}
	}
	service.log("info", "pushing remediation branch", map[string]interface{}{
		"owner":     owner,
		"repo":      repo,
		"branch":    branch,
		"push_args": pushArgs,
	})
	pushStdout, pushStderr, pushErr := runCommand(ctx, repoPath, nil, "git", pushArgs...)
	if pushErr != nil {
		return fixRunResult{}, fmt.Errorf(
			"git push: %w\nstdout:\n%s\nstderr:\n%s",
			pushErr,
			truncateForComment(pushStdout),
			truncateForComment(pushStderr),
		)
	}
	headSHA, err = currentHeadSHA(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	service.log("info", "pushed remediation branch", map[string]interface{}{
		"owner":         owner,
		"repo":          repo,
		"branch":        branch,
		"head_sha":      headSHA,
		"push_stdout":   previewLogText(pushStdout),
		"push_stderr":   previewLogText(pushStderr),
		"risk_score":    safety.RiskScore,
		"changed_files": len(changedFiles),
	})

	return fixRunResult{
		ExitCode:        exitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		Changed:         true,
		Branch:          branch,
		HeadSHA:         headSHA,
		RiskScore:       safety.RiskScore,
		ChangedFiles:    changedFiles,
		RegressionCount: safety.VerificationRegressions,
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
