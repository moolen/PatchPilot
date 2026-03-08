package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v75/github"
)

type fixRunResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	Changed         bool
	Branch          string
	BlockedReason   string
	RiskScore       int
	ChangedFiles    []string
	RegressionCount int
}

const remediationPRTitle = "chore: automated CVE remediation"

func (service *Service) processIssueComment(event *github.IssueCommentEvent, installationID int64, command FixCommand) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	owner := ownerFromRepository(event.GetRepo())
	repo := event.GetRepo().GetName()
	defaultBranch := event.GetRepo().GetDefaultBranch()
	issueNumber := event.GetIssue().GetNumber()

	client, token, err := service.installationClient(ctx, installationID)
	if err != nil {
		service.metrics.IncFailure("installation_client")
		service.log("error", "installation client failed", map[string]interface{}{"trigger": "issue_comment", "owner": owner, "repo": repo, "error": err.Error()})
		return
	}

	service.postIssueComment(ctx, client, owner, repo, issueNumber, remediationStartedComment())

	existingPR, _, err := service.findOpenRemediationPR(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		service.log("warn", "failed to query existing remediation PR", map[string]interface{}{"owner": owner, "repo": repo, "error": err.Error()})
	}
	preferredBranch := ""
	if existingPR != nil {
		preferredBranch = existingPR.GetHead().GetRef()
	}

	result, err := service.runFixWorkflow(ctx, owner, repo, defaultBranch, token, command, preferredBranch)
	if err != nil {
		service.metrics.IncFix("failed")
		service.metrics.IncFailure("fix_workflow")
		service.postIssueComment(ctx, client, owner, repo, issueNumber, remediationFailedComment(err))
		return
	}
	if result.BlockedReason != "" {
		service.metrics.IncFix("blocked")
		service.postIssueComment(
			ctx,
			client,
			owner,
			repo,
			issueNumber,
			remediationBlockedComment(result.BlockedReason, result.RiskScore),
		)
		return
	}

	if !result.Changed {
		service.metrics.IncFix("nochange")
		service.postIssueComment(ctx, client, owner, repo, issueNumber, remediationNoChangesComment(result.ExitCode))
		return
	}

	body := service.remediationPRBody(
		fmt.Sprintf("issue comment by @%s", event.GetSender().GetLogin()),
		"/cvefix fix",
		result,
	)
	pr, created, err := service.upsertRemediationPR(ctx, client, owner, repo, defaultBranch, result.Branch, body, existingPR)
	if err != nil {
		service.metrics.IncFix("failed")
		service.metrics.IncFailure("pr_upsert")
		service.postIssueComment(ctx, client, owner, repo, issueNumber, remediationPRUpsertFailedComment(err))
		return
	}
	service.metrics.IncFix("changed")

	action := "updated"
	if created {
		action = "opened"
	}
	autoMergeErr := error(nil)
	if command.AutoMerge && service.cfg.EnableAutoMerge {
		autoMergeErr = service.enablePRAutoMerge(ctx, token, pr.GetNodeID())
	}
	message := remediationPRReadyComment(action, pr.GetHTMLURL(), command.AutoMerge, service.cfg.EnableAutoMerge, autoMergeErr)
	service.postIssueComment(ctx, client, owner, repo, issueNumber, message)
}

func (service *Service) processPushEvent(event *github.PushEvent, installationID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	owner := ownerFromPushRepository(event.GetRepo())
	repo := event.GetRepo().GetName()
	defaultBranch := event.GetRepo().GetDefaultBranch()

	client, token, err := service.installationClient(ctx, installationID)
	if err != nil {
		service.metrics.IncFailure("installation_client")
		service.log("error", "installation client failed", map[string]interface{}{"trigger": "push", "owner": owner, "repo": repo, "error": err.Error()})
		return
	}

	existingPR, _, err := service.findOpenRemediationPR(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		service.log("warn", "failed to query existing remediation PR", map[string]interface{}{"owner": owner, "repo": repo, "error": err.Error()})
	}
	preferredBranch := ""
	if existingPR != nil {
		preferredBranch = existingPR.GetHead().GetRef()
	}

	result, err := service.runFixWorkflow(ctx, owner, repo, defaultBranch, token, FixCommand{}, preferredBranch)
	if err != nil {
		service.metrics.IncFix("failed")
		service.metrics.IncFailure("fix_workflow")
		service.log("error", "push remediation failed", map[string]interface{}{"owner": owner, "repo": repo, "error": err.Error()})
		return
	}
	if result.BlockedReason != "" {
		service.metrics.IncFix("blocked")
		service.log("warn", "push remediation blocked by safety policy", map[string]interface{}{"owner": owner, "repo": repo, "reason": result.BlockedReason, "risk_score": result.RiskScore})
		return
	}
	if !result.Changed {
		service.metrics.IncFix("nochange")
		service.log("info", "push remediation found no changes", map[string]interface{}{"owner": owner, "repo": repo, "exit_code": result.ExitCode})
		return
	}

	body := service.remediationPRBody(fmt.Sprintf("push to `%s`", defaultBranch), "automatic", result)
	pr, _, err := service.upsertRemediationPR(ctx, client, owner, repo, defaultBranch, result.Branch, body, existingPR)
	if err != nil {
		service.metrics.IncFix("failed")
		service.metrics.IncFailure("pr_upsert")
		service.log("error", "push remediation could not create PR", map[string]interface{}{"owner": owner, "repo": repo, "error": err.Error()})
		return
	}
	service.metrics.IncFix("changed")

	service.log("info", "push remediation PR ready", map[string]interface{}{"owner": owner, "repo": repo, "pr_url": pr.GetHTMLURL()})
}

func ownerFromRepository(repo *github.Repository) string {
	if repo == nil || repo.Owner == nil {
		return ""
	}
	owner := strings.TrimSpace(repo.GetOwner().GetLogin())
	if owner != "" {
		return owner
	}
	return strings.TrimSpace(repo.GetOwner().GetName())
}

func ownerFromPushRepository(repo *github.PushEventRepository) string {
	if repo == nil || repo.Owner == nil {
		return ""
	}
	owner := strings.TrimSpace(repo.GetOwner().GetLogin())
	if owner != "" {
		return owner
	}
	return strings.TrimSpace(repo.GetOwner().GetName())
}

func (service *Service) runFixWorkflow(ctx context.Context, owner, repo, defaultBranch, token string, command FixCommand, preferredBranch string) (fixRunResult, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return fixRunResult{}, fmt.Errorf("owner and repo must not be empty")
	}
	if strings.TrimSpace(defaultBranch) == "" {
		defaultBranch = "master"
	}

	tempRoot, err := os.MkdirTemp(service.cfg.WorkDir, "patchpilot-repo-")
	if err != nil {
		return fixRunResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempRoot)

	repoPath := filepath.Join(tempRoot, "repo")
	cloneURL, err := repositoryCloneURL(service.cfg.GitHubBaseWebURL, owner, repo, token)
	if err != nil {
		return fixRunResult{}, err
	}

	if _, _, err := runCommand(ctx, tempRoot, nil, "git", "clone", "--depth", "1", "--branch", defaultBranch, cloneURL, repoPath); err != nil {
		return fixRunResult{}, fmt.Errorf("clone repository: %w", err)
	}

	args := []string{"fix", "--dir", repoPath, "--enable-agent=false"}
	if strings.TrimSpace(command.PolicyPath) != "" {
		policyPath := command.PolicyPath
		if !filepath.IsAbs(policyPath) {
			policyPath = filepath.Join(repoPath, filepath.FromSlash(policyPath))
		}
		args = append(args, "--policy", policyPath)
	}

	stdout, stderr, runErr := runCommand(ctx, repoPath, nil, service.cfg.CVEFixBinary, args...)
	exitCode := commandExitCode(runErr)
	if runErr != nil && exitCode != 23 {
		return fixRunResult{}, fmt.Errorf("run cvefix (exit %d): %w\nstderr:\n%s", exitCode, runErr, truncateForComment(stderr))
	}

	changed, err := hasRepositoryChanges(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	if !changed {
		return fixRunResult{ExitCode: exitCode, Stdout: stdout, Stderr: stderr, Changed: false}, nil
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
	changedFiles, err := stagedChangedFiles(ctx, repoPath)
	if err != nil {
		return fixRunResult{}, err
	}
	safety, err := service.evaluateSafety(repoPath, changedFiles)
	if err != nil {
		return fixRunResult{}, fmt.Errorf("evaluate safety: %w", err)
	}
	if safety.Blocked {
		return fixRunResult{
			ExitCode:        exitCode,
			Stdout:          stdout,
			Stderr:          stderr,
			Changed:         false,
			Branch:          "",
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

	pushArgs := []string{"push", "origin", branch}
	if strings.TrimSpace(preferredBranch) != "" {
		pushArgs = []string{"push", "--force-with-lease", "origin", branch}
	}
	if _, _, err := runCommand(ctx, repoPath, nil, "git", pushArgs...); err != nil {
		return fixRunResult{}, fmt.Errorf("git push: %w", err)
	}

	return fixRunResult{
		ExitCode:        exitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		Changed:         true,
		Branch:          branch,
		RiskScore:       safety.RiskScore,
		ChangedFiles:    changedFiles,
		RegressionCount: safety.VerificationRegressions,
	}, nil
}

func (service *Service) postIssueComment(ctx context.Context, client *github.Client, owner, repo string, issueNumber int, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	err := service.withGitHubRetry(ctx, "create_issue_comment", func(callCtx context.Context) error {
		_, _, commentErr := client.Issues.CreateComment(callCtx, owner, repo, issueNumber, &github.IssueComment{Body: github.String(body)})
		return commentErr
	})
	if err != nil {
		service.log("error", "post issue comment failed", map[string]interface{}{"owner": owner, "repo": repo, "issue_number": issueNumber, "error": err.Error()})
	}
}

func runCommand(ctx context.Context, dir string, extraEnv map[string]string, name string, args ...string) (string, string, error) {
	if err := validateExecutableName(name); err != nil {
		return "", "", err
	}

	command := exec.CommandContext(ctx, name, args...) // #nosec G204,G702 -- command/args are controlled by internal callsites and validated executable names.
	command.Dir = dir

	if len(extraEnv) > 0 {
		env := os.Environ()
		for key, value := range extraEnv {
			env = append(env, key+"="+value)
		}
		command.Env = env
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer

	err := command.Run()
	return stdoutBuffer.String(), stderrBuffer.String(), err
}

func validateExecutableName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("command name cannot be empty")
	}
	if strings.ContainsAny(name, "\n\r\t") {
		return fmt.Errorf("command name contains invalid characters")
	}
	return nil
}

func hasRepositoryChanges(ctx context.Context, repoPath string) (bool, error) {
	stdout, _, err := runCommand(ctx, repoPath, nil, "git", "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("check git status: %w", err)
	}
	return strings.TrimSpace(stdout) != "", nil
}

func stagedChangedFiles(ctx context.Context, repoPath string) ([]string, error) {
	stdout, _, err := runCommand(ctx, repoPath, nil, "git", "diff", "--cached", "--name-only")
	if err != nil {
		return nil, fmt.Errorf("list changed files: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result, nil
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func truncateForComment(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "(empty)"
	}
	const max = 3500
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "\n... (truncated)"
}

func (service *Service) remediationPRBody(trigger, command string, result fixRunResult) string {
	return fmt.Sprintf(
		"Automated remediation generated by PatchPilot App.\n\n- Trigger: %s\n- Command: `%s`\n- cvefix exit code: `%d`\n- Risk score: `%d`\n- Changed files: `%d`\n\nStdout (truncated):\n```text\n%s\n```\n\nStderr (truncated):\n```text\n%s\n```",
		trigger,
		command,
		result.ExitCode,
		result.RiskScore,
		len(result.ChangedFiles),
		truncateForComment(result.Stdout),
		truncateForComment(result.Stderr),
	)
}

func (service *Service) findOpenRemediationPR(ctx context.Context, client *github.Client, owner, repo, baseBranch string) (*github.PullRequest, bool, error) {
	options := &github.PullRequestListOptions{
		State: "open",
		Base:  baseBranch,
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	var prs []*github.PullRequest
	err := service.withGitHubRetry(ctx, "list_pull_requests", func(callCtx context.Context) error {
		response, _, listErr := client.PullRequests.List(callCtx, owner, repo, options)
		if listErr != nil {
			return listErr
		}
		prs = response
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	for _, pr := range prs {
		if pr.GetTitle() != remediationPRTitle {
			continue
		}
		ref := pr.GetHead().GetRef()
		if strings.HasPrefix(ref, "patchpilot/auto-fix-") {
			return pr, true, nil
		}
	}
	return nil, false, nil
}

func (service *Service) upsertRemediationPR(ctx context.Context, client *github.Client, owner, repo, baseBranch, headBranch, body string, existing *github.PullRequest) (*github.PullRequest, bool, error) {
	if existing != nil {
		var updated *github.PullRequest
		err := service.withGitHubRetry(ctx, "edit_pull_request", func(callCtx context.Context) error {
			response, _, editErr := client.PullRequests.Edit(callCtx, owner, repo, existing.GetNumber(), &github.PullRequest{
				Title: github.String(remediationPRTitle),
				Body:  github.String(body),
			})
			if editErr != nil {
				return editErr
			}
			updated = response
			return nil
		})
		if err != nil {
			return nil, false, err
		}
		return updated, false, nil
	}
	var created *github.PullRequest
	err := service.withGitHubRetry(ctx, "create_pull_request", func(callCtx context.Context) error {
		response, _, createErr := client.PullRequests.Create(callCtx, owner, repo, &github.NewPullRequest{
			Title: github.String(remediationPRTitle),
			Head:  github.String(headBranch),
			Base:  github.String(baseBranch),
			Body:  github.String(body),
		})
		if createErr != nil {
			return createErr
		}
		created = response
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

func (service *Service) enablePRAutoMerge(ctx context.Context, installationToken, pullRequestNodeID string) error {
	if strings.TrimSpace(installationToken) == "" {
		return fmt.Errorf("installation token is empty")
	}
	if strings.TrimSpace(pullRequestNodeID) == "" {
		return fmt.Errorf("pull request node ID is empty")
	}

	graphqlURL, err := service.graphqlURL()
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"query": `mutation EnableAutoMerge($pullRequestId: ID!) { enablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId, mergeMethod: SQUASH}) { pullRequest { id } } }`,
		"variables": map[string]string{
			"pullRequestId": pullRequestNodeID,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal graphql payload: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create graphql request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+installationToken)
	request.Header.Set("Content-Type", "application/json")

	return service.withGitHubRetry(ctx, "enable_pr_auto_merge", func(callCtx context.Context) error {
		retryRequest := request.Clone(callCtx)
		retryRequest.Body = io.NopCloser(bytes.NewReader(data))
		response, reqErr := http.DefaultClient.Do(retryRequest)
		if reqErr != nil {
			return reqErr
		}
		defer response.Body.Close()

		if response.StatusCode < 300 {
			return nil
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return &httpStatusError{
			StatusCode: response.StatusCode,
			Header:     response.Header.Clone(),
			Body:       string(bodyBytes),
		}
	})
}

func (service *Service) graphqlURL() (string, error) {
	baseURL := strings.TrimSpace(service.cfg.GitHubAPIBaseURL)
	if baseURL == "" {
		return "https://api.github.com/graphql", nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse github api base URL: %w", err)
	}
	cleanPath := strings.TrimSuffix(parsed.Path, "/")
	cleanPath = strings.TrimSuffix(cleanPath, "/api/v3")
	parsed.Path = cleanPath + "/api/graphql"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
