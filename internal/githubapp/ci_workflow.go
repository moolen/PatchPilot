package githubapp

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v75/github"
	agentpkg "github.com/moolen/patchpilot/internal/agent"
	"github.com/moolen/patchpilot/internal/policy"
)

const (
	ciConclusionPending = "pending"
	ciConclusionSuccess = "success"
	ciConclusionFailure = "failure"
)

type ciCheck struct {
	Name       string
	Kind       string
	Status     string
	Conclusion string
	DetailsURL string
	HTMLURL    string
	RunID      int64
	JobID      int64
}

type ciState struct {
	HeadSHA    string
	Overall    string
	Pending    []ciCheck
	Successful []ciCheck
	Failed     []ciCheck
}

type ciAssessment struct {
	Classification    string `json:"classification"`
	Summary           string `json:"summary"`
	RecommendedAction string `json:"recommended_action"`
}

type ciLogEvidence struct {
	RunID   int64  `json:"run_id"`
	JobID   int64  `json:"job_id"`
	Name    string `json:"name"`
	RunName string `json:"run_name"`
	Log     string `json:"log"`
}

func (service *Service) continueOpenRemediationPR(ctx context.Context, client *github.Client, token, owner, repo, repoKey string, now time.Time) (bool, error) {
	state := service.state.Get(repoKey)
	if state.OpenPR == nil || state.OpenPR.Number <= 0 {
		return false, nil
	}
	var pr *github.PullRequest
	err := service.withGitHubRetry(ctx, "get_pull_request", func(callCtx context.Context) error {
		var getErr error
		pr, _, getErr = client.PullRequests.Get(callCtx, owner, repo, state.OpenPR.Number)
		return getErr
	})
	if err != nil {
		if isGitHubNotFound(err) {
			return true, service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
				state.OpenPR = nil
			}, now)
		}
		return true, err
	}
	if pr.GetState() != "open" {
		return true, nil
	}
	meaningfulFiles, err := service.pullRequestMeaningfulFiles(ctx, client, owner, repo, pr.GetNumber())
	if err != nil {
		return true, err
	}
	if len(meaningfulFiles) == 0 {
		service.log("warn", "closing remediation PR with only .patchpilot changes", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"pr":    pr.GetNumber(),
		})
		if err := service.closeArtifactOnlyRemediationPR(ctx, client, owner, repo, repoKey, pr, now); err != nil {
			return true, err
		}
		return false, nil
	}
	return true, service.manageRemediationPullRequest(ctx, client, token, owner, repo, repoKey, pr, now)
}

func (service *Service) manageRemediationPullRequest(ctx context.Context, client *github.Client, token, owner, repo, repoKey string, pr *github.PullRequest, now time.Time) error {
	if pr == nil {
		return nil
	}
	maxAttempts := defaultMaxCIAttempts
	runtimeCfg := service.runtimeSnapshot()
	if runtimeCfg != nil && runtimeCfg.Remediation.MaxCIAttempts > 0 {
		maxAttempts = runtimeCfg.Remediation.MaxCIAttempts
	}
	for {
		state, err := service.fetchPullRequestCIState(ctx, client, owner, repo, pr)
		if err != nil {
			return err
		}
		failedNames := make([]string, 0, len(state.Failed))
		for _, failed := range state.Failed {
			failedNames = append(failedNames, failed.Name)
		}
		sort.Strings(failedNames)
		if err := service.updateRepositoryState(repoKey, func(current *scheduledRepositoryState) {
			if current.OpenPR == nil {
				current.OpenPR = &trackedRemediationPRState{}
			}
			current.OpenPR.Number = pr.GetNumber()
			current.OpenPR.URL = pr.GetHTMLURL()
			current.OpenPR.Branch = pr.GetHead().GetRef()
			current.OpenPR.HeadSHA = pr.GetHead().GetSHA()
			current.OpenPR.LastSeenAt = now.UTC()
			current.OpenPR.LastCIPollAt = time.Now().UTC()
			current.OpenPR.LastCIConclusion = state.Overall
			current.OpenPR.LastFailedChecks = failedNames
		}, now); err != nil {
			return err
		}

		switch state.Overall {
		case ciConclusionSuccess:
			return nil
		case ciConclusionPending:
			if err := sleepWithContext(ctx, service.cfg.PRStatusPollInterval); err != nil {
				return nil
			}
			continue
		default:
			current := service.state.Get(repoKey)
			attempt := 1
			if current.OpenPR != nil {
				attempt = current.OpenPR.CIAttemptCount + 1
			}
			assessment, evidence, err := service.assessPullRequestFailure(ctx, token, owner, repo, repoKey, pr, state, attempt)
			if err != nil {
				assessment = ciAssessment{
					Classification:    "insufficient_evidence",
					Summary:           err.Error(),
					RecommendedAction: "none",
				}
			}
			if err := service.updateRepositoryState(repoKey, func(current *scheduledRepositoryState) {
				if current.OpenPR == nil {
					current.OpenPR = &trackedRemediationPRState{}
				}
				current.OpenPR.CIAttemptCount = attempt
				current.OpenPR.LastAIAssessment = assessment.Classification + ": " + assessment.Summary
			}, now); err != nil {
				return err
			}
			switch assessment.Classification {
			case "known_flake":
				if err := service.rerunKnownFlake(ctx, client, owner, repo, evidence); err != nil {
					return err
				}
				if err := service.updateRepositoryState(repoKey, func(current *scheduledRepositoryState) {
					if current.OpenPR != nil {
						current.OpenPR.LastRerunAction = "rerun_failed_jobs"
					}
				}, now); err != nil {
					return err
				}
			case "related_patch":
				if err := service.repairPullRequestBranch(ctx, owner, repo, repoKey, token, pr.GetHead().GetRef(), evidence, assessment, attempt); err != nil {
					return err
				}
			}
			if attempt >= maxAttempts && assessment.Classification != "known_flake" && assessment.Classification != "related_patch" {
				return service.closeRemediationPullRequest(ctx, client, owner, repo, repoKey, pr, assessment, evidence, now)
			}
			if attempt >= maxAttempts {
				// One last poll after the last action. If it is still red, close it.
				if err := sleepWithContext(ctx, service.cfg.PRStatusPollInterval); err != nil {
					return nil
				}
				state, err := service.fetchPullRequestCIState(ctx, client, owner, repo, pr)
				if err != nil {
					return err
				}
				if state.Overall == ciConclusionSuccess {
					return nil
				}
				return service.closeRemediationPullRequest(ctx, client, owner, repo, repoKey, pr, assessment, evidence, now)
			}
			if err := sleepWithContext(ctx, service.cfg.PRStatusPollInterval); err != nil {
				return nil
			}
		}
	}
}

func (service *Service) fetchPullRequestCIState(ctx context.Context, client *github.Client, owner, repo string, pr *github.PullRequest) (ciState, error) {
	headSHA := pr.GetHead().GetSHA()
	result := ciState{HeadSHA: headSHA}
	if strings.TrimSpace(headSHA) == "" {
		return result, fmt.Errorf("pull request head sha is empty")
	}
	var checkResults *github.ListCheckRunsResults
	err := service.withGitHubRetry(ctx, "list_check_runs", func(callCtx context.Context) error {
		var listErr error
		checkResults, _, listErr = client.Checks.ListCheckRunsForRef(callCtx, owner, repo, headSHA, &github.ListCheckRunsOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		})
		return listErr
	})
	if err != nil {
		return result, err
	}
	for _, checkRun := range checkResults.CheckRuns {
		check := ciCheck{
			Name:       checkRun.GetName(),
			Kind:       "check_run",
			Status:     checkRun.GetStatus(),
			Conclusion: checkRun.GetConclusion(),
			DetailsURL: checkRun.GetDetailsURL(),
			HTMLURL:    checkRun.GetHTMLURL(),
		}
		switch classifyCheckOutcome(check.Status, check.Conclusion) {
		case ciConclusionSuccess:
			result.Successful = append(result.Successful, check)
		case ciConclusionPending:
			result.Pending = append(result.Pending, check)
		default:
			result.Failed = append(result.Failed, check)
		}
	}

	var combined *github.CombinedStatus
	err = service.withGitHubRetry(ctx, "get_combined_status", func(callCtx context.Context) error {
		var statusErr error
		combined, _, statusErr = client.Repositories.GetCombinedStatus(callCtx, owner, repo, headSHA, &github.ListOptions{PerPage: 100})
		return statusErr
	})
	if err != nil {
		return result, err
	}
	for _, status := range combined.Statuses {
		check := ciCheck{
			Name:       status.GetContext(),
			Kind:       "status",
			Status:     status.GetState(),
			Conclusion: status.GetState(),
			DetailsURL: status.GetTargetURL(),
		}
		switch classifyStatusOutcome(check.Status) {
		case ciConclusionSuccess:
			result.Successful = append(result.Successful, check)
		case ciConclusionPending:
			result.Pending = append(result.Pending, check)
		default:
			result.Failed = append(result.Failed, check)
		}
	}

	switch {
	case len(result.Failed) > 0:
		result.Overall = ciConclusionFailure
	case len(result.Pending) > 0:
		result.Overall = ciConclusionPending
	default:
		result.Overall = ciConclusionSuccess
	}
	return result, nil
}

func classifyCheckOutcome(status, conclusion string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	conclusion = strings.ToLower(strings.TrimSpace(conclusion))
	if status != "completed" {
		return ciConclusionPending
	}
	switch conclusion {
	case "success", "neutral", "skipped":
		return ciConclusionSuccess
	case "":
		return ciConclusionPending
	default:
		return ciConclusionFailure
	}
}

func classifyStatusOutcome(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "success":
		return ciConclusionSuccess
	case "pending":
		return ciConclusionPending
	default:
		return ciConclusionFailure
	}
}

func (service *Service) assessPullRequestFailure(ctx context.Context, token, owner, repo, repoKey string, pr *github.PullRequest, state ciState, attempt int) (ciAssessment, []ciLogEvidence, error) {
	evidence, _ := service.fetchFailedWorkflowEvidence(ctx, token, owner, repo, state.HeadSHA)
	payload := map[string]any{
		"repository":     repoKey,
		"pull_request":   pr.GetHTMLURL(),
		"branch":         pr.GetHead().GetRef(),
		"head_sha":       state.HeadSHA,
		"failed_checks":  state.Failed,
		"log_evidence":   evidence,
		"attempt_number": attempt,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return ciAssessment{}, evidence, err
	}
	runtimeCfg := service.runtimeSnapshot()
	ciAssessmentPrompts := []policy.AgentRemediationPromptPolicy(nil)
	if runtimeCfg != nil {
		ciAssessmentPrompts = runtimeCfg.Remediation.Prompts.CIFailureAssessment
	}
	responseText, err := service.runStructuredAgentAttempt(ctx, pr.GetHead().GetRef(), "ci-assessment", "github_app_ci_failure_assessment", "Classify the PR CI failure and respond with JSON only.", string(data), []string{
		"Do not modify repository files.",
		"Respond with JSON only.",
	}, []string{
		"Inspect failing checks and logs.",
		"Output JSON with classification, summary, and recommended_action.",
	}, ciAssessmentPrompts)
	if err != nil {
		return ciAssessment{}, evidence, err
	}
	var assessment ciAssessment
	if err := json.Unmarshal([]byte(responseText), &assessment); err != nil {
		return ciAssessment{}, evidence, fmt.Errorf("parse ci assessment JSON: %w", err)
	}
	assessment.Classification = strings.TrimSpace(assessment.Classification)
	assessment.RecommendedAction = strings.TrimSpace(assessment.RecommendedAction)
	assessment.Summary = strings.TrimSpace(assessment.Summary)
	if assessment.Classification == "" {
		assessment.Classification = "insufficient_evidence"
	}
	if assessment.RecommendedAction == "" {
		assessment.RecommendedAction = "none"
	}
	return assessment, evidence, nil
}

func (service *Service) fetchFailedWorkflowEvidence(ctx context.Context, token, owner, repo, headSHA string) ([]ciLogEvidence, error) {
	client, err := service.tokenClient(ctx, token)
	if err != nil {
		return nil, err
	}
	var runs *github.WorkflowRuns
	err = service.withGitHubRetry(ctx, "list_workflow_runs", func(callCtx context.Context) error {
		var listErr error
		runs, _, listErr = client.Actions.ListRepositoryWorkflowRuns(callCtx, owner, repo, &github.ListWorkflowRunsOptions{
			HeadSHA:     headSHA,
			ListOptions: github.ListOptions{PerPage: 50},
		})
		return listErr
	})
	if err != nil || runs == nil {
		return nil, err
	}
	result := make([]ciLogEvidence, 0)
	for _, run := range runs.WorkflowRuns {
		if classifyCheckOutcome(run.GetStatus(), run.GetConclusion()) != ciConclusionFailure {
			continue
		}
		var jobs *github.Jobs
		err := service.withGitHubRetry(ctx, "list_workflow_jobs", func(callCtx context.Context) error {
			var listErr error
			jobs, _, listErr = client.Actions.ListWorkflowJobs(callCtx, owner, repo, run.GetID(), &github.ListWorkflowJobsOptions{
				ListOptions: github.ListOptions{PerPage: 100},
			})
			return listErr
		})
		if err != nil || jobs == nil {
			continue
		}
		for _, job := range jobs.Jobs {
			if classifyCheckOutcome(job.GetStatus(), job.GetConclusion()) != ciConclusionFailure {
				continue
			}
			logText, _ := service.fetchWorkflowJobLog(ctx, token, owner, repo, job.GetID())
			result = append(result, ciLogEvidence{
				RunID:   run.GetID(),
				JobID:   job.GetID(),
				Name:    job.GetName(),
				RunName: run.GetName(),
				Log:     truncateForComment(logText),
			})
		}
	}
	return result, nil
}

func (service *Service) fetchWorkflowJobLog(ctx context.Context, token, owner, repo string, jobID int64) (string, error) {
	client, err := service.tokenClient(ctx, token)
	if err != nil {
		return "", err
	}
	var logURL *string
	err = service.withGitHubRetry(ctx, "get_workflow_job_logs", func(callCtx context.Context) error {
		url, _, getErr := client.Actions.GetWorkflowJobLogs(callCtx, owner, repo, jobID, 3)
		if getErr != nil {
			return getErr
		}
		if url != nil {
			value := url.String()
			logURL = &value
		}
		return nil
	})
	if err != nil || logURL == nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, *logURL, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token) != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if bytes.HasPrefix(data, []byte("PK")) {
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return "", err
		}
		var builder strings.Builder
		for _, file := range reader.File {
			handle, err := file.Open()
			if err != nil {
				continue
			}
			content, _ := io.ReadAll(io.LimitReader(handle, 2<<20))
			_ = handle.Close()
			if builder.Len() > 0 {
				builder.WriteString("\n\n")
			}
			builder.Write(content)
		}
		return builder.String(), nil
	}
	return string(data), nil
}

func (service *Service) rerunKnownFlake(ctx context.Context, client *github.Client, owner, repo string, evidence []ciLogEvidence) error {
	runIDs := map[int64]struct{}{}
	for _, item := range evidence {
		if item.RunID > 0 {
			runIDs[item.RunID] = struct{}{}
		}
	}
	if len(runIDs) == 0 {
		return fmt.Errorf("no rerunnable workflow runs associated with failed checks")
	}
	for runID := range runIDs {
		if err := service.withGitHubRetry(ctx, "rerun_failed_jobs", func(callCtx context.Context) error {
			_, rerunErr := client.Actions.RerunFailedJobsByID(callCtx, owner, repo, runID)
			return rerunErr
		}); err != nil {
			return err
		}
	}
	return nil
}

func (service *Service) repairPullRequestBranch(ctx context.Context, owner, repo, repoKey, token, branch string, evidence []ciLogEvidence, assessment ciAssessment, attempt int) error {
	tempRoot, err := os.MkdirTemp(service.cfg.WorkDir, "patchpilot-ci-repair-")
	if err != nil {
		return fmt.Errorf("create ci repair temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempRoot)
	}()
	repoPath := filepath.Join(tempRoot, "repo")
	cloneURL, err := repositoryCloneURL(service.cfg.GitHubBaseWebURL, owner, repo, token)
	if err != nil {
		return err
	}
	if _, _, err := runCommand(ctx, tempRoot, nil, "git", "clone", "--depth", "1", "--branch", branch, cloneURL, repoPath); err != nil {
		return fmt.Errorf("clone remediation branch: %w", err)
	}
	payload := map[string]any{
		"repository":     repoKey,
		"branch":         branch,
		"assessment":     assessment,
		"log_evidence":   evidence,
		"attempt_number": attempt,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := service.runAgentPatchAttempt(ctx, repoPath, fmt.Sprintf("ci-repair-%d", attempt), "github_app_ci_failure_repair", "Repair the open remediation PR so CI passes. Do not run validation commands.", string(data), []string{
		"Do not run build, test, or scan commands.",
		"Prefer minimal changes related to the observed CI failure.",
		"Do not modify .patchpilot artifacts or .patchpilot.yaml.",
	}, []string{
		"Inspect the failing CI evidence.",
		"Patch the repository branch only if the failure appears related to the remediation.",
		"Do not run validation commands.",
	}, func() []policy.AgentRemediationPromptPolicy {
		runtimeCfg := service.runtimeSnapshot()
		if runtimeCfg == nil {
			return nil
		}
		return runtimeCfg.Remediation.Prompts.CIFailureRepair
	}()); err != nil {
		return err
	}
	changed, err := hasRepositoryChanges(ctx, repoPath)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if _, _, err := runCommand(ctx, repoPath, nil, "git", "add", "-A"); err != nil {
		return fmt.Errorf("git add ci repair: %w", err)
	}
	if err := unstagePatchPilotArtifacts(ctx, repoPath); err != nil {
		return err
	}
	changedFiles, err := stagedChangedFiles(ctx, repoPath)
	if err != nil {
		return err
	}
	for _, changedFile := range changedFiles {
		if pathBlocked(changedFile, service.cfg.DisallowedPaths) {
			return fmt.Errorf("changed path %q is blocked by PP_DISALLOWED_PATHS", changedFile)
		}
	}
	commitEnv := map[string]string{
		"GIT_AUTHOR_NAME":     "patchpilot-app[bot]",
		"GIT_AUTHOR_EMAIL":    "patchpilot-app[bot]@users.noreply.github.com",
		"GIT_COMMITTER_NAME":  "patchpilot-app[bot]",
		"GIT_COMMITTER_EMAIL": "patchpilot-app[bot]@users.noreply.github.com",
	}
	message := fmt.Sprintf("fix: CI follow-up for remediation attempt %d", attempt)
	if _, _, err := runCommand(ctx, repoPath, commitEnv, "git", "commit", "-m", message); err != nil && !strings.Contains(err.Error(), "nothing to commit") {
		return fmt.Errorf("git commit ci repair: %w", err)
	}
	if _, _, err := runCommand(ctx, repoPath, nil, "git", "push", "origin", branch); err != nil {
		return fmt.Errorf("git push ci repair: %w", err)
	}
	return nil
}

func (service *Service) runStructuredAgentAttempt(ctx context.Context, branch, artifactSuffix, taskKind, goal, currentState string, constraints, validationPlan []string, remediationPrompts []policy.AgentRemediationPromptPolicy) (string, error) {
	tempRoot, err := os.MkdirTemp(service.cfg.WorkDir, "patchpilot-agent-")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = os.RemoveAll(tempRoot)
	}()
	artifactDir := filepath.Join(tempRoot, artifactSuffix)
	runner := agentpkg.Runner{
		Command: service.cfg.AgentCommand,
		Stdout:  os.Stderr,
		Stderr:  os.Stderr,
	}
	prompts := make([]agentpkg.RemediationPrompt, 0, len(remediationPrompts))
	for _, prompt := range remediationPrompts {
		prompts = append(prompts, agentpkg.RemediationPrompt{Mode: prompt.Mode, Template: prompt.Template})
	}
	if _, err := runner.RunAttempt(ctx, agentpkg.AttemptRequest{
		RepoPath:           tempRoot,
		AttemptNumber:      1,
		TaskKind:           taskKind,
		Goal:               goal,
		CurrentStateLabel:  "Current state",
		CurrentState:       currentState,
		Constraints:        constraints,
		ValidationPlan:     validationPlan,
		RemediationPrompts: prompts,
		WorkingDirectory:   tempRoot,
		PromptFilePath:     filepath.Join(artifactDir, "prompt.txt"),
	}); err != nil {
		return "", err
	}
	lastMessagePath := filepath.Join(artifactDir, "last-message.txt")
	data, err := os.ReadFile(lastMessagePath)
	if err != nil {
		return "", fmt.Errorf("read structured agent output: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
