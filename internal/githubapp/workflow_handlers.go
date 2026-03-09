package githubapp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v75/github"
)

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
		service.postCheckRun(ctx, client, owner, repo, result.HeadSHA, "neutral", "Remediation blocked", blockedRemediationSummary(result.BlockedReason, result.RiskScore))
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
		service.postCheckRun(ctx, client, owner, repo, result.HeadSHA, "neutral", "No remediation changes", noChangesRemediationSummary(result.ExitCode))
		service.postIssueComment(ctx, client, owner, repo, issueNumber, remediationNoChangesComment(result.ExitCode))
		return
	}

	body := service.remediationPRBody(
		fmt.Sprintf("issue comment by @%s", event.GetSender().GetLogin()),
		"/patchpilot fix",
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
	service.postCheckRun(ctx, client, owner, repo, result.HeadSHA, "success", "Remediation PR ready", fmt.Sprintf("PatchPilot %s a remediation PR. Changed files: %d. Risk score: %d.", action, len(result.ChangedFiles), result.RiskScore))
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
		service.postCheckRun(ctx, client, owner, repo, strings.TrimSpace(event.GetAfter()), "failure", "Remediation failed", truncateForComment(err.Error()))
		return
	}
	if result.BlockedReason != "" {
		service.metrics.IncFix("blocked")
		service.log("warn", "push remediation blocked by safety policy", map[string]interface{}{"owner": owner, "repo": repo, "reason": result.BlockedReason, "risk_score": result.RiskScore})
		service.postCheckRun(ctx, client, owner, repo, result.HeadSHA, "neutral", "Remediation blocked", blockedRemediationSummary(result.BlockedReason, result.RiskScore))
		return
	}
	if !result.Changed {
		service.metrics.IncFix("nochange")
		service.log("info", "push remediation found no changes", map[string]interface{}{"owner": owner, "repo": repo, "exit_code": result.ExitCode})
		service.postCheckRun(ctx, client, owner, repo, result.HeadSHA, "neutral", "No remediation changes", noChangesRemediationSummary(result.ExitCode))
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
	service.postCheckRun(ctx, client, owner, repo, result.HeadSHA, "success", "Remediation PR ready", fmt.Sprintf("PatchPilot prepared remediation changes on %d file(s) with risk score %d.", len(result.ChangedFiles), result.RiskScore))
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

func blockedRemediationSummary(reason string, riskScore int) string {
	return fmt.Sprintf("PatchPilot blocked remediation: %s (risk score=%d).", reason, riskScore)
}

func noChangesRemediationSummary(exitCode int) string {
	return fmt.Sprintf("PatchPilot exited with code %d and produced no repository changes.", exitCode)
}
