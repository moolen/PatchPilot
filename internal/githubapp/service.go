package githubapp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v75/github"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/vuln"
	cron "github.com/robfig/cron/v3"
	"golang.org/x/oauth2"
)

type Service struct {
	cfg       Config
	logger    *log.Logger
	slog      *structuredLogger
	appClient *github.Client
	runtime   *AppRuntimeConfig
	runtimeMu sync.RWMutex
	metrics   *Metrics
	state     *schedulerStateStore
	jobRunner patchPilotJobRunner
}

type schedulerCycleOptions struct {
	ForceReconcile bool
}

type scanRunResult struct {
	ExitCode           int
	Stdout             string
	Stderr             string
	HasFindings        bool
	HeadSHA            string
	FindingCount       int
	FindingsBySeverity map[string]int
	Report             *vuln.Report
}

type repositoryCronSchedule struct {
	Schedule cron.Schedule
	Location *time.Location
	Spec     string
	Timezone string
	Key      string
}

const policyRequiredMissingScheduleKey = "repository-policy-required-missing"

func NewService(cfg Config, logger *log.Logger) (*Service, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "[patchpilot-app] ", log.LstdFlags)
	}
	if strings.TrimSpace(cfg.AuthMode) == "" {
		switch {
		case strings.TrimSpace(cfg.GitHubToken) != "":
			cfg.AuthMode = AuthModeToken
		default:
			cfg.AuthMode = AuthModeApp
		}
	}

	var appClient *github.Client
	var err error
	if cfg.AuthMode == AuthModeApp {
		appClient, err = newAppClient(cfg)
		if err != nil {
			return nil, err
		}
	}
	runtimeCfg, err := LoadAppRuntimeConfig(cfg.RuntimeConfigPath)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}
	state, err := newSchedulerStateStore(filepath.Join(cfg.WorkDir, "scheduler-state.json"))
	if err != nil {
		return nil, err
	}

	service := &Service{
		cfg:       cfg,
		logger:    logger,
		slog:      newStructuredLogger(logger),
		appClient: appClient,
		runtime:   runtimeCfg,
		metrics:   NewMetrics(),
		state:     state,
	}
	service.jobRunner, err = newPatchPilotJobRunner(cfg)
	if err != nil {
		return nil, err
	}
	service.refreshStateMetrics(time.Now().UTC())
	return service, nil
}

func (service *Service) Run(ctx context.Context) error {
	service.log("info", "scheduler started", map[string]interface{}{
		"tick":                     service.cfg.SchedulerTick.String(),
		"repo_run_timeout":         service.cfg.RepoRunTimeout.String(),
		"job_runner":               service.jobRunner.Description(),
		"force_reconcile_on_start": service.cfg.ForceReconcileOnStart,
	})

	service.runSchedulerCycleWithOptions(ctx, schedulerCycleOptions{ForceReconcile: service.cfg.ForceReconcileOnStart})
	service.startRuntimeConfigWatcher(ctx)

	ticker := time.NewTicker(service.cfg.SchedulerTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			service.log("info", "scheduler stopped", map[string]interface{}{"error": ctx.Err().Error()})
			return ctx.Err()
		case <-ticker.C:
			service.runSchedulerCycle(ctx)
		}
	}
}

func (service *Service) runSchedulerCycle(ctx context.Context) {
	service.runSchedulerCycleWithOptions(ctx, schedulerCycleOptions{})
}

func (service *Service) runSchedulerCycleWithOptions(ctx context.Context, options schedulerCycleOptions) {
	started := time.Now()
	status := "completed"
	if service.metrics != nil {
		service.metrics.IncSchedulerCycle("started")
	}
	defer func() {
		duration := time.Since(started)
		if service.metrics != nil {
			service.metrics.ObserveSchedulerCycleDuration(duration)
			service.metrics.IncSchedulerCycle(status)
			service.refreshStateMetrics(time.Now().UTC())
		}
	}()

	repositories, err := service.listRepositoryContexts(ctx)
	if err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("list_repositories")
			service.metrics.IncSchedulerRepositoryState("list_repositories_failed")
		}
		service.log("error", "list repositories failed", map[string]interface{}{"error": err.Error(), "auth_mode": service.cfg.AuthMode})
		status = "failed"
		return
	}

	service.log("info", "scheduler cycle started", map[string]interface{}{
		"repositories":    len(repositories),
		"auth_mode":       service.cfg.AuthMode,
		"force_reconcile": options.ForceReconcile,
	})

	now := time.Now().UTC()
	for _, repository := range repositories {
		if ctx.Err() != nil {
			status = "canceled"
			return
		}
		if service.metrics != nil {
			service.metrics.IncSchedulerRepositoryState("discovered")
		}
		service.runRepositoryCycleWithOptions(ctx, repository.Client, repository.Token, repository.Repository, now, options)
	}

	service.log("info", "scheduler cycle finished", map[string]interface{}{"repositories": len(repositories), "duration_ms": time.Since(started).Milliseconds()})
}

func (service *Service) runRepositoryCycleWithOptions(parentCtx context.Context, client *github.Client, token string, repository *github.Repository, now time.Time, options schedulerCycleOptions) {
	owner := ownerFromRepository(repository)
	repo := repository.GetName()
	defaultBranch := strings.TrimSpace(repository.GetDefaultBranch())
	repoKey := normalizeRepoName(repository.GetFullName())
	if repoKey == "" || owner == "" || repo == "" {
		service.log("warn", "skipping repository with incomplete metadata", map[string]interface{}{
			"full_name": repository.GetFullName(),
			"owner":     owner,
			"repo":      repo,
		})
		return
	}

	if err := service.reconcileTrackedPullRequest(parentCtx, client, owner, repo, repoKey, now); err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("pr_reconcile")
			service.metrics.IncRepositoryJob("pr_reconcile", "failed")
		}
		service.log("warn", "reconcile remediation PR failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": err.Error(),
		})
	}
	if handled, err := service.continueOpenRemediationPR(parentCtx, client, token, owner, repo, repoKey, now); err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("pr_continue")
			service.metrics.IncRepositoryJob("pr", "failed")
		}
		service.log("warn", "continue remediation PR failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": err.Error(),
		})
		return
	} else if handled {
		return
	}

	if len(service.cfg.RepositoryLabelSelectors) > 0 || len(service.cfg.RepositoryIgnoreLabelSelectors) > 0 {
		labels, err := service.repositoryLabels(parentCtx, client, owner, repo)
		if err != nil {
			if service.metrics != nil {
				service.metrics.IncFailure("repository_labels")
				service.metrics.IncSchedulerRepositoryState("repository_labels_failed")
			}
			service.log("error", "load repository labels failed", map[string]interface{}{
				"owner": owner,
				"repo":  repo,
				"error": err.Error(),
			})
			return
		}
		if repositoryMatchesLabelSelectors(labels, service.cfg.RepositoryIgnoreLabelSelectors) {
			if service.metrics != nil {
				service.metrics.IncSchedulerRepositoryState("label_ignored")
			}
			if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
				state.ScheduleKey = labelIgnoredScheduleKey
				state.NextRunAt = time.Time{}
			}, now); err != nil {
				service.log("warn", "persist ignored repository state failed", map[string]interface{}{
					"owner": owner,
					"repo":  repo,
					"error": err.Error(),
				})
			}
			service.log("info", "repository skipped by ignore label selector", map[string]interface{}{
				"owner":             owner,
				"repo":              repo,
				"repository_labels": labels,
				"ignore_labels":     service.cfg.RepositoryIgnoreLabelSelectors,
			})
			return
		}
		if len(service.cfg.RepositoryLabelSelectors) > 0 && !repositoryMatchesLabelSelectors(labels, service.cfg.RepositoryLabelSelectors) {
			if service.metrics != nil {
				service.metrics.IncSchedulerRepositoryState("label_filtered")
			}
			if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
				state.ScheduleKey = labelFilteredScheduleKey
				state.NextRunAt = time.Time{}
			}, now); err != nil {
				service.log("warn", "persist label-filtered repository state failed", map[string]interface{}{
					"owner": owner,
					"repo":  repo,
					"error": err.Error(),
				})
			}
			service.log("info", "repository skipped by label selector", map[string]interface{}{
				"owner":             owner,
				"repo":              repo,
				"repository_labels": labels,
				"required_labels":   service.cfg.RepositoryLabelSelectors,
			})
			return
		}
	}

	cfg, schedule, enabled, hasPolicyFile, err := service.loadRepositoryPolicy(parentCtx, client, owner, repo, defaultBranch)
	if err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("load_policy")
			service.metrics.IncSchedulerRepositoryState("load_policy_failed")
		}
		service.log("error", "load repository policy failed", map[string]interface{}{
			"owner":  owner,
			"repo":   repo,
			"error":  err.Error(),
			"branch": defaultBranch,
		})
		return
	}
	if service.cfg.RequirePolicyFile && !hasPolicyFile {
		if service.metrics != nil {
			service.metrics.IncSchedulerRepositoryState("policy_file_missing")
		}
		if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
			state.ScheduleKey = policyRequiredMissingScheduleKey
			state.NextRunAt = time.Time{}
		}, now); err != nil {
			service.log("warn", "persist policy-file-missing repository state failed", map[string]interface{}{
				"owner": owner,
				"repo":  repo,
				"error": err.Error(),
			})
		}
		service.log("info", "repository skipped because required policy file is missing", map[string]interface{}{
			"owner":       owner,
			"repo":        repo,
			"policy_file": policy.FileName,
		})
		return
	}
	if !enabled {
		if service.metrics != nil {
			service.metrics.IncSchedulerRepositoryState("disabled")
		}
		_ = service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
			state.ScheduleKey = policy.ScanCronDisabled
			state.NextRunAt = time.Time{}
		}, now)
		service.log("info", "scheduler disabled for repository", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
		})
		return
	}
	scheduledFor, due, err := service.claimRepositoryRun(repoKey, schedule, now, options.ForceReconcile)
	if err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("scheduler_state")
			service.metrics.IncSchedulerRepositoryState("scheduler_state_failed")
		}
		service.log("error", "update repository schedule state failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": err.Error(),
		})
		return
	}
	if !due {
		if service.metrics != nil {
			service.metrics.IncSchedulerRepositoryState("not_due")
		}
		return
	}
	if service.metrics != nil {
		service.metrics.IncSchedulerRepositoryState("due")
		service.metrics.IncSchedulerRepositoryState("processed")
		service.metrics.ObserveSchedulerRunLag(now.Sub(scheduledFor))
	}

	ctx, cancel := context.WithTimeout(parentCtx, service.cfg.RepoRunTimeout)
	defer cancel()

	service.log("info", "starting scheduled repository run", map[string]interface{}{
		"owner":          owner,
		"repo":           repo,
		"default_branch": defaultBranch,
		"cron":           schedule.Spec,
		"timezone":       schedule.Timezone,
		"scheduled_for":  scheduledFor.Format(time.RFC3339),
	})

	scanStarted := time.Now()
	if service.metrics != nil {
		service.metrics.IncRepositoryJobInFlight("scan")
	}
	scanResult, err := service.runScanWorkflow(ctx, owner, repo, repoKey, defaultBranch, token)
	if service.metrics != nil {
		service.metrics.DecRepositoryJobInFlight("scan")
		service.metrics.ObserveRepositoryJobDuration("scan", time.Since(scanStarted))
	}
	if err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("scan_workflow")
			service.metrics.IncSchedulerRepositoryState("scan_failed")
			service.metrics.IncRepositoryJob("scan", "failed")
		}
		service.log("error", "scheduled scan failed", map[string]interface{}{
			"owner":          owner,
			"repo":           repo,
			"default_branch": defaultBranch,
			"error":          err.Error(),
		})
		return
	}
	if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
		state.LastScanAt = now
		state.LastFindingCount = scanResult.FindingCount
		state.LastFindingsBySeverity = cloneSeverityCounts(scanResult.FindingsBySeverity)
	}, now); err != nil {
		service.log("warn", "persist scan findings failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": err.Error(),
		})
	}
	if !scanResult.HasFindings {
		if service.metrics != nil {
			service.metrics.IncSchedulerRepositoryState("no_findings")
			service.metrics.IncRepositoryJob("scan", "no_findings")
		}
		service.log("info", "scheduled scan found no fixable vulnerabilities", map[string]interface{}{
			"owner":     owner,
			"repo":      repo,
			"exit_code": scanResult.ExitCode,
			"head_sha":  scanResult.HeadSHA,
		})
		return
	}
	if service.metrics != nil {
		service.metrics.IncRepositoryJob("scan", "findings")
	}

	prStarted := time.Now()
	if service.metrics != nil {
		service.metrics.IncRepositoryJobInFlight("pr")
	}
	existingPR, _, err := service.findOpenRemediationPR(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		service.log("warn", "query existing remediation PR failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": err.Error(),
		})
	} else if existingPR != nil {
		meaningfulFiles, filesErr := service.pullRequestMeaningfulFiles(ctx, client, owner, repo, existingPR.GetNumber())
		if filesErr != nil {
			service.log("warn", "inspect remediation PR files failed", map[string]interface{}{
				"owner": owner,
				"repo":  repo,
				"pr":    existingPR.GetNumber(),
				"error": filesErr.Error(),
			})
			return
		}
		if len(meaningfulFiles) == 0 {
			service.log("warn", "closing remediation PR with only .patchpilot changes", map[string]interface{}{
				"owner": owner,
				"repo":  repo,
				"pr":    existingPR.GetNumber(),
			})
			if closeErr := service.closeArtifactOnlyRemediationPR(ctx, client, owner, repo, repoKey, existingPR, now); closeErr != nil {
				service.log("warn", "close artifact-only remediation PR failed", map[string]interface{}{
					"owner": owner,
					"repo":  repo,
					"pr":    existingPR.GetNumber(),
					"error": closeErr.Error(),
				})
				return
			}
			existingPR = nil
		} else if trackErr := service.trackOpenRemediationPR(repoKey, existingPR, now); trackErr != nil {
			service.log("warn", "track existing remediation PR failed", map[string]interface{}{
				"owner": owner,
				"repo":  repo,
				"error": trackErr.Error(),
			})
		}
	}
	preferredBranch := ""
	if existingPR != nil {
		preferredBranch = existingPR.GetHead().GetRef()
	}

	fixStarted := time.Now()
	if service.metrics != nil {
		service.metrics.IncRepositoryJobInFlight("fix")
	}
	result, err := service.runFixWorkflow(ctx, owner, repo, repoKey, defaultBranch, token, preferredBranch, cfg, scanResult)
	if service.metrics != nil {
		service.metrics.DecRepositoryJobInFlight("fix")
		service.metrics.ObserveRepositoryJobDuration("fix", time.Since(fixStarted))
	}
	if err != nil {
		if service.metrics != nil {
			service.metrics.IncFix("failed")
			service.metrics.IncFailure("fix_workflow")
			service.metrics.IncSchedulerRepositoryState("fix_failed")
			service.metrics.IncRepositoryJob("fix", "failed")
			service.metrics.DecRepositoryJobInFlight("pr")
			service.metrics.ObserveRepositoryJobDuration("pr", time.Since(prStarted))
			service.metrics.IncRepositoryJob("pr", "skipped")
		}
		service.log("error", "scheduled remediation failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": err.Error(),
		})
		return
	}
	if result.BlockedReason != "" {
		if service.metrics != nil {
			service.metrics.IncFix("blocked")
			service.metrics.IncSchedulerRepositoryState("blocked")
			service.metrics.IncRepositoryJob("fix", "blocked")
			service.metrics.ObserveFixChangedFiles(len(result.ChangedFiles))
			service.metrics.ObserveFixRiskScore(result.RiskScore)
			service.metrics.DecRepositoryJobInFlight("pr")
			service.metrics.ObserveRepositoryJobDuration("pr", time.Since(prStarted))
			service.metrics.IncRepositoryJob("pr", "skipped")
		}
		service.log("warn", "scheduled remediation blocked", map[string]interface{}{
			"owner":      owner,
			"repo":       repo,
			"reason":     result.BlockedReason,
			"risk_score": result.RiskScore,
		})
		return
	}
	if !result.Changed {
		if service.metrics != nil {
			service.metrics.IncFix("nochange")
			service.metrics.IncSchedulerRepositoryState("no_changes")
			service.metrics.IncRepositoryJob("fix", "no_changes")
			service.metrics.DecRepositoryJobInFlight("pr")
			service.metrics.ObserveRepositoryJobDuration("pr", time.Since(prStarted))
			service.metrics.IncRepositoryJob("pr", "skipped")
		}
		service.log("info", "scheduled remediation produced no repository changes", map[string]interface{}{
			"owner":     owner,
			"repo":      repo,
			"exit_code": result.ExitCode,
			"head_sha":  result.HeadSHA,
		})
		return
	}
	if service.metrics != nil {
		service.metrics.IncRepositoryJob("fix", "success")
		service.metrics.ObserveFixChangedFiles(len(result.ChangedFiles))
		service.metrics.ObserveFixRiskScore(result.RiskScore)
	}

	body := service.remediationPRBody(
		fmt.Sprintf("scheduled scan `%s` (%s)", schedule.Spec, schedule.Timezone),
		"automatic scheduled remediation",
		result,
	)
	pr, created, err := service.upsertRemediationPR(ctx, client, owner, repo, defaultBranch, result.Branch, body, existingPR)
	if err != nil {
		if service.metrics != nil {
			service.metrics.IncFix("failed")
			service.metrics.IncFailure("pr_upsert")
			service.metrics.IncSchedulerRepositoryState("pr_failed")
			service.metrics.DecRepositoryJobInFlight("pr")
			service.metrics.ObserveRepositoryJobDuration("pr", time.Since(prStarted))
			service.metrics.IncRepositoryJob("pr", "failed")
		}
		service.log("error", "scheduled remediation PR upsert failed", map[string]interface{}{
			"owner":  owner,
			"repo":   repo,
			"branch": result.Branch,
			"error":  err.Error(),
		})
		return
	}
	if trackErr := service.trackOpenRemediationPR(repoKey, pr, now); trackErr != nil {
		service.log("warn", "track remediation PR failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"error": trackErr.Error(),
		})
	}
	if err := service.manageRemediationPullRequest(ctx, client, token, owner, repo, repoKey, pr, now); err != nil {
		if service.metrics != nil {
			service.metrics.IncFailure("pr_manage")
			service.metrics.IncRepositoryJob("pr", "failed")
		}
		service.log("warn", "manage remediation PR failed", map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"pr":    pr.GetNumber(),
			"error": err.Error(),
		})
		return
	}
	if service.metrics != nil {
		service.metrics.IncFix("changed")
		service.metrics.DecRepositoryJobInFlight("pr")
		service.metrics.ObserveRepositoryJobDuration("pr", time.Since(prStarted))
	}

	if service.cfg.EnableAutoMerge {
		if err := service.enablePRAutoMerge(ctx, token, pr.GetNodeID()); err != nil {
			service.log("warn", "enable PR auto-merge failed", map[string]interface{}{
				"owner":  owner,
				"repo":   repo,
				"pr_url": pr.GetHTMLURL(),
				"error":  err.Error(),
			})
		}
	}

	action := "updated"
	if created {
		action = "opened"
	}
	if service.metrics != nil {
		state := "pr_updated"
		prOutcome := "updated"
		if created {
			state = "pr_created"
			prOutcome = "created"
		}
		service.metrics.IncSchedulerRepositoryState(state)
		service.metrics.IncRepositoryJob("pr", prOutcome)
	}
	service.log("info", "scheduled remediation PR ready", map[string]interface{}{
		"owner":         owner,
		"repo":          repo,
		"branch":        result.Branch,
		"action":        action,
		"pr_url":        pr.GetHTMLURL(),
		"changed_files": len(result.ChangedFiles),
		"risk_score":    result.RiskScore,
	})
}

func (service *Service) runScanWorkflow(ctx context.Context, owner, repo, repoKey, defaultBranch, token string) (scanRunResult, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return scanRunResult{}, fmt.Errorf("owner and repo must not be empty")
	}
	if strings.TrimSpace(defaultBranch) == "" {
		defaultBranch = "master"
	}

	tempRoot, err := os.MkdirTemp(service.cfg.WorkDir, "patchpilot-scan-")
	if err != nil {
		return scanRunResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempRoot)
	}()

	repoPath := filepath.Join(tempRoot, "repo")
	cloneURL, err := repositoryCloneURL(service.cfg.GitHubBaseWebURL, owner, repo, token)
	if err != nil {
		return scanRunResult{}, err
	}

	service.log("info", "cloning repository for scan", map[string]interface{}{
		"owner":  owner,
		"repo":   repo,
		"branch": defaultBranch,
	})
	if _, _, err := runCommand(ctx, tempRoot, nil, "git", "clone", "--depth", "1", "--branch", defaultBranch, cloneURL, repoPath); err != nil {
		return scanRunResult{}, fmt.Errorf("clone repository: %w", err)
	}
	headSHA, err := currentHeadSHA(ctx, repoPath)
	if err != nil {
		return scanRunResult{}, err
	}

	args := []string{"scan", "--dir", repoPath, "--untrusted-repo-policy", "--repository-key", repoKey}
	runtimeMappingPath, err := service.materializeRepositoryOCIMapping(repoPath, repoKey)
	if err != nil {
		return scanRunResult{}, err
	}
	if strings.TrimSpace(runtimeMappingPath) != "" {
		args = append(args, "--oci-mapping-file", runtimeMappingPath)
	}
	service.log("info", "running patchpilot scan", map[string]interface{}{
		"owner": owner,
		"repo":  repo,
		"args":  args,
	})
	stdout, stderr, runErr := service.jobRunner.Run(ctx, repoPath, args)
	exitCode := commandExitCode(runErr)
	service.log("info", "patchpilot scan finished", map[string]interface{}{
		"owner":          owner,
		"repo":           repo,
		"exit_code":      exitCode,
		"stdout_bytes":   len(stdout),
		"stderr_bytes":   len(stderr),
		"stdout_preview": previewLogText(stdout),
		"stderr_preview": previewLogText(stderr),
	})
	if runErr != nil && exitCode != 23 {
		return scanRunResult{}, fmt.Errorf("run PatchPilot scan (exit %d): %w\nstderr:\n%s", exitCode, runErr, truncateForComment(stderr))
	}

	findingsReport, err := vuln.ReadNormalized(repoPath)
	if err != nil {
		return scanRunResult{}, fmt.Errorf("read normalized scan findings: %w", err)
	}
	findingsBySeverity := countFindingsBySeverity(findingsReport)

	return scanRunResult{
		ExitCode:           exitCode,
		Stdout:             stdout,
		Stderr:             stderr,
		HasFindings:        len(findingsReport.Findings) > 0,
		HeadSHA:            headSHA,
		FindingCount:       len(findingsReport.Findings),
		FindingsBySeverity: findingsBySeverity,
		Report:             findingsReport,
	}, nil
}

func (service *Service) loadRepositoryPolicy(ctx context.Context, client *github.Client, owner, repo, defaultBranch string) (*policy.Config, *repositoryCronSchedule, bool, bool, error) {
	cfg := policy.Default()
	var content *github.RepositoryContent
	err := service.withGitHubRetry(ctx, "get_policy_file", func(callCtx context.Context) error {
		fileContent, _, _, getErr := client.Repositories.GetContents(callCtx, owner, repo, policy.FileName, &github.RepositoryContentGetOptions{
			Ref: defaultBranch,
		})
		if getErr != nil {
			return getErr
		}
		content = fileContent
		return nil
	})
	if err != nil {
		if isGitHubNotFound(err) {
			schedule, enabled, scheduleErr := buildRepositoryCronSchedule(cfg)
			return cfg, schedule, enabled, false, scheduleErr
		}
		return nil, nil, false, false, err
	}

	text, err := content.GetContent()
	if err != nil {
		return nil, nil, false, false, fmt.Errorf("decode %s: %w", policy.FileName, err)
	}
	cfg, err = policy.ParseYAMLWithOptions([]byte(text), policy.ParseOptions{UntrustedRepo: true})
	if err != nil {
		return nil, nil, false, true, err
	}
	schedule, enabled, err := buildRepositoryCronSchedule(cfg)
	if err != nil {
		return nil, nil, false, true, err
	}
	return cfg, schedule, enabled, true, nil
}

func (service *Service) claimRepositoryRun(repoKey string, schedule *repositoryCronSchedule, now time.Time, force bool) (time.Time, bool, error) {
	state := service.state.Get(repoKey)
	if force {
		nextRunAt := schedule.next(now)
		if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
			state.ScheduleKey = schedule.Key
			state.NextRunAt = nextRunAt.UTC()
		}, now); err != nil {
			return time.Time{}, false, err
		}
		return now, true, nil
	}
	if state.ScheduleKey != schedule.Key || state.NextRunAt.IsZero() {
		nextRunAt := schedule.next(now)
		if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
			state.ScheduleKey = schedule.Key
			state.NextRunAt = nextRunAt.UTC()
		}, now); err != nil {
			return time.Time{}, false, err
		}
		return now, true, nil
	}
	if now.Before(state.NextRunAt) {
		return state.NextRunAt, false, nil
	}
	nextRunAt := schedule.next(now)
	if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
		state.ScheduleKey = schedule.Key
		state.NextRunAt = nextRunAt.UTC()
	}, now); err != nil {
		return time.Time{}, false, err
	}
	return state.NextRunAt, true, nil
}

func (service *Service) listInstallations(ctx context.Context) ([]*github.Installation, error) {
	installations := make([]*github.Installation, 0)
	options := &github.ListOptions{PerPage: 100}
	for {
		var page []*github.Installation
		var response *github.Response
		err := service.withGitHubRetry(ctx, "list_installations", func(callCtx context.Context) error {
			var listErr error
			page, response, listErr = service.appClient.Apps.ListInstallations(callCtx, options)
			return listErr
		})
		if err != nil {
			return nil, err
		}
		installations = append(installations, page...)
		if response == nil || response.NextPage == 0 {
			return installations, nil
		}
		options.Page = response.NextPage
	}
}

func (service *Service) listInstallationRepos(ctx context.Context, client *github.Client) ([]*github.Repository, error) {
	repositories := make([]*github.Repository, 0)
	options := &github.ListOptions{PerPage: 100}
	for {
		var page *github.ListRepositories
		var response *github.Response
		err := service.withGitHubRetry(ctx, "list_installation_repositories", func(callCtx context.Context) error {
			var listErr error
			page, response, listErr = client.Apps.ListRepos(callCtx, options)
			return listErr
		})
		if err != nil {
			return nil, err
		}
		if page != nil {
			repositories = append(repositories, page.Repositories...)
		}
		if response == nil || response.NextPage == 0 {
			return repositories, nil
		}
		options.Page = response.NextPage
	}
}

func (service *Service) repositoryLabels(ctx context.Context, client *github.Client, owner, repo string) ([]string, error) {
	topics := make([]string, 0)
	err := service.withGitHubRetry(ctx, "list_repository_topics", func(callCtx context.Context) error {
		var listErr error
		topics, _, listErr = client.Repositories.ListAllTopics(callCtx, owner, repo)
		return listErr
	})
	if err != nil {
		return nil, fmt.Errorf("list repository topics: %w", err)
	}
	return normalizeRepositoryLabels(topics), nil
}

func (service *Service) installationClient(ctx context.Context, installationID int64) (*github.Client, string, error) {
	var tokenResp *github.InstallationToken
	err := service.withGitHubRetry(ctx, "create_installation_token", func(callCtx context.Context) error {
		response, _, tokenErr := service.appClient.Apps.CreateInstallationToken(callCtx, installationID, &github.InstallationTokenOptions{})
		if tokenErr != nil {
			return tokenErr
		}
		tokenResp = response
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("create installation token: %w", err)
	}
	token := tokenResp.GetToken()
	if strings.TrimSpace(token) == "" {
		return nil, "", fmt.Errorf("installation token is empty")
	}

	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	client := github.NewClient(httpClient)
	if service.cfg.GitHubAPIBaseURL != "" {
		client, err = client.WithEnterpriseURLs(service.cfg.GitHubAPIBaseURL, service.cfg.GitHubUploadAPIURL)
		if err != nil {
			return nil, "", fmt.Errorf("create enterprise github client: %w", err)
		}
	}
	return client, token, nil
}

func (service *Service) MetricsHandler(writer http.ResponseWriter, request *http.Request) {
	if service.metrics == nil {
		http.Error(writer, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	service.metrics.ServeHTTP(writer, request)
}

func (service *Service) updateRepositoryState(repoKey string, mutate func(*scheduledRepositoryState), now time.Time) error {
	if err := service.state.Update(repoKey, mutate); err != nil {
		return err
	}
	service.refreshStateMetrics(now)
	return nil
}

func (service *Service) refreshStateMetrics(now time.Time) {
	if service.metrics == nil || service.state == nil {
		return
	}
	service.metrics.RefreshState(service.state.Snapshot(), now)
}

func (service *Service) log(level, message string, fields map[string]interface{}) {
	if service.slog == nil {
		service.logger.Printf("%s: %s", strings.ToUpper(level), message)
		return
	}
	service.slog.Log(level, message, fields)
}

func normalizeRepoName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func loadPrivateKey(cfg Config) ([]byte, error) {
	if strings.TrimSpace(cfg.PrivateKeyPEM) != "" {
		text := strings.ReplaceAll(cfg.PrivateKeyPEM, `\n`, "\n")
		return []byte(text), nil
	}
	if strings.TrimSpace(cfg.PrivateKeyPath) == "" {
		return nil, fmt.Errorf("no private key configured")
	}
	data, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	return data, nil
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

func isGitHubNotFound(err error) bool {
	var responseErr *github.ErrorResponse
	if errors.As(err, &responseErr) {
		return statusCodeFromResponse(responseErr.Response) == http.StatusNotFound
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusNotFound
	}
	return false
}

func (service *Service) trackOpenRemediationPR(repoKey string, pr *github.PullRequest, now time.Time) error {
	if pr == nil {
		return nil
	}
	return service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
		createdAt := pr.GetCreatedAt().UTC()
		existing := state.OpenPR
		attempts := 0
		lastCIPollAt := time.Time{}
		lastCIConclusion := ""
		lastFailedChecks := []string(nil)
		lastAIAssessment := ""
		lastRerunAction := ""
		lastClosureComment := ""
		if existing != nil {
			attempts = existing.CIAttemptCount
			lastCIPollAt = existing.LastCIPollAt
			lastCIConclusion = existing.LastCIConclusion
			lastFailedChecks = append([]string(nil), existing.LastFailedChecks...)
			lastAIAssessment = existing.LastAIAssessment
			lastRerunAction = existing.LastRerunAction
			lastClosureComment = existing.LastClosureComment
		}
		state.OpenPR = &trackedRemediationPRState{
			Number:             pr.GetNumber(),
			URL:                pr.GetHTMLURL(),
			Branch:             pr.GetHead().GetRef(),
			HeadSHA:            pr.GetHead().GetSHA(),
			CreatedAt:          createdAt,
			LastSeenAt:         now.UTC(),
			CIAttemptCount:     attempts,
			LastCIPollAt:       lastCIPollAt,
			LastCIConclusion:   lastCIConclusion,
			LastFailedChecks:   lastFailedChecks,
			LastAIAssessment:   lastAIAssessment,
			LastRerunAction:    lastRerunAction,
			LastClosureComment: lastClosureComment,
		}
	}, now)
}

func (service *Service) reconcileTrackedPullRequest(ctx context.Context, client *github.Client, owner, repo, repoKey string, now time.Time) error {
	current := service.state.Get(repoKey)
	if current.OpenPR == nil || current.OpenPR.Number <= 0 {
		return nil
	}

	var pr *github.PullRequest
	err := service.withGitHubRetry(ctx, "get_pull_request", func(callCtx context.Context) error {
		var getErr error
		pr, _, getErr = client.PullRequests.Get(callCtx, owner, repo, current.OpenPR.Number)
		return getErr
	})
	if err != nil {
		if isGitHubNotFound(err) {
			return service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
				state.OpenPR = nil
			}, now)
		}
		return err
	}

	if pr.GetState() != "open" {
		if mergedAt := pr.GetMergedAt(); !mergedAt.IsZero() && current.OpenPR.CreatedAt.Unix() > 0 && service.metrics != nil {
			service.metrics.ObserveMergeLatency(mergedAt.Sub(current.OpenPR.CreatedAt))
		}
		return service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
			state.OpenPR = nil
		}, now)
	}

	return service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
		createdAt := pr.GetCreatedAt().UTC()
		existing := state.OpenPR
		attempts := 0
		lastCIPollAt := time.Time{}
		lastCIConclusion := ""
		lastFailedChecks := []string(nil)
		lastAIAssessment := ""
		lastRerunAction := ""
		lastClosureComment := ""
		if existing != nil {
			attempts = existing.CIAttemptCount
			lastCIPollAt = existing.LastCIPollAt
			lastCIConclusion = existing.LastCIConclusion
			lastFailedChecks = append([]string(nil), existing.LastFailedChecks...)
			lastAIAssessment = existing.LastAIAssessment
			lastRerunAction = existing.LastRerunAction
			lastClosureComment = existing.LastClosureComment
		}
		state.OpenPR = &trackedRemediationPRState{
			Number:             pr.GetNumber(),
			URL:                pr.GetHTMLURL(),
			Branch:             pr.GetHead().GetRef(),
			HeadSHA:            pr.GetHead().GetSHA(),
			CreatedAt:          createdAt,
			LastSeenAt:         now.UTC(),
			CIAttemptCount:     attempts,
			LastCIPollAt:       lastCIPollAt,
			LastCIConclusion:   lastCIConclusion,
			LastFailedChecks:   lastFailedChecks,
			LastAIAssessment:   lastAIAssessment,
			LastRerunAction:    lastRerunAction,
			LastClosureComment: lastClosureComment,
		}
	}, now)
}

func countFindingsBySeverity(report *vuln.Report) map[string]int {
	counts := map[string]int{}
	if report == nil {
		return counts
	}
	for _, finding := range report.Findings {
		severity := normalizeSeverityLabel(strings.ToLower(strings.TrimSpace(finding.Severity)))
		counts[severity]++
	}
	return counts
}

func cloneSeverityCounts(counts map[string]int) map[string]int {
	if len(counts) == 0 {
		return nil
	}
	cloned := make(map[string]int, len(counts))
	for severity, count := range counts {
		cloned[severity] = count
	}
	return cloned
}

func buildRepositoryCronSchedule(cfg *policy.Config) (*repositoryCronSchedule, bool, error) {
	if cfg == nil {
		cfg = policy.Default()
	}
	schedule, location, enabled, err := cfg.ResolveScanSchedule()
	if err != nil {
		return nil, false, err
	}
	if !enabled {
		return nil, false, nil
	}
	spec := strings.TrimSpace(cfg.Scan.Cron)
	if spec == "" {
		spec = policy.DefaultScanCron
	}
	timezone := strings.TrimSpace(cfg.Scan.Timezone)
	if timezone == "" {
		timezone = policy.DefaultScanTimezone
	}
	return &repositoryCronSchedule{
		Schedule: schedule,
		Location: location,
		Spec:     spec,
		Timezone: timezone,
		Key:      spec + "|" + timezone,
	}, true, nil
}

func (schedule *repositoryCronSchedule) next(now time.Time) time.Time {
	if schedule == nil || schedule.Schedule == nil || schedule.Location == nil {
		return time.Time{}
	}
	return schedule.Schedule.Next(now.In(schedule.Location)).UTC()
}
