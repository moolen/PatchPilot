package githubapp

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var knownSeverityLabels = []string{"critical", "high", "medium", "low", "negligible", "unknown"}

type Metrics struct {
	registry *prometheus.Registry
	handler  http.Handler

	schedulerCyclesTotal       *prometheus.CounterVec
	schedulerCycleDuration     prometheus.Histogram
	schedulerRepositoriesTotal *prometheus.CounterVec
	schedulerDueRepositories   prometheus.Gauge
	schedulerOldestDueAge      prometheus.Gauge
	schedulerRunLag            prometheus.Histogram

	fixesTotal    *prometheus.CounterVec
	failuresTotal *prometheus.CounterVec

	repositoryJobsTotal    *prometheus.CounterVec
	repositoryJobDuration  *prometheus.HistogramVec
	repositoryJobsInFlight *prometheus.GaugeVec

	githubAPIRequestsTotal  *prometheus.CounterVec
	githubAPIRetriesTotal   *prometheus.CounterVec
	githubAPIRateLimitTotal *prometheus.CounterVec

	fixChangedFiles prometheus.Histogram
	fixRiskScore    prometheus.Histogram

	fixableFindingsTotal      prometheus.Gauge
	fixableFindingsBySeverity *prometheus.GaugeVec
	repositoriesWithFindings  prometheus.Gauge

	openRemediationPRs     prometheus.Gauge
	oldestOpenPRAgeSeconds prometheus.Gauge
	remediationTimeToMerge prometheus.Histogram
}

func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		registry: registry,
		schedulerCyclesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_scheduler_cycles_total",
			Help: "Total scheduler cycles by terminal status.",
		}, []string{"status"}),
		schedulerCycleDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "patchpilot_scheduler_cycle_duration_seconds",
			Help:    "Duration of scheduler cycles in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		schedulerRepositoriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_scheduler_repositories_total",
			Help: "Repositories observed by the scheduler, partitioned by state transitions.",
		}, []string{"state"}),
		schedulerDueRepositories: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "patchpilot_scheduler_due_repositories",
			Help: "Number of repositories currently due for processing based on persisted schedule state.",
		}),
		schedulerOldestDueAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "patchpilot_scheduler_oldest_due_age_seconds",
			Help: "Age in seconds of the oldest due repository based on persisted schedule state.",
		}),
		schedulerRunLag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "patchpilot_scheduler_run_lag_seconds",
			Help:    "Delay between a repository's scheduled execution time and when processing actually starts.",
			Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600, 21600, 86400},
		}),
		fixesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_fixes_total",
			Help: "Total remediation outcomes.",
		}, []string{"outcome"}),
		failuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_failures_total",
			Help: "Total remediation failures grouped by stage.",
		}, []string{"stage"}),
		repositoryJobsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_repository_jobs_total",
			Help: "Repository job outcomes grouped by phase and outcome.",
		}, []string{"phase", "outcome"}),
		repositoryJobDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "patchpilot_repository_job_duration_seconds",
			Help:    "Duration of repository job phases in seconds.",
			Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200, 1800},
		}, []string{"phase"}),
		repositoryJobsInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "patchpilot_repository_jobs_in_flight",
			Help: "Repository jobs currently in flight by phase.",
		}, []string{"phase"}),
		githubAPIRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_github_api_requests_total",
			Help: "GitHub API request attempts by operation and outcome.",
		}, []string{"operation", "outcome"}),
		githubAPIRetriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_github_api_retries_total",
			Help: "GitHub API retries by operation.",
		}, []string{"operation"}),
		githubAPIRateLimitTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "patchpilot_github_api_rate_limit_total",
			Help: "GitHub API rate-limit related retry events by kind.",
		}, []string{"kind"}),
		fixChangedFiles: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "patchpilot_fix_changed_files",
			Help:    "Number of changed files in remediation runs.",
			Buckets: []float64{0, 1, 2, 5, 10, 20, 50, 100, 250},
		}),
		fixRiskScore: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "patchpilot_fix_risk_score",
			Help:    "Observed remediation risk scores.",
			Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 1000, 5000, 10000, 25000, 50000},
		}),
		fixableFindingsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "patchpilot_fixable_findings_total",
			Help: "Total fixable findings from the latest successful scan state across repositories.",
		}),
		fixableFindingsBySeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "patchpilot_fixable_findings_by_severity",
			Help: "Total fixable findings from the latest successful scan state grouped by severity.",
		}, []string{"severity"}),
		repositoriesWithFindings: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "patchpilot_repositories_with_findings",
			Help: "Repositories whose latest successful scan still has fixable findings.",
		}),
		openRemediationPRs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "patchpilot_open_remediation_pull_requests",
			Help: "Open remediation pull requests currently tracked by the scheduler.",
		}),
		oldestOpenPRAgeSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "patchpilot_oldest_open_remediation_pull_request_age_seconds",
			Help: "Age in seconds of the oldest tracked open remediation pull request.",
		}),
		remediationTimeToMerge: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "patchpilot_remediation_time_to_merge_seconds",
			Help:    "Time from remediation pull request creation to merge.",
			Buckets: []float64{60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 604800, 1209600, 2592000},
		}),
	}

	registry.MustRegister(
		metrics.schedulerCyclesTotal,
		metrics.schedulerCycleDuration,
		metrics.schedulerRepositoriesTotal,
		metrics.schedulerDueRepositories,
		metrics.schedulerOldestDueAge,
		metrics.schedulerRunLag,
		metrics.fixesTotal,
		metrics.failuresTotal,
		metrics.repositoryJobsTotal,
		metrics.repositoryJobDuration,
		metrics.repositoryJobsInFlight,
		metrics.githubAPIRequestsTotal,
		metrics.githubAPIRetriesTotal,
		metrics.githubAPIRateLimitTotal,
		metrics.fixChangedFiles,
		metrics.fixRiskScore,
		metrics.fixableFindingsTotal,
		metrics.fixableFindingsBySeverity,
		metrics.repositoriesWithFindings,
		metrics.openRemediationPRs,
		metrics.oldestOpenPRAgeSeconds,
		metrics.remediationTimeToMerge,
	)

	for _, severity := range knownSeverityLabels {
		metrics.fixableFindingsBySeverity.WithLabelValues(severity).Set(0)
	}

	metrics.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return metrics
}

func (metrics *Metrics) IncSchedulerCycle(status string) {
	metrics.schedulerCyclesTotal.WithLabelValues(status).Inc()
}

func (metrics *Metrics) ObserveSchedulerCycleDuration(duration time.Duration) {
	metrics.schedulerCycleDuration.Observe(duration.Seconds())
}

func (metrics *Metrics) IncSchedulerRepositoryState(state string) {
	metrics.schedulerRepositoriesTotal.WithLabelValues(state).Inc()
}

func (metrics *Metrics) ObserveSchedulerRunLag(duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	metrics.schedulerRunLag.Observe(duration.Seconds())
}

func (metrics *Metrics) IncFix(outcome string) {
	metrics.fixesTotal.WithLabelValues(outcome).Inc()
}

func (metrics *Metrics) IncFailure(stage string) {
	metrics.failuresTotal.WithLabelValues(stage).Inc()
}

func (metrics *Metrics) IncRepositoryJob(phase, outcome string) {
	metrics.repositoryJobsTotal.WithLabelValues(phase, outcome).Inc()
}

func (metrics *Metrics) ObserveRepositoryJobDuration(phase string, duration time.Duration) {
	metrics.repositoryJobDuration.WithLabelValues(phase).Observe(duration.Seconds())
}

func (metrics *Metrics) IncRepositoryJobInFlight(phase string) {
	metrics.repositoryJobsInFlight.WithLabelValues(phase).Inc()
}

func (metrics *Metrics) DecRepositoryJobInFlight(phase string) {
	metrics.repositoryJobsInFlight.WithLabelValues(phase).Dec()
}

func (metrics *Metrics) ObserveGitHubRequest(operation, outcome string) {
	metrics.githubAPIRequestsTotal.WithLabelValues(operation, outcome).Inc()
}

func (metrics *Metrics) IncGitHubRetry(operation string) {
	metrics.githubAPIRetriesTotal.WithLabelValues(operation).Inc()
}

func (metrics *Metrics) IncGitHubRateLimit(kind string) {
	metrics.githubAPIRateLimitTotal.WithLabelValues(kind).Inc()
}

func (metrics *Metrics) ObserveFixChangedFiles(count int) {
	if count < 0 {
		count = 0
	}
	metrics.fixChangedFiles.Observe(float64(count))
}

func (metrics *Metrics) ObserveFixRiskScore(score int) {
	if score < 0 {
		score = 0
	}
	metrics.fixRiskScore.Observe(float64(score))
}

func (metrics *Metrics) ObserveMergeLatency(duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	metrics.remediationTimeToMerge.Observe(duration.Seconds())
}

func (metrics *Metrics) RefreshState(snapshot map[string]scheduledRepositoryState, now time.Time) {
	dueRepositories := 0
	oldestDueAge := 0.0
	findingsTotal := 0
	repositoriesWithFindings := 0
	openPRs := 0
	oldestOpenPRAge := 0.0

	severityCounts := make(map[string]int, len(knownSeverityLabels))
	for _, severity := range knownSeverityLabels {
		severityCounts[severity] = 0
	}

	for _, state := range snapshot {
		if !state.NextRunAt.IsZero() && !now.Before(state.NextRunAt) {
			dueRepositories++
			age := now.Sub(state.NextRunAt).Seconds()
			if age > oldestDueAge {
				oldestDueAge = age
			}
		}

		findingsTotal += state.LastFindingCount
		if state.LastFindingCount > 0 {
			repositoriesWithFindings++
		}
		for severity, count := range state.LastFindingsBySeverity {
			severityCounts[normalizeSeverityLabel(severity)] += count
		}

		if state.OpenPR != nil {
			openPRs++
			if !state.OpenPR.CreatedAt.IsZero() {
				age := now.Sub(state.OpenPR.CreatedAt).Seconds()
				if age > oldestOpenPRAge {
					oldestOpenPRAge = age
				}
			}
		}
	}

	metrics.schedulerDueRepositories.Set(float64(dueRepositories))
	metrics.schedulerOldestDueAge.Set(oldestDueAge)
	metrics.fixableFindingsTotal.Set(float64(findingsTotal))
	metrics.repositoriesWithFindings.Set(float64(repositoriesWithFindings))
	metrics.openRemediationPRs.Set(float64(openPRs))
	metrics.oldestOpenPRAgeSeconds.Set(oldestOpenPRAge)
	for _, severity := range knownSeverityLabels {
		metrics.fixableFindingsBySeverity.WithLabelValues(severity).Set(float64(severityCounts[severity]))
	}
}

func (metrics *Metrics) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	metrics.handler.ServeHTTP(writer, request)
}

func normalizeSeverityLabel(value string) string {
	switch value {
	case "critical", "high", "medium", "low", "negligible":
		return value
	default:
		return "unknown"
	}
}
