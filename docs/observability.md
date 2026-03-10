# PatchPilot Observability

`patchpilot-app` exposes Prometheus metrics on `PP_METRICS_PATH` (default: `/metrics`) on the same HTTP listener as `/healthz`.

This document covers:

- how to scrape the service,
- which metrics are most useful for operations,
- the bundled Grafana dashboard and Prometheus alert rules,
- which thresholds you will likely want to tune for your deployment.

## Scraping

Minimal Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: patchpilot
    metrics_path: /metrics
    static_configs:
      - targets:
          - patchpilot-app.monitoring.svc.cluster.local:8080
```

If you change `PP_METRICS_PATH`, update `metrics_path` accordingly.

## Bundled Assets

- Grafana dashboard: `examples/observability/grafana-dashboard.json`
- Prometheus alert rules: `examples/observability/prometheus-rules.yaml`

The dashboard is aimed at the scheduler-first GitHub App model:

- Can one replica keep up with the repo set?
- Is GitHub API pressure slowing the worker down?
- Are findings accumulating faster than remediations are merged?

## Metric Groups

Scheduler health and backlog:

- `patchpilot_scheduler_cycles_total{status}`
- `patchpilot_scheduler_cycle_duration_seconds`
- `patchpilot_scheduler_due_repositories`
- `patchpilot_scheduler_oldest_due_age_seconds`
- `patchpilot_scheduler_run_lag_seconds`
- `patchpilot_scheduler_repositories_total{state}`

Repository processing throughput:

- `patchpilot_repository_jobs_total{phase,outcome}`
- `patchpilot_repository_job_duration_seconds{phase}`
- `patchpilot_repository_jobs_in_flight{phase}`
- `patchpilot_failures_total{stage}`
- `patchpilot_fixes_total{outcome}`

GitHub API pressure:

- `patchpilot_github_api_requests_total{operation,outcome}`
- `patchpilot_github_api_retries_total{operation}`
- `patchpilot_github_api_rate_limit_total{kind}`

Security posture and remediation latency:

- `patchpilot_fixable_findings_total`
- `patchpilot_fixable_findings_by_severity{severity}`
- `patchpilot_repositories_with_findings`
- `patchpilot_open_remediation_pull_requests`
- `patchpilot_oldest_open_remediation_pull_request_age_seconds`
- `patchpilot_remediation_time_to_merge_seconds`

Safety and remediation scope:

- `patchpilot_fix_changed_files`
- `patchpilot_fix_risk_score`

## What To Watch First

For a single replica, these are the most important leading indicators:

1. `patchpilot_scheduler_due_repositories`
   Rising values mean the worker is falling behind.
2. `patchpilot_scheduler_oldest_due_age_seconds`
   This shows real backlog age, not just queue size.
3. `patchpilot_scheduler_run_lag_seconds`
   Use p95. If it trends upward, scheduled scans are missing their intended windows.
4. `patchpilot_repository_job_duration_seconds{phase="scan"|"fix"|"pr"}`
   These tell you which phase is consuming the budget.
5. `patchpilot_github_api_rate_limit_total`
   If this moves, GitHub is part of your bottleneck.

Security-facing operators should watch:

1. `patchpilot_fixable_findings_by_severity{severity="critical"}`
2. `patchpilot_fixable_findings_total`
3. `patchpilot_open_remediation_pull_requests`
4. `patchpilot_oldest_open_remediation_pull_request_age_seconds`
5. `patchpilot_remediation_time_to_merge_seconds`

## Tuning The Bundled Alerts

The shipped alert rules are intentionally conservative, but they still need local tuning.

`PatchPilotSchedulerStalled`:

- Default lookback assumes the default `PP_SCHEDULER_TICK=1h`.
- Set the lookback to roughly `2x` your scheduler tick.

`PatchPilotSchedulerBacklog` and `PatchPilotSchedulerLagHigh`:

- Tune these relative to your repo count and expected scan duration.
- A small org might alert at `10` due repos; a large installation may need `100+`.

`PatchPilotOpenRemediationPRStuck`:

- Default threshold is 7 days.
- Tighten it if you expect same-day merges for critical repos.

`PatchPilotCriticalFindingsPresent`:

- This is intentionally simple.
- If you only want to alert on sustained exposure, increase the `for:` window.

## Suggested SLO Framing

If you want to formalize operations around this app, these are the cleanest initial SLOs:

- Scheduler freshness: p95 scheduled run lag stays below 30 minutes.
- Backlog control: oldest due repository stays below 2 hours.
- Security responsiveness: oldest open remediation PR stays below 7 days.
- Merge responsiveness: p95 remediation time to merge stays below 14 days.

## Runbook Hints

If `due_repositories` and `oldest_due_age_seconds` both rise:

- inspect `patchpilot_repository_job_duration_seconds` by phase,
- check for GitHub rate-limit alerts,
- verify whether the repo set grew faster than the current scan/fix budget.

If findings stay high but PRs stay low:

- inspect `patchpilot_fixes_total{outcome="blocked"|"nochange"|"failed"}`,
- check `patchpilot_failures_total{stage}`,
- inspect safety-related metrics like `patchpilot_fix_risk_score`.

If open PR age rises while findings remain stable:

- the bottleneck is probably review/merge flow, not scheduler throughput.
