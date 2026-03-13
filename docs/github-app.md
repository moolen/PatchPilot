# PatchPilot GitHub App

`patchpilot-app` runs as a scheduler-first GitHub automation worker. It can authenticate either as a GitHub App or with an explicit-allowlist GitHub token, and it runs scans/remediation automatically without webhook triggers or slash commands.

## How it works

1. PatchPilot resolves repositories from either GitHub App installations or the explicit token allowlist.
2. Each repository is scanned on its own cadence from `.patchpilot.yaml`.
3. When remediation is needed, PatchPilot opens a pull request with the proposed fix, waits on PR CI, and retries flaky or repairable failures up to the configured limit.

Per-repository cadence comes from `.patchpilot.yaml`:

```yaml
scan:
  cron: "0 0 * * *"
  timezone: UTC
```

- `scan.cron` defaults to `"0 0 * * *"` if omitted.
- `scan.timezone` defaults to `UTC` if omitted.
- Newly discovered repositories run once immediately, then continue on the configured cron schedule.
- Set `scan.cron: disabled` to opt a repository out of scheduled scans.

## GitHub App setup

Use these minimum GitHub App permissions:

- Repository permissions:
  - `Actions`: Read & write
  - `Checks`: Read-only
  - `Contents`: Read & write
  - `Issues`: Read & write
  - `Pull requests`: Read & write
  - `Statuses`: Read-only
  - `Metadata`: Read-only

Install the app on the repositories you want PatchPilot to manage. Installed repositories are discovered automatically.

For gradual rollout, PatchPilot can gate scheduled work on repository topics. GitHub does not have first-class repository labels, so PatchPilot treats repository topics as rollout labels.

## Configuration

`patchpilot-app run` exposes most non-secret runtime settings as CLI flags.

- Precedence: `CLI flag > environment variable > default`.
- Secrets remain environment-only: `PP_GITHUB_TOKEN` and `PP_PRIVATE_KEY_PEM`.
- Run `./bin/patchpilot-app run --help` for the full flag list.

Common `run` flags:

- `--github-auth-mode` (`PP_GITHUB_AUTH_MODE`)
- `--app-id` (`PP_APP_ID`)
- `--private-key-path` (`PP_PRIVATE_KEY_PATH`)
- `--github-token-repositories` (`PP_GITHUB_TOKEN_REPOSITORIES`)
- `--runtime-config-file` (`PP_GITHUB_APP_CONFIG_FILE`)
- `--workdir` (`PP_WORKDIR`)
- `--patchpilot-binary` (`PP_PATCHPILOT_BINARY`)
- `--patchpilot-policy` (`PP_PATCHPILOT_POLICY`)
- `--patchpilot-policy-mode` (`PP_PATCHPILOT_POLICY_MODE`)
- `--agent-command` (`PP_AGENT_COMMAND`)
- `--job-runner`, `--job-container-runtime`, `--job-container-image`, `--job-container-binary`, `--job-container-network`
- `--listen-addr`, `--metrics-path`
- `--enable-auto-merge`
- `--force-reconcile-on-start`
- `--disallowed-paths`
- `--repository-label-selector`, `--repository-ignore-label-selector`
- `--scheduler-tick`, `--repo-run-timeout`, `--pr-status-poll-interval`
- `--github-retry-max-attempts`, `--github-retry-initial-backoff`, `--github-retry-max-backoff`
- `--github-web-base-url`, `--github-api-base-url`, `--github-upload-api-url`

## Environment Variables

Required:

- GitHub App mode:
  - `PP_APP_ID`
  - `PP_PRIVATE_KEY_PATH` or `PP_PRIVATE_KEY_PEM`
- Token mode:
  - `PP_GITHUB_AUTH_MODE=token`
  - `PP_GITHUB_TOKEN`
  - `PP_GITHUB_TOKEN_REPOSITORIES`

Common optional settings:

- `PP_GITHUB_AUTH_MODE`: `app`, `token`, or `auto`. Defaults to `auto`.
- `PP_GITHUB_APP_CONFIG_FILE` or `PP_OCI_MAPPING_FILE`: operator-managed YAML file for external OCI mappings (`oci.mappings`) and optional app remediation settings.
- `PP_WORKDIR`: temporary working directory root.
- `PP_PATCHPILOT_BINARY`: path to the PatchPilot binary.
- `PP_PATCHPILOT_POLICY`: optional central PatchPilot policy file path passed to all `scan`/`fix` invocations as `--policy`.
- `PP_PATCHPILOT_POLICY_MODE`: optional central policy layering mode passed to all `scan`/`fix` invocations as `--policy-mode` (`merge` or `override`). Defaults to `merge`.
- `PP_AGENT_COMMAND`: external agent command used for container OS patching and CI failure triage/repair.
- `PP_JOB_RUNNER`: `local` or `container`. Defaults to `local`.
- `PP_JOB_CONTAINER_RUNTIME`: container runtime for repo jobs when `PP_JOB_RUNNER=container`. Defaults to `docker`.
- `PP_JOB_CONTAINER_IMAGE`: container image that contains `patchpilot`, `syft`, `grype`, language toolchains, and package managers needed for remediation, including `cargo` for Rust/Cargo repositories.
- `PP_JOB_CONTAINER_BINARY`: PatchPilot binary path inside the job container. Defaults to `patchpilot`.
- `PP_JOB_CONTAINER_NETWORK`: container network mode for repo jobs. Defaults to `bridge`.
- `PP_GITHUB_WEB_BASE_URL`: GitHub web base URL for clone links. Defaults to `https://github.com`.
- `PP_GITHUB_API_BASE_URL` and `PP_GITHUB_UPLOAD_API_URL`: set both for GitHub Enterprise.
- `PP_ENABLE_AUTO_MERGE`: allow auto-merge enablement when PatchPilot requests it.
- `PP_DISALLOWED_PATHS`: block PR creation for matching changed paths.
- `PP_REPOSITORY_LABEL_SELECTOR`: comma-separated repository topic selectors for opt-in rollout. If set, a repository must match at least one selector before PatchPilot will scan it. Wildcards such as `patchpilot-*` are supported.
- `PP_REPOSITORY_IGNORE_LABEL_SELECTOR`: comma-separated repository topic selectors that force PatchPilot to skip a repository even if it matches the opt-in selector.
- `PP_LISTEN_ADDR`: HTTP listen address if you expose health/metrics endpoints.
- `PP_METRICS_PATH`: metrics endpoint path. Defaults to `/metrics`.
- `PP_FORCE_RECONCILE_ON_START`: force one immediate repository reconciliation cycle on process start, even when persisted scheduler state says a repository is not due yet.
- `PP_PR_STATUS_POLL_INTERVAL`: polling interval while waiting on PR CI. Defaults to `30s`.
- `PP_GITHUB_RETRY_MAX_ATTEMPTS`, `PP_GITHUB_RETRY_INITIAL_BACKOFF`, `PP_GITHUB_RETRY_MAX_BACKOFF`: GitHub API retry controls.

Operator-managed app config example:

```yaml
oci:
  mappings:
    - repo: acme/demo
      images:
        - source: ghcr.io/acme/demo
          dockerfiles:
            - Dockerfile
          tag: latest-semver
remediation:
  max_ci_attempts: 3
  prompts:
    ci_failure_assessment:
      - mode: extend
        template: |
          Return JSON only.
```

`patchpilot-app` watches this file and hot-reloads it. Invalid updates are logged and ignored, and the last valid configuration remains active.

Example gradual rollout:

```bash
PP_REPOSITORY_LABEL_SELECTOR=patchpilot,opt-in-security \
PP_REPOSITORY_IGNORE_LABEL_SELECTOR=patchpilot-ignore \
./bin/patchpilot-app
```

- Add a matching topic such as `patchpilot` to let engineers opt a repository in.
- Add an ignore topic such as `patchpilot-ignore` to force that repository out of scope.
- Ignore selectors win over opt-in selectors.

## Run

```bash
make build
./bin/patchpilot-app run \
  --app-id 123 \
  --private-key-path ./private-key.pem
```

Token mode example (token stays env-only):

```bash
PP_GITHUB_TOKEN=ghp_xxx \
./bin/patchpilot-app run \
  --github-auth-mode token \
  --github-token-repositories acme/service,acme/api
```

Require an in-repo policy file before the scheduler will process a repository:

```bash
PP_APP_ID=123 \
PP_PRIVATE_KEY_PATH=./private-key.pem \
./bin/patchpilot-app run --require-policy-file
```

With `--require-policy-file`, repositories that do not contain `.patchpilot.yaml` are skipped entirely instead of inheriting the default scan schedule.

Force one immediate reconcile pass on startup:

```bash
PP_APP_ID=123 \
PP_PRIVATE_KEY_PATH=./private-key.pem \
./bin/patchpilot-app run --force-reconcile-on-start
```

This bypasses only the persisted `NextRunAt` gate for the initial startup cycle. Policy loading, topic selectors, and `scan.cron: disabled` still apply.

Container image:

```bash
docker build -f Dockerfile.patchpilot-app -t patchpilot-app:dev .
docker run --rm \
  -p 8080:8080 \
  -e PP_APP_ID=123 \
  -e PP_PRIVATE_KEY_PATH=/run/secrets/patchpilot.pem \
  -v "$PWD/private-key.pem:/run/secrets/patchpilot.pem:ro" \
  patchpilot-app:dev
```

Published releases push a multi-arch image to `ghcr.io/<owner>/patchpilot-app`.
Mount access to a Docker-compatible daemon or socket because the app also pulls and scans mapped OCI images during scheduled runs.

Run environment diagnostics:

```bash
./bin/patchpilot-app doctor
```

## Observability

`patchpilot-app` exposes Prometheus metrics on `PP_METRICS_PATH` (default: `/metrics`) on the same listener as `/healthz`.

Bundled observability assets:

- Dashboard guide: `docs/observability.md`
- Grafana dashboard: `examples/observability/grafana-dashboard.json`
- Prometheus alert rules: `examples/observability/prometheus-rules.yaml`

The most important scheduler-capacity metrics for a single replica are:

- `patchpilot_scheduler_due_repositories`
- `patchpilot_scheduler_oldest_due_age_seconds`
- `patchpilot_scheduler_run_lag_seconds`
- `patchpilot_repository_job_duration_seconds`
- `patchpilot_github_api_rate_limit_total`

Security note:

- In GitHub App mode, repo-local `.patchpilot.yaml` is treated as untrusted input.
- Repo-local `pre_execution`, `verification`, and `post_execution` are no longer supported policy keys and are dropped during policy migration.
- Repo-local `registry`, `artifacts`, and `agent` sections are ignored in app mode.
- OCI image mappings and remediation prompt overrides come from the operator-managed app config file, not from repo-local policy.
- This prevents repository owners from using policy to execute arbitrary host commands or read operator-managed environment secrets.
- For stronger isolation, set `PP_JOB_RUNNER=container` so `scan` and `fix` run inside a short-lived container with a read-only root filesystem, dropped capabilities, and only the cloned repository mounted in.

## Manifest note

`./bin/patchpilot-app manifest` prints a starter GitHub App manifest. GitHub’s app setup still exposes webhook configuration fields, but scheduler-first PatchPilot does not depend on inbound webhook delivery at runtime.
