# PatchPilot GitHub App

`patchpilot-app` runs as a scheduler-first GitHub App worker. It authenticates as the app, discovers every repository where the app is installed, and runs scans/remediation automatically without webhook triggers or slash commands.

## How it works

1. PatchPilot lists the app installations and the repositories granted to each installation.
2. Each repository is scanned on its own cadence from `.patchpilot.yaml`.
3. When remediation is needed, PatchPilot opens a pull request with the proposed fix.

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
  - `Contents`: Read & write
  - `Pull requests`: Read & write
  - `Metadata`: Read-only

Install the app on the repositories you want PatchPilot to manage. Installed repositories are discovered automatically.

For gradual rollout, PatchPilot can gate scheduled work on repository topics. GitHub does not have first-class repository labels, so PatchPilot treats repository topics as rollout labels.

## Environment

Required:

- `PP_APP_ID`: GitHub App ID.
- `PP_PRIVATE_KEY_PATH` or `PP_PRIVATE_KEY_PEM`: app private key.

Common optional settings:

- `PP_WORKDIR`: temporary working directory root.
- `PP_PATCHPILOT_BINARY`: path to the PatchPilot binary.
- `PP_JOB_RUNNER`: `local` or `container`. Defaults to `local`.
- `PP_JOB_CONTAINER_RUNTIME`: container runtime for repo jobs when `PP_JOB_RUNNER=container`. Defaults to `docker`.
- `PP_JOB_CONTAINER_IMAGE`: container image that contains `patchpilot`, `syft`, `grype`, language toolchains, and package managers needed for remediation.
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
- `PP_GITHUB_RETRY_MAX_ATTEMPTS`, `PP_GITHUB_RETRY_INITIAL_BACKOFF`, `PP_GITHUB_RETRY_MAX_BACKOFF`: GitHub API retry controls.

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
PP_APP_ID=123 \
PP_PRIVATE_KEY_PATH=./private-key.pem \
./bin/patchpilot-app
```

Require an in-repo policy file before the scheduler will process a repository:

```bash
PP_APP_ID=123 \
PP_PRIVATE_KEY_PATH=./private-key.pem \
./bin/patchpilot-app run --require-policy-file
```

With `--require-policy-file`, repositories that do not contain `.patchpilot.yaml` are skipped entirely instead of inheriting the default scan schedule.

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
If you enable `PP_JOB_RUNNER=container`, mount access to a Docker-compatible daemon or socket because the app invokes `docker run` for repo jobs.

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
- Repo-local `verification`, `post_execution`, and `registry` sections are ignored.
- This prevents repository owners from using policy to execute arbitrary host commands or read operator-managed environment secrets.
- For stronger isolation, set `PP_JOB_RUNNER=container` so `scan` and `fix` run inside a short-lived container with a read-only root filesystem, dropped capabilities, and only the cloned repository mounted in.

## Manifest note

`./bin/patchpilot-app manifest` prints a starter GitHub App manifest. GitHub’s app setup still exposes webhook configuration fields, but scheduler-first PatchPilot does not depend on inbound webhook delivery at runtime.
