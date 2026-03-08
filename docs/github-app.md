# PatchPilot GitHub App

`patchpilot-app` is a webhook service that runs `cvefix` on repositories where your GitHub App is installed and opens remediation pull requests.

## Supported triggers

- `issue_comment`: run when a user comments a slash command.
- `push`: optional automatic remediation on default-branch pushes.

Slash command format:

```text
/cvefix fix [--policy <path>] [--auto-merge]
```

`/patchpilot fix` is accepted as an alias.

## App permissions and events

Use these minimum GitHub App permissions:

- Repository permissions:
  - `Contents`: Read & write
  - `Pull requests`: Read & write
  - `Issues`: Read & write
  - `Metadata`: Read-only
- Subscribe to events:
  - `Issue comment`
  - `Push` (only if using push-based remediation)

## Environment variables

- `PP_APP_ID` (required): GitHub App ID.
- `PP_WEBHOOK_SECRET` (required): webhook secret configured in the app.
- `PP_PRIVATE_KEY_PATH` or `PP_PRIVATE_KEY_PEM` (required): app private key.
- `PP_LISTEN_ADDR` (optional, default `:8080`): HTTP listen address.
- `PP_WORKDIR` (optional): temporary working directory root.
- `PP_CVEFIX_BINARY` (optional, default `cvefix`): path to cvefix binary.
- `PP_ALLOWED_REPOS` (optional): comma-separated allow-list (`org/repo,org/repo2`).
- `PP_ENABLE_PUSH_AUTOFIX` (optional, default `false`): enable push-triggered remediation.
- `PP_GITHUB_WEB_BASE_URL` (optional, default `https://github.com`): clone URL base.
- `PP_GITHUB_API_BASE_URL` and `PP_GITHUB_UPLOAD_API_URL` (optional, set both for GitHub Enterprise).
- `PP_ENABLE_AUTO_MERGE` (optional, default `true`): allow app-side auto-merge enablement when requested.
- `PP_DELIVERY_DEDUP_TTL` (optional, default `24h`): retention window for webhook delivery dedupe state.
- `PP_MAX_RISK_SCORE` (optional, default `25`): maximum allowed remediation risk score before PR creation is blocked.
- `PP_DISALLOWED_PATHS` (optional): comma-separated blocked path patterns (supports `*` and `/**`).
- `PP_METRICS_PATH` (optional, default `/metrics`): metrics endpoint path.

## Run locally

```bash
make build
PP_APP_ID=123 \
PP_WEBHOOK_SECRET=... \
PP_PRIVATE_KEY_PATH=./private-key.pem \
./bin/patchpilot-app
```

Health endpoint: `GET /healthz`  
Webhook endpoint: `POST /webhook`  
Metrics endpoint: `GET /metrics`

## Doctor and Manifest UX

Run environment diagnostics:

```bash
./bin/patchpilot-app doctor
```

Generate a starter GitHub App manifest JSON:

```bash
PP_APP_NAME=PatchPilot \
PP_APP_URL=https://patchpilot.example.com \
PP_WEBHOOK_URL=https://patchpilot.example.com/webhook \
./bin/patchpilot-app manifest
```

## Typical flow

1. User comments `/cvefix fix` on an issue/PR.
2. App clones the repository default branch with an installation token.
3. App runs `cvefix fix --enable-agent=false`.
4. If files changed, app commits on `patchpilot/auto-fix-<timestamp>` and opens a PR.
5. If no change is needed, app posts a status comment.

Safety gates block PR creation when:

- verification regressions are detected,
- changed files match `PP_DISALLOWED_PATHS`,
- computed risk score exceeds `PP_MAX_RISK_SCORE`.

Webhook idempotency:

- The app stores `X-GitHub-Delivery` IDs in `<PP_WORKDIR>/deliveries.json`.
- Duplicate or retried deliveries are ignored within `PP_DELIVERY_DEDUP_TTL`.
