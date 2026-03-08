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

## Typical flow

1. User comments `/cvefix fix` on an issue/PR.
2. App clones the repository default branch with an installation token.
3. App runs `cvefix fix --enable-agent=false`.
4. If files changed, app commits on `patchpilot/auto-fix-<timestamp>` and opens a PR.
5. If no change is needed, app posts a status comment.
