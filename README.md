# PatchPilot

`PatchPilot` is a Go CLI that fixes known vulnerabilities in a source repository by upgrading only the minimal dependency versions required by `grype` findings.

It uses existing security tooling for discovery and keeps remediation narrow: no custom CVE database, no feature-chasing upgrades, and no unnecessary version bumps.

## Commands

- `patchpilot scan [repo]`: generate an SBOM with `syft`, scan it with `grype`, and write normalized findings to `<repo>/.patchpilot/`.
- `patchpilot fix [repo]`: scan, apply minimal dependency fixes, run standard verification across discovered Go modules, re-scan, and write summaries into `<repo>/.patchpilot/`.
- `patchpilot verify [repo]`: re-run the scan and standard verification checks, then compare against the saved baselines.
- `patchpilot schema`: print the JSON schema for `.patchpilot.yaml` (useful for editor validation/CI checks).

Global flags:

- `--dir <path>`: use a specific local directory as the working repository.
- `--repo-url <git-url>`: clone a repository into a temporary directory and use that clone as the working repository.
- `--policy <path>`: load a central policy file and combine it with `<repo>/.patchpilot.yaml` when present.
- `--policy-mode <merge|override>`: policy layering strategy when `--policy` is set.
  `merge`: deep-merge central + in-repo policy (in-repo values take precedence for scalar fields; list fields are combined).
  `override`: if `<repo>/.patchpilot.yaml` exists, use it instead of the central policy; otherwise use the central policy.
- `--json`: emit structured JSON progress logs with `run_id`, `command`, and `repo`.

Exit codes for CI:

- `20`: scan failed (SBOM generation or vulnerability scan failed)
- `21`: patch failed (dependency patch application failed)
- `22`: verification regressed (a previously passing verification check now fails/timeouts)
- `23`: vulnerabilities remain after command completion

When multiple failure conditions apply, precedence is: scan/patch failures first, then verification regressions, then vulnerabilities remaining.

## How it works

1. Generate an SBOM with `syft` into `.patchpilot/sbom.json`.
2. Scan the SBOM with `grype` into `.patchpilot/vulns.json`.
3. Normalize only findings that include a known fix version.
4. Apply direct Go fixes with `golang.org/x/mod/modfile`.
5. Apply transitive Go fixes with `go list -m all` plus `go get module@fixedVersion` when a vulnerable module is present in the module build list.
6. Automatically bump each `go.mod` `go` directive to the latest supported patch release on the same Go major/minor line (or the oldest currently supported line if the current line is no longer supported).
7. Parse Dockerfiles and add minimal package or base-image remediation only when OS-package findings exist.
8. Patch `package.json` dependencies for npm findings and automatically sync `package-lock.json` / `npm-shrinkwrap.json` when present.
9. Patch `requirements*.txt` entries for Python/PyPI findings.
10. Patch `pom.xml` and `build.gradle*` dependency versions for Maven/Gradle findings.
11. Patch `Cargo.toml` dependencies for Cargo findings.
12. Patch `.csproj` package references for NuGet findings.
13. Patch `composer.json` requirements for Composer findings.
14. Run standard verification checks: Go build/test/vet for discovered Go modules plus manifest syntax/parse checks for npm, pip, Maven, Gradle, Cargo, NuGet, and Composer.
15. Re-scan and report before/fixed/remaining counts plus any verification regressions.

When `.patchpilot.yaml` is present, scan/fix/verify also apply repo-specific policy.
In enterprise setups, `--policy` can provide a central baseline policy that is layered with the in-repo file:

- `--policy-mode merge` (default): central baseline plus repo-specific adjustments.
- `--policy-mode override`: repo file fully replaces central baseline.

Repo-local policy always has precedence over central policy when both are considered.

Policy controls include:

- custom verification commands (append or replace mode),
- post-execution hooks after `fix`,
- vulnerability/CVE excludes,
- skip-paths for scanning/module discovery/fixers,
- registry cache/auth configuration for Docker tag/digest resolution,
- Docker base-image allow/deny policy and patch strategy toggles,
- Go runtime remediation policy (`disabled`, `toolchain`, `minimum`).

## Requirements

- `syft`
- `grype`
- Go toolchain

## GitHub Integrations

- GitHub App service docs: `docs/github-app.md`
- Observability docs: `docs/observability.md`
- Reusable GitHub Action docs: `docs/github-action.md`
- Action tag sync workflow: `.github/workflows/action-tags.yml`

Build both binaries locally:

```bash
make build
```

- `bin/patchpilot`: PatchPilot CLI binary
- `bin/patchpilot-app`: scheduler service for GitHub App automation

Build the GitHub App container image locally:

```bash
docker build -f Dockerfile.patchpilot-app -t patchpilot-app:dev .
docker run --rm \
  -p 8080:8080 \
  -e PP_APP_ID=123 \
  -e PP_PRIVATE_KEY_PATH=/run/secrets/patchpilot.pem \
  -v "$PWD/private-key.pem:/run/secrets/patchpilot.pem:ro" \
  patchpilot-app:dev
```

The app image includes `patchpilot-app`, `patchpilot`, `git`, `syft`, `grype`, `go`, `node`, and `npm` so the default local job runner can scan and remediate repositories without additional sidecar tooling.

GitHub App utility commands:

- `./bin/patchpilot-app doctor`: validate environment and dependencies.
- `./bin/patchpilot-app manifest`: emit a starter GitHub App manifest JSON.

## Example

```bash
patchpilot scan ~/dev/external-secrets/external-secrets
patchpilot fix ~/dev/external-secrets/external-secrets
patchpilot verify ~/dev/external-secrets/external-secrets
patchpilot scan --dir ~/dev/external-secrets/external-secrets
patchpilot fix --repo-url https://github.com/external-secrets/external-secrets.git
patchpilot fix --dir ~/dev/external-secrets/external-secrets --policy ~/policies/org-baseline.yaml --policy-mode merge
patchpilot fix --dir ~/dev/external-secrets/external-secrets --policy ~/policies/org-baseline.yaml --policy-mode override
```

## Agent Artifacts

When agent mode is enabled, PatchPilot stores per-attempt artifacts that include:

- `prompt.txt` (input prompt sent to the external agent)
- `agent.log` (captured stdout/stderr from the agent command)
- `validation.log` (post-attempt validation output)
- `summary.json` (attempt success and vulnerability delta)

Defaults and controls:

- default artifact path: `<repo>/.patchpilot/agent`
- override path: `--agent-artifact-dir <path>`
- default non-interactive command: `codex exec ... < "$PATCHPILOT_PROMPT_FILE"`

## Policy File

Create `<repo>/.patchpilot.yaml` to control behavior per repository.
Use `--policy` to add a central baseline policy on top.

Full example (`.patchpilot.yaml`, all supported top-level keys):

```yaml
version: 1

verification:
  mode: append # append | replace
  commands:
    - name: lint
      run: make lint
      timeout: 4m
    - name: integration
      run: make test-integration
      timeout: 15m

post_execution:
  commands:
    - name: cleanup
      run: rm -rf .tmp-work
      when: always # always | success | failure
      fail_on_error: false
    - name: notify-on-failure
      run: ./scripts/notify-slack.sh
      when: failure
      fail_on_error: true

exclude:
  cves:
    - CVE-2025-12345
  cve_rules:
    - id: CVE-2025-22222
      package: github.com/example/legacy-lib
      ecosystem: golang
      path: services/api/go.mod
      reason: pending upstream patch
      owner: team-security
      expires_at: 2026-12-31
  vulnerabilities:
    - id: GHSA-xxxx-yyyy-zzzz
      package: openssl
      ecosystem: deb
      path: images/Dockerfile
      reason: accepted temporary risk
      owner: team-platform
      expires_at: 2026-06-30

scan:
  cron: "0 3 * * *"
  timezone: Europe/Berlin
  skip_paths:
    - vendor/**
    - examples/legacy/**
    - third_party/**

registry:
  cache:
    dir: .patchpilot-cache/registry
    ttl: 4h
  auth:
    mode: bearer # auto | none | bearer
    token_env: REGISTRY_TOKEN # required when mode=bearer

docker:
  allowed_base_images:
    - golang:1.24-alpine
    - cgr.dev/chainguard/*
  disallowed_base_images:
    - ubuntu:latest
  patching:
    base_images: auto # auto | disabled
    os_packages: auto # auto | disabled

go:
  patching:
    runtime: minimum # disabled | toolchain | minimum
```

Use `go.patching.runtime: toolchain` for OSS libraries that want to prefer a patched local toolchain without hard-raising the declared minimum Go version. Use `minimum` for applications or enterprise environments that want to require the patched Go version everywhere.

Policy parsing is strict after applying built-in legacy migrations (for example `postExecution` -> `post_execution`, `verification.commands[].command` -> `run`, and top-level `skip_paths` -> `scan.skip_paths`). Unknown keys still fail fast to avoid silent misconfiguration.

## Output

Each run writes state into `<repo>/.patchpilot/`, including:

- `sbom.json`
- `vulns.json`
- `findings.json`
- `findings.sarif`
- `baseline-findings.json`
- `summary.json`
- `run.json`
- `verification-baseline.json`
- `verification.json`

`run.json` contains staged telemetry for scan/fix/verify:

- run metadata (`run_id`, command, start/end timestamps, duration),
- per-stage timings and errors,
- machine-readable failure taxonomy (`policy_violation`, `scan_failed`, `no_automated_fix_available`, `partial_fix_applied`, `verification_regressed`, ...),
- counters (before/fixed/after, regressions).

## Proof Of Work

Against `~/dev/external-secrets/external-secrets`, the tool reduced the source-focused fixable vulnerability count from `22` to `0` after the direct and transitive Go-module passes.
