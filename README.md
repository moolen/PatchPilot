# cvefix

`cvefix` is a Go CLI that fixes known vulnerabilities in a source repository by upgrading only the minimal dependency versions required by `grype` findings.

It uses existing security tooling for discovery and keeps remediation narrow: no custom CVE database, no feature-chasing upgrades, and no unnecessary version bumps.

## Commands

- `cvefix scan [repo]`: generate an SBOM with `syft`, scan it with `grype`, and write normalized findings to `<repo>/.cvefix/`.
- `cvefix fix [repo]`: scan, apply minimal dependency fixes, run standard verification across discovered Go modules, re-scan, and write summaries into `<repo>/.cvefix/`.
- `cvefix verify [repo]`: re-run the scan and standard verification checks, then compare against the saved baselines.
- `cvefix schema`: print the JSON schema for `.patchpilot.yaml` (useful for editor validation/CI checks).

Global flags:

- `--dir <path>`: use a specific local directory as the working repository.
- `--repo-url <git-url>`: clone a repository into a temporary directory and use that clone as the working repository.
- `--policy <path>`: load a policy file from a custom path. By default, `cvefix` reads `<repo>/.patchpilot.yaml` when present.
- `--json`: emit structured JSON progress logs with `run_id`, `command`, and `repo`.

Exit codes for CI:

- `20`: scan failed (SBOM generation or vulnerability scan failed)
- `21`: patch failed (dependency patch application failed)
- `22`: verification regressed (a previously passing verification check now fails/timeouts)
- `23`: vulnerabilities remain after command completion

When multiple failure conditions apply, precedence is: scan/patch failures first, then verification regressions, then vulnerabilities remaining.

## How it works

1. Generate an SBOM with `syft` into `.cvefix/sbom.json`.
2. Scan the SBOM with `grype` into `.cvefix/vulns.json`.
3. Normalize only findings that include a known fix version.
4. Apply direct Go fixes with `golang.org/x/mod/modfile`.
5. Apply transitive Go fixes with `go list -m all` plus `go get module@fixedVersion` when a vulnerable module is present in the module build list.
6. Automatically bump each `go.mod` `go` directive to the latest supported patch release on the same Go major/minor line (or the oldest currently supported line if the current line is no longer supported).
7. Parse Dockerfiles and add minimal package or base-image remediation only when OS-package findings exist.
8. Patch `package.json` dependencies for npm findings.
9. Patch `requirements*.txt` entries for Python/PyPI findings.
10. Patch `pom.xml` dependency versions for Maven findings.
11. Run standard Go verification for each discovered module: `go build ./...`, `go test -run '^$' ./...`, and `go vet ./...`, using isolated caches under `.cvefix/`.
12. Re-scan and report before/fixed/remaining counts plus any verification regressions.

When `.patchpilot.yaml` is present, scan/fix/verify also apply repo-specific policy:

- custom verification commands (append or replace mode),
- post-execution hooks after `fix`,
- vulnerability/CVE excludes,
- skip-paths for scanning/module discovery/fixers,
- registry cache/auth configuration for Docker tag/digest resolution,
- Docker base-image allow/deny policy and patch strategy toggles.

## Requirements

- `syft`
- `grype`
- Go toolchain

## GitHub Integrations

- GitHub App service docs: `docs/github-app.md`
- Reusable GitHub Action docs: `docs/github-action.md`
- Action tag sync workflow: `.github/workflows/action-tags.yml`

Build both binaries locally:

```bash
make build
```

- `bin/cvefix`: CLI tool
- `bin/patchpilot-app`: webhook service for GitHub App automation

GitHub App utility commands:

- `./bin/patchpilot-app doctor`: validate environment and dependencies.
- `./bin/patchpilot-app manifest`: emit a starter GitHub App manifest JSON.

## Example

```bash
go run . scan ~/dev/external-secrets/external-secrets
go run . fix ~/dev/external-secrets/external-secrets
go run . verify ~/dev/external-secrets/external-secrets
go run . scan --dir ~/dev/external-secrets/external-secrets
go run . fix --repo-url https://github.com/external-secrets/external-secrets.git
go run . fix --dir ~/dev/external-secrets/external-secrets --policy ~/policies/external-secrets.yaml
```

## Agent Artifacts

When agent mode is enabled, cvefix stores per-attempt artifacts that include:

- `prompt.txt` (input prompt sent to the external agent)
- `agent.log` (captured stdout/stderr from the agent command)
- `validation.log` (post-attempt validation output)
- `summary.json` (attempt success and vulnerability delta)

Defaults and controls:

- default artifact path: `<repo>/.cvefix/agent`
- override path: `--agent-artifact-dir <path>`
- default non-interactive command: `codex exec ... < "$CVEFIX_PROMPT_FILE"`

## Policy File

Create `<repo>/.patchpilot.yaml` (or pass `--policy`) to control behavior per repository.

```yaml
version: 1

verification:
  mode: append # append | replace
  commands:
    - name: lint
      run: make lint
      timeout: 4m

post_execution:
  commands:
    - name: cleanup
      run: rm -rf .tmp-work
      when: always # always | success | failure
      fail_on_error: false

exclude:
  cves:
    - CVE-2025-12345
  vulnerabilities:
    - id: GHSA-xxxx-yyyy-zzzz
      package: openssl
      ecosystem: deb
      path: images/Dockerfile

scan:
  skip_paths:
    - vendor/**
    - examples/legacy/**

registry:
  cache:
    dir: .patchpilot-cache/registry
    ttl: 4h
  auth:
    mode: auto # auto | none | bearer
    token_env: REGISTRY_TOKEN # required when mode=bearer

docker:
  allowed_base_images:
    - golang:*
    - cgr.dev/chainguard/*
  disallowed_base_images:
    - ubuntu:latest
  patching:
    base_images: auto # auto | disabled
    os_packages: auto # auto | disabled
```

Policy parsing is strict after applying built-in legacy migrations (for example `postExecution` -> `post_execution`, `verification.commands[].command` -> `run`, and top-level `skip_paths` -> `scan.skip_paths`). Unknown keys still fail fast to avoid silent misconfiguration.

## Output

Each run writes state into `<repo>/.cvefix/`, including:

- `sbom.json`
- `vulns.json`
- `findings.json`
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
