# OCI Scan App Design And Implementation Plan

## Goal

Change the GitHub automation flow so the scheduler can:

1. authenticate with either GitHub App credentials or a GitHub token,
2. run on a schedule,
3. scan repository code plus configured OCI artifacts,
4. do nothing when the scan yields `0` fixable CVEs,
5. patch ecosystem vulnerabilities deterministically where possible,
6. patch container OS packages through AI instead of Dockerfile heuristics,
7. open a PR without local validation,
8. watch CI on that PR,
9. use AI to assess failed CI logs and either repair the PR or treat the failure as flaky,
10. retry up to 3 CI-fix attempts, then close the PR if it never goes green.

## Current State In This Repo

- `internal/githubapp` already provides a scheduler-first GitHub App service.
- The app currently supports only GitHub App auth via `PP_APP_ID` plus private key.
- The scheduler already loads `.patchpilot.yaml` and respects `scan.cron` / `scan.timezone`.
- `patchpilot scan` already generates an SBOM, scans repo findings, and can also scan configured `artifacts.targets` / `artifacts.targets_command`.
- In GitHub App mode the repo-local policy is sanitized as untrusted and strips `artifacts`, `registry`, `verification`, `pre_execution`, `post_execution`, and `agent`.
- The existing `patchpilot fix` flow performs deterministic patching, then local validation, then optional agent repair.
- Docker OS package patching is currently heuristic and deterministic in `internal/fixer/dockerfile.go`.
- The app currently opens or updates a remediation PR, but it does not wait on CI, inspect logs, or iterate on failed PRs.

## Required Behavioral Changes

### 1. Dual GitHub authentication

The automation service must support:

- GitHub App mode: current behavior, installation-scoped token minting.
- Token mode: PAT or equivalent GitHub token supplied directly.

The scheduler behavior must remain available in both modes.

### 2. App scan/remediation pipeline

Per scheduled repository run:

1. resolve the repository's OCI image repository from an operator-managed mapping YAML file stored where the app runs,
2. fetch the latest semver tag from that OCI image repository,
3. generate an SBOM for repo source and each configured artifact image,
4. scan for CVEs,
5. if no fixable CVEs are found, log that there is nothing to do and stop,
6. if CVEs exist, patch language ecosystems,
7. for container findings, patch in two phases:
   - update the base image according to `docker.base_image_rules`,
   - then update OS packages if still needed,
8. perform Dockerfile OS package remediation via AI prompt, not deterministic text insertion,
9. do not run local validation before PR creation or after patching,
10. open or update a remediation PR,
11. wait for CI to turn green,
12. if CI fails, use AI to inspect job logs and decide whether the failure is caused by the patch or is flaky/unrelated,
13. apply follow-up fixes to the PR branch and wait again,
14. stop after 3 CI repair attempts and close the PR if it still is not green.

## Proposed Design

## A. Split CLI Fix Semantics From GitHub App Remediation

The current `patchpilot fix` contract is validation-centric. The requested app behavior is not.

Recommendation:

- Keep the existing CLI `patchpilot fix` behavior unchanged for local/operator usage.
- Add a separate app remediation pipeline for `patchpilot-app`.
- Reuse existing scan, fixer, git, PR, and agent building blocks where they fit.

This avoids breaking the existing CLI contract and keeps the new "open PR first, let CI validate later" flow isolated to GitHub automation.

## B. Introduce A GitHub Auth Provider Abstraction

Add a small auth/repository access layer under `internal/githubapp`:

- `AuthModeApp`
- `AuthModeToken`

Expected responsibilities:

- construct API clients,
- return clone credentials,
- list repositories in scope,
- report the actor/bot identity used for commits and PRs.

Suggested config additions:

- `PP_GITHUB_AUTH_MODE=app|token|auto`
- `PP_GITHUB_TOKEN`
- `PP_GITHUB_TOKEN_REPOSITORIES=owner-one/repo-a,owner-two/repo-b`

App mode keeps:

- `PP_APP_ID`
- `PP_PRIVATE_KEY_PATH` / `PP_PRIVATE_KEY_PEM`

Token mode uses:

- `PP_GITHUB_TOKEN`
- `PP_GITHUB_TOKEN_REPOSITORIES`

Token mode repository discovery should be explicit-allowlist only. The app should not enumerate and scan every repository visible to the token by default.

## C. Introduce An App-Specific Policy Sanitization Mode

Today the app strips repo-local `artifacts` and `agent` sections because the repo policy is treated as untrusted.

That no longer matches the requested workflow because the app must use:

- `docker.base_image_rules`
- an AI prompt configurable through policy
- an operator-managed repository-to-OCI mapping file

Recommendation:

- keep the existing strict `UntrustedRepo` mode for the CLI and other callers,
- add a separate GitHub automation policy mode with an explicit allowlist.

Suggested allowlist for GitHub automation mode:

- `scan`
- `exclude`
- `docker.allowed_base_images`
- `docker.disallowed_base_images`
- `docker.base_image_rules`
- `docker.patching`
- new app-safe prompt configuration

Suggested denylist to keep:

- `pre_execution`
- `post_execution`
- `verification`
- `registry`
- `artifacts`
- `agent`

The app should not execute repo-local `artifacts.targets_command` or trust repo-local artifact target definitions.

## D. Add An Operator-Managed Repository-To-OCI Mapping File

The OCI image lookup should not come from repo-local policy.

Recommendation:

- store a YAML file on the host where `patchpilot-app` runs,
- map repository full name to OCI image repository,
- have the app resolve the latest semver tag from that image repository at scan time.

Suggested config additions:

- `PP_OCI_MAPPING_FILE=/path/to/oci-mapping.yaml`

Suggested mapping shape:

```yaml
repositories:
  owner-one/service-a:
    image_repository: ghcr.io/example/service-a
  owner-two/service-b:
    image_repository: us-docker.pkg.dev/example-prod/service-b
```

Suggested behavior:

- if a repository is not present in the mapping file, only scan the repository source tree,
- if a repository has a mapping entry, scan the source tree plus the latest semver OCI image,
- semver means tags that parse as semver directly or after a leading `v` normalization,
- non-semver tags such as `latest` should be ignored for this workflow.

## E. Add A Dedicated App Remediation Workflow

Add a new workflow layer in `internal/githubapp` that replaces the current direct call to `patchpilot fix --enable-agent=false`.

Suggested stages:

1. `scan`
   - clone repo
   - load GitHub automation policy
   - run source SBOM + source CVE scan
   - resolve the OCI image repository from the host-local mapping file
   - resolve the latest semver image tag
   - pull or fetch that image
   - generate artifact SBOMs
   - run artifact CVE scan
   - merge all findings
2. `patch`
   - apply deterministic language fixers
   - apply deterministic base image updates
   - invoke AI container OS patching when container findings remain
3. `pr`
   - commit and push changes
   - open or update remediation PR
4. `ci`
   - poll PR checks/statuses
   - green => success
   - red => fetch failed-job logs, triage with AI, then either rerun CI or patch branch
5. `closeout`
   - close PR after max failed CI repair attempts

This can be implemented as a new app workflow entrypoint instead of overloading the current `runFixWorkflow`.

## F. Separate Docker Base Image Updates From Docker OS Package Updates

Current state:

- `internal/fixer/dockerfile.go` does both base image and OS package edits heuristically.

Required change:

- keep deterministic base image updates,
- remove deterministic OS package insertion from the app remediation path,
- hand OS package remediation to AI.

Recommended refactor:

1. split Docker remediation into two engines:
   - `docker_base_images`
   - `docker_os_packages`
2. keep `docker_base_images` deterministic and policy-driven,
3. replace `docker_os_packages` in app mode with an AI-driven stage.

Why:

- the requested Dockerfile edge cases are real:
  - final `USER <unprivileged>`
  - inherited non-root base images
  - multi-stage Dockerfiles
  - distro-specific package manager behavior
  - package install location in the correct stage

## G. Add App-Specific Prompt Configuration

The existing `agent.remediation_prompts` tree is built around the CLI repair loop and validation phases.

The app needs different prompts for:

- container OS patching,
- CI failure triage,
- CI repair attempts.

Recommendation:

- add a new operator-managed app config subtree for app automation prompts rather than overloading the current validation-oriented prompt stages.

Suggested shape:

```yaml
github_app:
  remediation:
    max_ci_attempts: 3
    prompts:
      container_os_patching:
        - mode: extend
          template: |
            ...
      ci_failure_assessment:
        - mode: extend
          template: |
            ...
      ci_failure_repair:
        - mode: extend
          template: |
            ...
```

Notes:

- keep the existing `mode: extend|replace` model,
- validate prompt size the same way current agent prompts are validated,
- only expose structured repository state and fetched CI logs to the prompt,
- do not expose operator secrets.
- treat these prompts as operator-managed app configuration, not repo-local trusted input.

## H. No Local Validation In App Remediation

The app workflow should not run:

- verification baseline,
- post-fix verification,
- post-fix vulnerability validation,
- safety blocking based on local verification output.

That means the app flow should not depend on:

- `.patchpilot/summary.json`
- `.patchpilot/verification.json`

for PR gating decisions before PR creation.

Instead:

- the initial scan decides whether remediation is needed,
- file changes decide whether there is something to commit,
- CI becomes the only validation signal after the PR is opened,
- the app should not perform any local post-patch re-scan either.

## I. Add A PR CI Tracking And Repair Loop

New app behavior after PR creation:

1. determine the PR head SHA,
2. poll GitHub check runs and commit statuses for that SHA,
3. treat the PR as green only when all relevant checks have completed successfully,
4. if checks fail:
   - collect failed check metadata,
   - fetch logs where possible,
   - ask AI whether the failure is related to the remediation or is flaky/unrelated,
   - if related, patch the PR branch and push,
   - if the AI classifies the failure as a known flake, rerun the job or workflow,
   - wait again.

Stop conditions:

- success: all checks green,
- failure: 3 failed CI repair attempts exhausted.

At exhaustion:

- close the PR,
- leave a summary comment with the failed attempts and AI assessment,
- delete the remediation branch.

## J. CI Status Model

Implementation recommendation:

- evaluate both classic commit statuses and modern check runs,
- use the PR head SHA as the source of truth,
- consider all statuses/checks as required for now,
- consider the PR pending while any required check is queued or in progress,
- consider the PR failed when any relevant check reaches failure,
- consider the PR green only when all relevant checks succeed.

First implementation scope recommendation:

- support all check runs/statuses for pass/fail detection,
- support GitHub Actions job log retrieval first,
- treat non-Actions failed checks as triageable metadata-only failures unless a log source is later added.

## K. AI CI Failure Triage Loop

Recommended data passed to the AI:

- repo path and changed files,
- PR branch,
- failing checks,
- per-job log excerpts,
- prior attempt summaries,
- explicit instruction to classify:
  - related to patch,
  - flaky/transient,
  - unrelated pre-existing failure,
  - insufficient evidence.

Recommended actions by classification:

- related to patch:
  - let AI modify the PR branch,
  - commit and push,
  - increment CI repair attempt counter.
- flaky/transient:
  - rerun failed workflow/job if possible,
  - return parseable output that explicitly marks the failure as a known flake,
  - do not create a code change for that attempt.
- unrelated pre-existing:
  - treat as non-green and count toward the capped retry budget unless later product policy says otherwise.
- insufficient evidence:
  - count as a failed attempt and stop after threshold.

The AI output for CI assessment should be structured and parseable. Suggested shape:

```json
{
  "classification": "related_patch | known_flake | unrelated | insufficient_evidence",
  "summary": "short explanation",
  "recommended_action": "patch | rerun | none"
}
```

## L. State Tracking

Extend scheduler state to track more than "one open PR exists".

Suggested tracked fields:

- PR number
- PR URL
- PR branch
- PR head SHA
- PR created/updated timestamps
- CI attempt count
- last CI poll time
- last CI conclusion
- last failed checks summary
- last AI assessment
- last rerun action
- last closure comment URL

This makes the scheduler resilient across restarts and allows CI follow-up to happen on later ticks.

## M. Logging And Metrics

Add structured logs and metrics for:

- auth mode
- repos discovered by auth mode
- artifact targets resolved
- artifact scans with `0 CVEs`
- PRs opened / updated / closed
- CI polls
- CI green / red / pending counts
- AI triage attempts
- AI repair attempts
- flaky reruns
- PRs closed after max attempts

## Decisions Captured

- token mode uses an explicit repository allowlist,
- repo-local `artifacts.targets` and `artifacts.targets_command` are not used by the app workflow,
- OCI image resolution comes from an operator-managed mapping YAML file stored where the app runs,
- prompt overrides are supported through operator-managed app configuration,
- the app performs absolutely no local validation step after patching, including no post-patch re-scan,
- the AI must emit structured output for CI failure assessment,
- known flaky CI should be rerun when the AI classifies it as such,
- all PR statuses/check runs are required,
- after 3 unsuccessful CI repair attempts the app closes the PR, leaves a comment, and deletes the remediation branch.

## Implementation Tasks

## Phase 1: Authentication And Config

- Add a GitHub auth mode abstraction in `internal/githubapp`.
- Extend config parsing in `internal/githubapp/config.go` for token mode.
- Add explicit allowlist config for token mode.
- Add operator-managed OCI mapping file config and parser.
- Update `cmd/patchpilot-app` doctor output for both auth modes.
- Update docs for both credential paths.
- Add config tests covering:
  - app mode success,
  - token mode success,
  - invalid mixed config,
  - missing allowlist in token mode,
  - missing or malformed OCI mapping file.

## Phase 2: GitHub Automation Policy Model

- Add a dedicated GitHub automation policy sanitization mode in `internal/policy/config.go`.
- Decide and implement the allowlist for repo-local policy sections in app mode.
- Add schema/config types for app-specific remediation prompts and CI attempt controls.
- Add policy validation tests for the new prompt subtree and attempt limits.
- Update docs to explain that repo-local artifact target execution is disabled in app mode.

## Phase 3: App Workflow Refactor

- Introduce a new app remediation workflow type under `internal/githubapp`.
- Keep `runScanWorkflow` for finding discovery or refactor it into reusable scan stages.
- Replace the current `runFixWorkflow` call from `service.go` with the new workflow.
- Ensure the new workflow uses the GitHub automation policy mode rather than generic untrusted mode.
- Preserve existing repo cloning, branch creation, commit, and PR upsert behavior where still valid.

## Phase 4: Scan Pipeline

- Reuse or refactor the existing source SBOM + vulnerability scan path.
- Add OCI mapping lookup for the current repository.
- Resolve the latest semver OCI tag from the mapped image repository.
- Pull/fetch the resolved image and scan it as an artifact image.
- Persist enough scan output for later PR body generation and AI context.
- Log and short-circuit cleanly on `0` fixable CVEs.

## Phase 5: Deterministic Remediation Refactor

- Split Docker base image patching from Docker OS package patching.
- Keep `docker.base_image_rules` enforcement and deterministic updates.
- Keep ecosystem fixers for Go, npm, Cargo, pip, Maven, Gradle, NuGet, Composer, and GitHub Actions.
- Make the app workflow skip validation-centric summary generation that currently feeds `evaluateSafety`.
- Decide whether the CLI flow keeps the current deterministic Docker OS patching or also migrates to the new split implementation.

## Phase 6: AI Container OS Patching

- Add an app-specific AI stage for Docker OS package remediation.
- Build a structured prompt input containing:
  - Dockerfile paths,
  - container findings,
  - fixed versions,
  - base image rule outcome,
  - repository constraints.
- Allow config-driven prompt extension/replacement.
- Ensure the AI stage only runs when container findings remain after base image updates.
- Add focused tests for prompt building and stage orchestration.

## Phase 7: PR Creation Without Local Validation

- Remove the app flow’s dependency on local verification and post-fix revalidation.
- Commit and push whenever remediation changes exist.
- Update PR body content so it reflects:
  - scan findings before patching,
  - changed files,
  - that validation is deferred to PR CI.
- Keep existing blocked-path enforcement from `PP_DISALLOWED_PATHS`.

## Phase 8: CI Observation

- Add GitHub APIs for:
  - PR head SHA retrieval,
  - check runs listing,
  - commit statuses listing,
  - workflow/job log download for GitHub Actions.
- Implement a CI state reducer:
  - pending,
  - green,
  - red,
  - unknown.
- Persist CI state in scheduler storage so retries survive restarts.
- Add tests for mixed status/check scenarios.

## Phase 9: AI CI Failure Assessment And Repair

- Add a CI triage prompt builder and workflow.
- Feed failed-check context plus logs into the AI runner.
- Implement structured AI classification output parsing.
- Add follow-up branch patching on related failures.
- Add rerun behavior for failures classified as known flakes.
- Cap CI repair attempts at 3.

## Phase 10: PR Closeout

- Close the remediation PR when the max attempts are exhausted.
- Post a summary comment describing:
  - attempts made,
  - last failing checks,
  - AI assessment,
  - why the PR was closed.
- Delete the remediation branch after closure.
- Update scheduler state and metrics accordingly.

## Phase 11: Testing

- Unit tests:
  - config/auth provider,
  - policy sanitization,
  - Docker remediation split,
  - prompt building,
  - CI state reducer,
  - retry accounting.
- Integration-style tests with fake GitHub responses for:
  - app auth flow,
  - token auth flow,
  - token allowlist filtering,
  - zero-CVE no-op,
  - mapped-OCI-image-driven PR creation,
  - CI green on first try,
  - CI failure fixed on retry,
  - flaky CI rerun path,
  - PR close after 3 failed attempts.

## Phase 12: Documentation

- Update `docs/github-app.md` for the new auth modes and changed trust model.
- Update `README.md` to distinguish CLI `fix` from GitHub app remediation behavior.
- Document the new policy keys and prompt hooks.
- Document CI retry semantics and PR closeout behavior.

## Recommended Order Of Execution

1. auth/config abstraction
2. GitHub automation policy model
3. app workflow refactor scaffold
4. scan pipeline reuse with artifact support restored
5. deterministic remediation split
6. AI container OS patching
7. PR creation without local validation
8. CI polling/state model
9. AI CI triage and repair loop
10. PR closeout
11. tests and docs hardening

## Suggested Initial Non-Goals

- supporting arbitrary third-party CI log providers on day one,
- changing the existing local CLI `patchpilot fix` UX unless needed by shared internals,
- trusting repo-local `pre_execution`, `post_execution`, `verification`, or `registry` config in GitHub automation mode.
