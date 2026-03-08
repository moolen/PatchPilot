# PatchPilot GitHub Action

This repository exposes a Docker-based GitHub Action that packages `cvefix` with `syft` and `grype`.

Use it from any repository:

```yaml
name: PatchPilot

on:
  workflow_dispatch:
  pull_request:

jobs:
  cvefix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PatchPilot fix
        id: patchpilot
        uses: moolen/PatchPilot@v1
        with:
          command: fix
          dir: .
          enable_agent: "false"
          acceptable_exit_codes: "0,23"
      - name: Upload SARIF to GitHub code scanning
        if: always() && steps.patchpilot.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.patchpilot.outputs.sarif-path }}
```

## Inputs

- `command`: `scan`, `fix`, or `verify` (default: `fix`).
- `dir`: local repository directory (default: `.`). Ignored when `repo_url` is set.
- `repo_url`: optional git URL to clone and process.
- `policy`: optional policy file path.
- `enable_agent`: used only for `fix` (default: `false`).
- `agent_command`: external agent command when `enable_agent=true`.
- `agent_max_attempts`: max external agent attempts.
- `extra_args`: extra CLI flags appended as space-separated args.
- `acceptable_exit_codes`: comma-separated exit codes treated as success (default: `0`).

## Outputs

- `exit-code`: raw `cvefix` process exit code.
- `sarif-path`: absolute path to `.cvefix/findings.sarif` when generated locally (`repo_url` runs are excluded).
- `summary-path`: absolute path to `.cvefix/summary.json` when generated.

## Notes

- Exit code `23` means vulnerabilities still remain; include it in `acceptable_exit_codes` if you want a non-failing informational run.
- The action is Docker-based and currently supports Linux runners.

## Versioning and Pinning

- Immutable release tags: use `v1.0.0`, `v1.1.0`, etc. for fully reproducible runs.
- Moving major tag: `v1` is maintained as a convenience alias to the latest `v1.x.x`.
- Maximum supply-chain safety: pin to a commit SHA.

Example SHA pin:

```yaml
- uses: moolen/PatchPilot@ad3563f90d69c26dd1a8e7821d98e105407925e7
```
