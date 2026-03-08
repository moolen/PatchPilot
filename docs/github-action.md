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
        uses: moolen/PatchPilot@master
        with:
          command: fix
          dir: .
          enable_agent: "false"
          acceptable_exit_codes: "0,23"
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

## Notes

- Exit code `23` means vulnerabilities still remain; include it in `acceptable_exit_codes` if you want a non-failing informational run.
- The action is Docker-based and currently supports Linux runners.
