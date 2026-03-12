# OCI Bump V2

## Goals

1. Remove `docker` and `artifacts` from repo policy.
2. Remove `repositories` from app/runtime OCI config.
3. Support two OCI workflows:
   - Base image bumping (`FROM <image>`) with policy-driven tag selection.
   - External OCI image scanning mapped to Dockerfiles (no local image builds).
4. Make OS package remediation agent-only (no deterministic Dockerfile package edits).
5. Support private ECR lookup with Docker credentials first, AWS SDK fallback.
6. Improve observability with step-by-step OCI decision logging.

## Confirmed Product Decisions

- Base image updates and OS package updates are separate paths.
- Base image updates must patch every `FROM` occurrence.
- If no explicit policy matches, choose latest semver from same source repository.
- If current `FROM` tag is non-semver (for example `latest`), jump to latest semver.
- Default prerelease behavior is exact-match family unless policy allows otherwise.
- OCI policies support wildcard source matching.
- Wildcard grammar supports doublestar (`**`).
- First matching policy wins.
- If multiple policies match, log this explicitly and use first match.
- Digest-pinned `FROM` should be updated as `tag + digest`.
- External image scanning mapping is for scanning external images only.
- Do not build images as part of scan/fix.
- OS package bumping is agent-only in both CLI and app flows.
- OS package prompt overrides live in `.patchpilot.yaml` with existing `extend|replace`.
- External mapping config must support hot reload with watcher and keep last-good state on parse errors.
- External mapping repo matching is exact normalized `owner/repo` (no wildcard).

## V2 Config Model

### 1) Repo-local `.patchpilot.yaml`

`docker` and `artifacts` are removed. New OCI policy and repo-local external mapping live under `oci`.

```yaml
version: 1

oci:
  policies:
    - name: kyverno-stable
      source: ghcr.io/kyverno/* # wildcard supported
      tags:
        allow:
          - '^v?\d+\.\d+\.\d+(-alpine\d+\.\d+)?$'
        semver:
          - range:
              - ">=1.15.0 <1.16.0"
            includePrerelease: false
            prereleaseAllow: []
        deny:
          - '.*-debug$'

  external_images:
    - source: ghcr.io/external-secrets/external-secrets
      dockerfiles:
        - Dockerfile
      tag: latest-semver # optional; default latest-semver
```

Notes:
- `oci.policies` are used for base-image bumping in `FROM`.
- `oci.external_images` are repo-local external scan mappings (no repo key in repo config).
- Repo-local configuration takes precedence over external mapping config.

### 2) External OCI Mapping Config (separate file, hot-reloaded)

The runtime config replaces `repositories:` with a new list-based mapping shape.

```yaml
oci:
  mappings:
    - repo: kyverno/kyverno
      images:
        - source: ghcr.io/kyverno/kyverno
          dockerfiles:
            - Dockerfile
          tag: latest-semver
```

Notes:
- Purpose: external OCI scanning mapping only.
- No image build commands.
- No prompt overrides here.
- Used by both CLI and app flows.

## Effective Configuration Resolution

For a target repository:

1. Load external mapping config (if configured).
2. Select external `oci.mappings[]` entry matching repo key.
3. Load repo `.patchpilot.yaml`.
4. Build effective external image scan mappings:
   - Start from external mapping images.
   - Overlay repo-local `oci.external_images` by `source` (repo-local wins).
5. Build effective OCI policy list for base image bumping:
   - Use repo-local `oci.policies` as authoritative policy source.
   - If future global/default policies are added, repo-local policies are prepended.

## Runtime Behavior

### A) Base image bumping (`fix`)

For each Dockerfile and each `FROM` occurrence:

1. Parse image reference (`registry/repo:tag[@digest]`).
2. Resolve matching policy by wildcard against `policy.source`.
3. If >1 policy matches:
   - log all matching policy names/indexes,
   - choose first match.
4. List tags from registry for the source image.
5. Filter in this order:
   - `tags.allow[]` regex allowlist (pre-semver),
   - semver extraction + semver range checks from `tags.semver[].range[]`,
   - prerelease handling (`includePrerelease`, `prereleaseAllow`),
   - `tags.deny[]` regex denylist (post-semver).
6. If no policy matches:
   - choose latest semver by default,
   - if current tag has prerelease suffix, require exact prerelease family match.
7. Select best candidate (highest valid semver; deterministic tie-break).
8. If `@sha256` is present, resolve and write updated `tag + digest`.
9. Patch Dockerfile for every `FROM` occurrence that can be upgraded.

### B) External OCI scanning (`scan` and `fix`)

1. Resolve effective image mappings (external file + repo-local overlay).
2. For each mapped image:
   - resolve image ref (`source` + tag strategy),
   - pull image,
   - generate SBOM from image,
   - scan SBOM,
   - map `deb/apk/rpm` findings to mapped Dockerfile paths.
3. Merge mapped findings with repository findings.
4. Do not run any image build command.

### C) OS package bumping (`fix`)

1. Deterministic Dockerfile OS package mutation is removed.
2. Container OS package remediation runs via agent only.
3. Prompt overrides come from `.patchpilot.yaml` using existing prompt extension model.

## Logging Requirements

Add structured logs for each OCI step:

- Policy resolution:
  - `from_image`, `matched_policies`, `selected_policy`, `reason`.
- Tag discovery:
  - registry, repository, total tags fetched.
- Filter pipeline counts:
  - `allow_in`, `allow_out`, `semver_in`, `semver_out`, `prerelease_in`, `prerelease_out`, `deny_out`, final candidates.
- Candidate decision:
  - current tag/version, selected tag/version, digest update status.
- External scan mapping:
  - mapping source (external file vs repo-local), resolved images, dockerfile targets.
- Auth path:
  - `auth_mode=docker_credentials|aws_sdk_fallback`.
- Conflict warnings:
  - multiple policy matches, duplicate mapping sources, invalid rules skipped.

## Authentication Requirements (OCI Tag Lookup)

1. Try Docker credential helpers / Docker config credentials first.
2. If lookup requires ECR auth and Docker creds are unavailable/insufficient:
   - use AWS SDK token fallback.
3. Preserve existing non-ECR registry auth behavior.

## Compatibility and Migration

1. Remove support for repo policy keys:
   - `docker`
   - `artifacts`
2. Remove support for runtime config key:
   - `repositories`
3. Introduce:
   - repo policy `oci.policies`
   - repo policy `oci.external_images`
   - external mapping config `oci.mappings`
4. Return clear policy errors when removed keys are present.
5. Update docs/examples accordingly.

## Implementation Task Plan

### Phase 0: Finalize spec and fixtures

- [x] Create policy examples for `oci.policies` and `oci.external_images`.
- [x] Create external mapping examples for `oci.mappings`.
- [x] Add golden test cases for wildcard policy matching and precedence.

### Phase 1: Policy schema/model refactor

- [x] Remove `DockerPolicy` and `ArtifactsPolicy` from `internal/policy/config.go`.
- [x] Add new `OCIPolicy` structs to repo policy model.
- [x] Update defaults/normalization/validation for `oci.*`.
- [x] Update `internal/policy/schema.go` to remove `docker`/`artifacts` and add `oci`.
- [x] Update policy tests and golden packs.

### Phase 2: Runtime mapping config refactor

- [x] Replace app/runtime `repositories` model with `oci.mappings`.
- [x] Update loader validation and tests.
- [x] Add file watcher with hot reload + last-good retention on parse errors.
- [x] Add integration test for atomic file replace and reload.

### Phase 3: Base image bump engine v2

- [x] Implement wildcard `source` policy matching.
- [x] Implement first-match precedence and multi-match warning logs.
- [x] Implement tag filter pipeline (`allow -> semver -> prerelease -> deny`).
- [x] Implement default fallback behavior when no policy matches.
- [x] Update digest-pinned rewrite to enforce tag+digest updates.
- [x] Ensure every `FROM` occurrence is evaluated and patched independently.
- [x] Add exhaustive unit tests for prerelease edge cases.

### Phase 4: External OCI scanning v2

- [x] Remove build-based artifact target flow from scan/fix.
- [x] Implement effective mapping merge (external + repo-local overlay).
- [x] Implement image pull/SBOM/scan pipeline for mapped external images.
- [x] Map container findings to configured Dockerfile paths.
- [ ] Add scan/fix integration tests for CLI and app.

### Phase 5: OS package remediation changes

- [x] Remove deterministic OS package Dockerfile patcher from default engine path.
- [x] Keep base-image deterministic patcher.
- [x] Route container OS package remediation through agent-only path.
- [x] Add/extend repo-local prompt hook for container OS patching prompts.
- [ ] Verify behavior in CLI and app with agent enabled/disabled.

### Phase 6: Auth and registry support

- [x] Keep Docker credential helper auth as first path.
- [x] Add AWS SDK ECR fallback for tag listing/digest resolution.
- [x] Add tests for ECR fallback path and failure diagnostics.

### Phase 7: Observability and docs

- [x] Add structured logs for every OCI decision point.
- [x] Update README and `docs/github-app.md` for new config format and behavior.
- [x] Add migration guide and deprecation error examples.
- [x] Add operator notes for Kubernetes hot-reload deployment.

### Phase 8: Cleanup

- [x] Remove dead code (`cmd/artifacts_runtime.go` and related wiring).
- [x] Remove obsolete CLI/runtime flags if superseded.
- [x] Regenerate/refresh all affected golden snapshots.
- [x] Run full test suite and targeted end-to-end validations.

## Spec Status

All previously open design items are now resolved and this plan is implementation-ready.
