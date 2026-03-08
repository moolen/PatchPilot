#!/usr/bin/env bash
set -euo pipefail

command="${INPUT_COMMAND:-fix}"
dir="${INPUT_DIR:-.}"
repo_url="${INPUT_REPO_URL:-}"
policy="${INPUT_POLICY:-}"
enable_agent="${INPUT_ENABLE_AGENT:-false}"
agent_command="${INPUT_AGENT_COMMAND:-codex}"
agent_max_attempts="${INPUT_AGENT_MAX_ATTEMPTS:-5}"
extra_args="${INPUT_EXTRA_ARGS:-}"
acceptable_exit_codes="${INPUT_ACCEPTABLE_EXIT_CODES:-0}"

case "${command}" in
scan|fix|verify)
	;;
*)
	echo "unsupported command: ${command} (expected scan|fix|verify)" >&2
	exit 2
	;;
esac

args=()
if [[ -n "${repo_url}" ]]; then
	args+=(--repo-url "${repo_url}")
elif [[ -n "${dir}" ]]; then
	args+=(--dir "${dir}")
fi
if [[ -n "${policy}" ]]; then
	args+=(--policy "${policy}")
fi
if [[ "${command}" == "fix" ]]; then
	args+=(--enable-agent="${enable_agent}")
	args+=(--agent-command "${agent_command}")
	args+=(--agent-max-attempts "${agent_max_attempts}")
fi
if [[ -n "${extra_args}" ]]; then
	# shellcheck disable=SC2206
	extra=( ${extra_args} )
	args+=("${extra[@]}")
fi

set +e
cvefix "${command}" "${args[@]}"
exit_code=$?
set -e

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
	echo "exit-code=${exit_code}" >> "${GITHUB_OUTPUT}"
fi

IFS=',' read -r -a acceptable_codes <<< "${acceptable_exit_codes}"
for value in "${acceptable_codes[@]}"; do
	code="$(echo "${value}" | xargs)"
	if [[ "${code}" == "${exit_code}" ]]; then
		exit 0
	fi
done

exit "${exit_code}"
