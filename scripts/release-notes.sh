#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
	cat <<'USAGE'
Usage: scripts/release-notes.sh <release-tag> <output-file> [previous-tag]

Create a Markdown commit summary for a GitHub release. Every non-merge commit
is assigned to exactly one project commit-prefix category. Historical
Conventional Commit subjects are recognized during the format transition.
USAGE
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
	usage >&2
	exit 1
fi

release_tag="$1"
output_file="$2"
previous_tag="${3:-}"

git rev-parse --verify "${release_tag}^{commit}" >/dev/null
if [[ -n "$previous_tag" ]]; then
	git rev-parse --verify "${previous_tag}^{commit}" >/dev/null
	revision_range="${previous_tag}..${release_tag}"
else
	revision_range="$release_tag"
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

for category in added changed fixed removed refactored tests documentation build_ci security dependencies chores other; do
	: >"${work_dir}/${category}"
done

while IFS=$'\t' read -r commit_hash subject || [[ -n "$commit_hash" ]]; do
	[[ -n "$commit_hash" ]] || continue
	normalized_subject="$(printf '%s' "$subject" | tr '[:upper:]' '[:lower:]')"
	category=other

	case "$normalized_subject" in
	add:* | add\ * | feat:* | feat\(*\):*) category=added ;;
	change:* | change\ *) category=changed ;;
	fix:* | fix\ * | fix\(*\):*) category=fixed ;;
	remove:* | remove\ *) category=removed ;;
	refactor:* | refactor\ * | refactor\(*\):*) category=refactored ;;
	test:* | test\ * | test\(*\):*) category=tests ;;
	docs:* | docs\ * | docs\(*\):*) category=documentation ;;
	build:* | build\ * | build\(*\):* | ci:* | ci\ * | ci\(*\):* | make:* | make\ *) category=build_ci ;;
	security:* | security\ * | security\(*\):*) category=security ;;
	vendor:* | vendor\ * | bump\ * | chore:*dependenc* | chore\(*\):*dependenc*) category=dependencies ;;
	chore:* | chore\ * | chore\(*\):*) category=chores ;;
	esac

	printf -- '- %s (%s)\n' "$subject" "$commit_hash" >>"${work_dir}/${category}"
done < <(git log "$revision_range" --pretty=format:'%h%x09%s' --no-merges)

append_section() {
	local title="$1"
	local category="$2"
	local category_file="${work_dir}/${category}"

	if [[ ! -s "$category_file" ]]; then
		return
	fi

	{
		printf '### %s\n' "$title"
		cat "$category_file"
		printf '\n'
	} >>"$output_file"
}

printf '## Commit Summary\n\n' >"$output_file"
append_section "Added" added
append_section "Changed" changed
append_section "Fixed" fixed
append_section "Removed" removed
append_section "Refactored" refactored
append_section "Tests" tests
append_section "Documentation" documentation
append_section "Build And CI" build_ci
append_section "Security" security
append_section "Dependencies" dependencies
append_section "Chores" chores
append_section "Other Commits" other
