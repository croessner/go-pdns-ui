#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

git_root="$(git rev-parse --show-toplevel)"
remote_name="${1:-origin}"
remote_url="${2:-}"

red=$'\033[0;31m'
green=$'\033[0;32m'
yellow=$'\033[1;33m'
reset=$'\033[0m'

triggered=0
refs=()
target_commits=()
zero_sha="0000000000000000000000000000000000000000"

ref_requires_govulncheck() {
	case "$1" in
	refs/heads/main | refs/tags/v*) return 0 ;;
	*) return 1 ;;
	esac
}

while read -r _local_ref local_sha remote_ref _remote_sha; do
	if [[ "$local_sha" == "$zero_sha" ]]; then
		continue
	fi

	if ref_requires_govulncheck "$remote_ref"; then
		target_commit="$(git rev-parse "${local_sha}^{commit}")"
		triggered=1
		refs+=("${remote_ref} -> ${target_commit:0:12}")
		target_commits+=("$target_commit")
	fi
done

if [[ "$triggered" -eq 0 ]]; then
	printf '%sNo release-sensitive refs in push; skipping govulncheck.%s\n' "$green" "$reset"
	exit 0
fi

cd "$git_root"

if [[ -n "$(git status --porcelain)" ]]; then
	printf '%sPush blocked: release-sensitive refs require a clean checkout.%s\n' "$red" "$reset"
	printf '%sCommit, stash, or remove local changes before pushing main or version tags.%s\n' "$red" "$reset"
	exit 1
fi

head_commit="$(git rev-parse HEAD)"
for target_commit in "${target_commits[@]}"; do
	if [[ "$target_commit" != "$head_commit" ]]; then
		printf '%sPush blocked: release-sensitive ref does not point to current HEAD.%s\n' "$red" "$reset"
		printf '%sCheck out the pushed main or tag commit before pushing so govulncheck analyzes the right code.%s\n' "$red" "$reset"
		exit 1
	fi
done

printf '%sRunning govulncheck before pushing release-sensitive refs to %s...%s\n' "$yellow" "$remote_name" "$reset"
printf '  - %s\n' "${refs[@]}"

if ! make govulncheck; then
	printf '\n%sPush blocked: govulncheck failed for %s %s.%s\n' "$red" "$remote_name" "$remote_url" "$reset"
	printf '%sFix vulnerability findings before pushing main or version tags.%s\n' "$red" "$reset"
	exit 1
fi

printf '%sGovulncheck passed.%s\n' "$green" "$reset"
