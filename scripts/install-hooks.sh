#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(CDPATH='' cd -- "${script_dir}/.." && pwd)"
hooks_dir="${project_root}/.git/hooks"

if [[ ! -d "${project_root}/.git" ]]; then
	printf 'install-hooks: %s is not a Git working tree\n' "$project_root" >&2
	exit 1
fi

mkdir -p "$hooks_dir"

printf 'Installing go-pdns-ui Git hooks...\n'

cat >"${hooks_dir}/pre-push" <<'HOOKEOF'
#!/usr/bin/env bash
# Pre-push hook for go-pdns-ui.
# Runs govulncheck before publishing main or version tags.

set -euo pipefail

git_root="$(git rev-parse --show-toplevel)"
exec "${git_root}/scripts/pre-push-govulncheck.sh" "$@"
HOOKEOF

chmod +x "${hooks_dir}/pre-push"
chmod +x "${project_root}/scripts/pre-push-govulncheck.sh"

printf 'Git hooks installed successfully.\n\n'
printf 'The pre-push hook runs govulncheck before pushing main or version tags.\n'
printf 'Run make release-guardrails for the complete manual release gate.\n'
