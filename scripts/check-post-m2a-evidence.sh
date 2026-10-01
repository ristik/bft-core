#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

syntax_files=(
  scripts/check-post-m2a-evidence.sh
  scripts/f7-mintproof-evidence.sh
  scripts/t1-vesting-claim-evidence.sh
  scripts/t4-post-m2a-audit-evidence.sh
  scripts/m2-replacement-client-lane.sh
  scripts/post-m2a-evidence-lib.sh
  scripts/reth-paired-devnet.sh
  scripts/m2-profile2-handoffs.sh
  scripts/lib/reth-pin.sh
  start-evm.sh
)
lint_files=(
  scripts/check-post-m2a-evidence.sh
  scripts/f7-mintproof-evidence.sh
  scripts/t1-vesting-claim-evidence.sh
  scripts/t4-post-m2a-audit-evidence.sh
  scripts/post-m2a-evidence-lib.sh
  scripts/m2-replacement-client-lane.sh
)

bash -n ${syntax_files[@]+"${syntax_files[@]}"}
printf 'PASS: bash -n parsed the post-M2a evidence and lane-hook scripts\n'

shellcheck_bin=${SHELLCHECK:-shellcheck}
command -v "$shellcheck_bin" >/dev/null 2>&1 || {
  printf 'FAIL: shellcheck is required; install it and rerun %s\n' "$0" >&2
  exit 1
}
"$shellcheck_bin" --external-sources ${lint_files[@]+"${lint_files[@]}"}
printf 'PASS: shellcheck checked the post-M2a evidence runners and helpers\n'
