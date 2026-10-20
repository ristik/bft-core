#!/usr/bin/env bash
# Usage: scripts/ci/devnet-lock.sh <owner> <command...>
# The repository copy of briefs/devnet-lock.sh (same semantics): serializes paired-devnet runs (shared ports + CPU). Waits for the lock; releases it on exit.
# The lock directory is $DEVNET_LOCK_DIR, else $AGRE_ROOT/.devnet-lock, else <repo parent>/.devnet-lock (what the lanes' own default expects), so a Mac and a CI
# runner use the same convention with their own roots. One devnet per VM on a runner: the lock only ever protects a second command of the same job.
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
L=${DEVNET_LOCK_DIR:-${AGRE_ROOT:-$(cd "$here/../../.." && pwd)}/.devnet-lock}
owner=$1; shift
until mkdir "$L" 2>/dev/null; do
  if [ -f "$L/pid" ] && ! kill -0 "$(cat "$L/pid")" 2>/dev/null; then echo "stale lock from $(cat "$L/owner" 2>/dev/null); removing"; rm -rf "$L"; continue; fi
  echo "devnet busy ($(cat "$L/owner" 2>/dev/null)); waiting..."; sleep 30
done
echo "$owner" > "$L/owner"; echo $$ > "$L/pid"
trap 'rm -rf "$L"' EXIT INT TERM
"$@"
