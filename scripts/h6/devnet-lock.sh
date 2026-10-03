#!/usr/bin/env bash
# Optional shared-host serialization. Dedicated hosts do not need this helper.
# Usage: H6_BASE=/operator/chosen/shared-directory bash scripts/h6/devnet-lock.sh OWNER COMMAND [ARG...]
# All operators using the same fixture ports must use the same H6_BASE.
set -eo pipefail
: "${H6_BASE:?choose an absolute shared directory in H6_BASE}"
[ "$#" -ge 2 ] || { echo 'usage: devnet-lock.sh OWNER COMMAND [ARG...]' >&2; exit 2; }
case "$H6_BASE" in /*) ;; *) echo 'H6_BASE must be absolute' >&2; exit 2 ;; esac
[ -d "$H6_BASE" ] && [ -w "$H6_BASE" ] || { echo 'H6_BASE must exist and be writable' >&2; exit 2; }
lock_dir="$H6_BASE/.h6-devnet-lock"
owner=$1
shift
until mkdir "$lock_dir" 2>/dev/null; do
  [ -d "$lock_dir" ] || { echo "cannot create lock: $lock_dir" >&2; exit 1; }
  printf 'devnet busy (%s); waiting...\n' "$(cat "$lock_dir/owner" 2>/dev/null || echo unknown)"
  sleep 5
done
cleanup() {
  rm -f "$lock_dir/pid" "$lock_dir/owner"
  rmdir "$lock_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s\n' "$owner" > "$lock_dir/owner"
printf '%s\n' "$$" > "$lock_dir/pid"
"$@"
