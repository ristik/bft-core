#!/usr/bin/env bash
# Run the F8 live lane only when the shared devnet lock is free.
set -euo pipefail
cd "$(dirname "$0")/.."

LOCK=/Users/risto/uni/agre/.devnet-lock
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "devnet lock is occupied ($(cat "$LOCK/owner" 2>/dev/null || echo unknown)); refusing to wait or alter it" >&2
  exit 3
fi
printf '%s\n' "f8-mixed-lane-acceptance" >"$LOCK/owner"
printf '%s\n' "$$" >"$LOCK/pid"
cleanup_lock() {
  if [ "$(cat "$LOCK/pid" 2>/dev/null || true)" = "$$" ]; then rm -rf "$LOCK"; fi
}
trap cleanup_lock EXIT INT TERM

[ -n "${RUGREGATOR_BIN:-}" ] || { echo "set RUGREGATOR_BIN to the binary built from 662e37a56e6da67fcb67aa4ebc32be5076bc301c" >&2; exit 2; }
[ -n "${RUGREGATOR_SOURCE:-}" ] || { echo "set RUGREGATOR_SOURCE to the pinned rugregator checkout" >&2; exit 2; }
[ "$(git -C "$RUGREGATOR_SOURCE" rev-parse HEAD)" = 662e37a56e6da67fcb67aa4ebc32be5076bc301c ] || {
  echo "RUGREGATOR_SOURCE is not at the F8 pinned revision" >&2; exit 2;
}

F8_MIXED_LANE=1 M2_PROFILE2=1 scripts/reth-paired-devnet.sh 4 10
