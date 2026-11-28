#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/ingress-loss-window.sh

Q4_SHIM_DIR=$(mktemp -d)
trap 'rm -rf -- "$Q4_SHIM_DIR"' EXIT
for i in 1 2 3 4 5; do
  mkdir "$Q4_SHIM_DIR/root$i"
  touch "$Q4_SHIM_DIR/root$i/shard-trace.jsonl"
done

hash=$(printf '%064x' 1)
event() {
  local root=$1 seq=$2 kind=$3 node=$4 rule=${5:-}
  printf '{"seq":%s,"time":"2026-11-27T17:11:%02dZ","kind":"%s","direction":"in","type":"request","partition":8,"round":6,"blockHash":"%s","node":"%s","rule":"%s"}\n' \
    "$seq" "$seq" "$kind" "$hash" "$node" "$rule" >>"$Q4_SHIM_DIR/root$root/shard-trace.jsonl"
}

# One match at each of three roots and a retry that escaped the gate.
for i in 1 2 3; do
  event "$i" 1 in "node$i"
  event "$i" 2 drop "node$i" evm-loss
done
event 3 3 in node3
if loss_drop_seen; then
  echo 'FAIL: cross-root drops hid an arrival without a drop' >&2
  exit 1
fi

# Even an ingress with a local quorum cannot hide the unmatched retry elsewhere.
event 1 3 in node2
event 1 4 drop node2 evm-loss
event 1 5 in node3
event 1 6 drop node3 evm-loss
if loss_drop_seen; then
  echo 'FAIL: a per-root quorum hid an arrival without a drop at another root' >&2
  exit 1
fi

event 3 4 drop node3 evm-loss
[[ $(loss_drop_seen) == $'6\t'"$hash"$'\t'* ]]

# The final check also covers late deliveries after opening fresh ingress.
event 2 3 in node2
if python3 scripts/ingress-loss-evidence.py audit-drops "$Q4_SHIM_DIR" 6 "$hash"; then
  echo 'FAIL: the final audit missed an undropped late retry' >&2
  exit 1
fi
event 2 4 drop node2 lost-round
python3 scripts/ingress-loss-evidence.py audit-drops "$Q4_SHIM_DIR" 6 "$hash"
echo 'PASS: selected arrivals and retries require per-root drop events'
