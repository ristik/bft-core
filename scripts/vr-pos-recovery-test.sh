#!/usr/bin/env bash
# Exercises archive restore, ordinary restart, and K's serving check without starting nodes.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
source helper.sh
source scripts/lib/h3-lib.sh
source scripts/vr-pos-steps.sh

work=$(mktemp -d)
work=$(cd "$work" && pwd -P)
trap 'rm -rf -- "$work"' EXIT
cd "$work"

# The real restore helper clears these destinations before its stubbed node starts.
unset EVM_EXECUTION_JOURNAL_ROOT H3_RESTORE_SEED_DIR H3_RESTORE_SEED_BUNDLES
H3_ARCHIVES=$work/archives
EVM_ARCHIVE_ROOT=$H3_ARCHIVES
H3_RESTORE_TRUST_BASE=$work/test-nodes/trust-base.json
REGISTRY_LAYOUT_FILE=$work/test-nodes/registry-layout
EVM_B1_PROFILE=$work/test-nodes/b1-profile.json
EVM_GENESIS_FILE=$work/test-nodes/genesis.json
EVM_FULL_SHARD_CONF=$work/test-nodes/shard.json
VR_EVIDENCE=$work
UTB_LANE=0

journal=test-nodes/evm5/execution-journal.db
python3 - "$work" build/ubft test-nodes/evm5 test-nodes/reth5/dd \
  "$H3_ARCHIVES/evm5" "$EVM_ARCHIVE_ROOT/evm5" "$journal" "$journal"-* \
  "$H3_RESTORE_TRUST_BASE" "$REGISTRY_LAYOUT_FILE" "$EVM_B1_PROFILE" "$EVM_GENESIS_FILE" "$EVM_FULL_SHARD_CONF" <<'PY'
from pathlib import Path
import sys

work = Path(sys.argv[1])
for name in [*sys.argv[2:], *work.rglob("*")]:
    resolved = Path(name).resolve()
    if work not in resolved.parents:
        raise SystemExit(f"Refusing fixture path outside {work}: {name} resolves to {resolved}")
PY

mkdir -p build test-nodes/evm5
cat >build/ubft <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$2.argv"
SH
chmod +x build/ubft

lane_port_preflight() { :; }
stop_one_evm_validator() { :; }
stop_pidfile() { :; }
owned_pids() { :; }
h3_start_reth() { :; }
lane_go_run() { echo 'bodyID=test-pin'; }
m2_root_addr() { echo root; }
evm_bootnodes_for_peers() { echo peers; }
evm_validator_id() { echo "peer-$1"; }
registry_layout() { echo 3; }

SIGNING=authority
H3_RESTORE_NO_SESSION=1
H3_ROOTS='1 2 3 4'
H3_ONLINE='1 2 3 4'
EVM_ARCHIVE_DERIVED=1
EVM_ENGINE_FEE_COLLECTOR=test-collector
EVM_JOURNAL_CANDIDATES=4096
EVM_EXTRA_ARGS='--journal-observations 8192 --journal-bytes=134217728 --journal-candidates=2048 --log-level debug'
rethEngineBase=$(lane_port 18551)
rethEthBase=$(lane_port 18545)

h3_restore_validator 5 1 2>restore.stderr || { cat restore.stderr >&2; exit 1; }
wait "$(cat test-nodes/evm5/pid)"
start_one_evm_validator 5 4 8 root engine-api rpc peers
wait "$(cat test-nodes/evm5/pid)"

journal_args() {
  awk '/^--journal-(candidates|observations|bytes)=/ { print; next }
       /^--journal-(candidates|observations|bytes)$/ { flag=$0; getline; print flag "=" $0 }' "$1"
}
journal_args run.argv >run.limits
journal_args restore.argv >restore.limits
diff -u run.limits restore.limits
if grep -Fxq debug restore.argv; then
  echo 'FAIL: ordinary run logging overrides reached archive restore' >&2
  exit 1
fi
echo 'PASS: restore and restart use the same durable journal limits'

partitionID=8
health='{"executorOk":true,"voting":true,"binding":{"member":true,"nodeId":"peer-5","partitionId":8,"shardEpoch":3,"history":[{"epoch":4}]}}'
curl() { [ -n "$health" ] && printf '%s\n' "$health"; }
vrp_k_shard_serving 5
test -s evm5-k-health.json
if vrp_k_shard_serving 4; then
  echo 'FAIL: health for the wrong node was accepted' >&2
  exit 1
fi
health=$(jq '.binding.history[-1].epoch = 3' <<<"$health")
if vrp_k_shard_serving 5; then
  echo 'FAIL: a stale shard node was accepted' >&2
  exit 1
fi
health=$(jq '.binding.shardEpoch = 2' <<<"$health")
vrp_k_shard_serving 5 3 2
if vrp_k_shard_serving 5 3 3; then
  echo 'FAIL: a shard node at the wrong recovery shard epoch was accepted' >&2
  exit 1
fi
health=
if vrp_k_shard_serving 5; then
  echo 'FAIL: a missing shard node was accepted' >&2
  exit 1
fi
echo 'PASS: K requires a live shard node bound to the expected peer and epoch'
