#!/usr/bin/env bash
# P85 slice 7 lane (briefs/p85-recovery-lane.md): a proof-of-stake genesis on the fresh-B1 layout (custody, election, evidence in the EVM genesis;
# four bonded entities), a joiner entity onboarded through the live contracts, the hook-driven election of J = K + joiner, the EVM possession proofs
# signed by the signing authorities, the V3 handoff with the v4 Freeze, J stalling with its joiner and one retained member down, and the derived
# recovery back to K. Every step prints PASS or FAIL. Runs under briefs/devnet-lock.sh.
#
#   P85_CONTRACTS=<unicity-pos-contracts checkout> M2_URETH_BIN=<ureth with the records hook and elect> M2_URETH_COMMIT=<its commit> scripts/p85-lane.sh
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${P85_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/p85-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

[ -n "${P85_CONTRACTS:-}" ] && [ -x "$P85_CONTRACTS/script/p85-genesis.sh" ] || fail "set P85_CONTRACTS to a unicity-pos-contracts checkout"
export PATH="$HOME/.foundry/bin:$PATH"
command -v forge >/dev/null && command -v cast >/dev/null || fail "forge and cast must be installed"
[ -n "${M2_URETH_BIN:-}" ] && [ -x "$M2_URETH_BIN" ] || fail "set M2_URETH_BIN to a ureth build carrying the fresh-B1 profile (--unicity.* bindings)"
[ -n "${M2_URETH_COMMIT:-}" ] || fail "set M2_URETH_COMMIT to the ureth source commit"
"$M2_URETH_BIN" --version 2>&1 | grep -Fq "Commit SHA: $M2_URETH_COMMIT" || fail "M2_URETH_BIN does not report the commit $M2_URETH_COMMIT"

if [ "${P85_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "p85-recovery" env P85_LANE_LOCKED=1 P85_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"
[ -x build/ubft ] || fail "build/ubft is missing (make build)"
echo "bft-core head=$(git rev-parse HEAD) ureth=$M2_URETH_COMMIT ubft sha256=$(shasum -a 256 build/ubft | cut -d' ' -f1)" | tee "$EVIDENCE_DIR/heads.txt"

# A signal to the lane stops the scenario child and waits for its own teardown (an orphaned child keeps restarting nodes in this checkout).
DEVNET_PIDFILE=
stop_devnet() {
  local pid i
  [ -n "$DEVNET_PIDFILE" ] && [ -s "$DEVNET_PIDFILE" ] || return 0
  pid=$(cat "$DEVNET_PIDFILE")
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -KILL "$pid" 2>/dev/null || true
}
trap stop_devnet EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# the single B1 layout: one B1 profile derived from the shard configuration and the root trust base; the registry slots are read under the layout-3 names;
# every shard node exposes its operator endpoint (the readiness check asks it what it has staged)
export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1 P85_LANE=1 P85_CONTRACTS
# the roots judge an assignment's committee continuity by the budget committed in the installed EVM configuration; it must be the one the election
# was priced under (the contracts' genesis parameter): adding a unit-weight joiner to four unit-weight members is D = 2/5, over the 1/4 default
export P85_DIST_NUM=${P85_DIST_NUM:-1} P85_DIST_DEN=${P85_DIST_DEN:-2}
export EVM_PARTITION_PARAMS_EXTRA=${EVM_PARTITION_PARAMS_EXTRA:-continuity_max_distance=$P85_DIST_NUM/$P85_DIST_DEN}

set +e
DEVNET_PIDFILE="$EVIDENCE_DIR/.devnet-pid"; rm -f "$DEVNET_PIDFILE"
( set -o pipefail
  EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} M2_PROFILE2=1 SIGNING=authority \
    POST_M2A_URETH_BIN="$M2_URETH_BIN" POST_M2A_URETH_COMMIT="$M2_URETH_COMMIT" \
    M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" \
    bash -c 'echo $$ >"$0"; exec bash ./scripts/reth-paired-devnet.sh 4 10' "$DEVNET_PIDFILE" 2>&1 | tee "$EVIDENCE_DIR/lane.log" ) &
wait "$!"
status=$?
set -e
rm -f "$DEVNET_PIDFILE"
cp -R test-nodes/p85 "$EVIDENCE_DIR/p85" 2>/dev/null || true
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "P85 recovery lane failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'P85 recovery lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing its steps"
pass "P85 recovery lane complete; evidence in $EVIDENCE_DIR"
