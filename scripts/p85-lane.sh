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
source "$SCRIPT_DIR/lib/portable.sh"
AGRE_ROOT=$(lane_agre_root)
LOCK_SCRIPT=$(lane_lock_script)
EVIDENCE_DIR=${P85_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/${P85_EVIDENCE_PREFIX:-p85}-$(date -u +%Y%m%dT%H%M%SZ)}
# The any-age final lane (scripts/anyage-lane.sh) is this runner with ANYAGE_LANE=1: its own lock owner and evidence prefix, nothing else differs here.
LOCK_OWNER=${P85_LOCK_OWNER:-p85-recovery}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

[ -n "${P85_CONTRACTS:-}" ] && [ -x "$P85_CONTRACTS/script/p85-genesis.sh" ] || fail "set P85_CONTRACTS to a unicity-pos-contracts checkout"
export PATH="$HOME/.foundry/bin:$PATH"
command -v forge >/dev/null && command -v cast >/dev/null || fail "forge and cast must be installed"
[ -n "${M2_URETH_BIN:-}" ] && [ -x "$M2_URETH_BIN" ] || fail "set M2_URETH_BIN to a ureth build carrying the fresh-B1 profile (--unicity.* bindings)"
[ -n "${M2_URETH_COMMIT:-}" ] || fail "set M2_URETH_COMMIT to the ureth source commit"
# the pin helpers compare commits for equality: resolve the given commit (full or abbreviated) to the full one the binary reports, here,
# before the lock is taken, so a pin the lane's later steps would refuse costs no lock slot
reported=$("$M2_URETH_BIN" --version 2>&1 | sed -n 's/^Commit SHA: //p' | head -1)
case "$reported" in *[!0-9a-f]*|"") fail "M2_URETH_BIN reports no commit" ;; esac
[ "${#reported}" = 40 ] && [ "${reported#"$M2_URETH_COMMIT"}" != "$reported" ] || fail "M2_URETH_BIN does not report the commit $M2_URETH_COMMIT (it reports $reported)"
M2_URETH_COMMIT=$reported
export M2_URETH_COMMIT URETH_PIN_COMMIT=$reported

# An evidence run names its attested binary: the provenance directory (commit.txt, sha256.txt) must record this very commit and this very binary, and the
# checkout must be clean with build/ubft built from its HEAD. Checked here, before the lock. P85_DEV_RUN=1 is a development run: it skips them and says so.
if [ "${P85_DEV_RUN:-0}" = 1 ]; then
  RUN_MODE="DEVELOPMENT RUN, NOT EVIDENCE: the binary and the checkout are not verified against a provenance record (P85_DEV_RUN=1)"
else
  PROVENANCE=${M2_URETH_ATTESTED_PROVENANCE:-$AGRE_ROOT/briefs/builds/ureth-${M2_URETH_COMMIT:0:8}}
  [ -s "$PROVENANCE/sha256.txt" ] && [ -s "$PROVENANCE/commit.txt" ] || fail "no attested provenance at $PROVENANCE (commit.txt, sha256.txt): set M2_URETH_ATTESTED_PROVENANCE, or P85_DEV_RUN=1 for a development run"
  [ "$(tr -d '[:space:]' <"$PROVENANCE/commit.txt")" = "$M2_URETH_COMMIT" ] || fail "the provenance commit.txt is not $M2_URETH_COMMIT"
  attested=$(awk '{print $1; exit}' "$PROVENANCE/sha256.txt")
  got=$(shasum -a 256 "$M2_URETH_BIN" | cut -d' ' -f1)
  [ "$got" = "$attested" ] || fail "M2_URETH_BIN sha256 $got is not the attested $attested (provenance $PROVENANCE)"
  [ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ] || fail "the checkout has uncommitted changes: an evidence run needs a clean one"
  [ -x "$REPO_ROOT/build/ubft" ] || fail "build/ubft is missing (make build)"
  head=$(git -C "$REPO_ROOT" rev-parse HEAD)
  lane_buildinfo "$REPO_ROOT/build/ubft" | grep -q "vcs.revision=$head" || fail "build/ubft is not built from HEAD $head (make build)"
  ! lane_buildinfo "$REPO_ROOT/build/ubft" | grep -q 'vcs.modified=true' || fail "build/ubft was built from a modified tree"
  RUN_MODE="RUN MODE: evidence run: attested prebuilt Ureth $M2_URETH_BIN sha256=$got commit=$M2_URETH_COMMIT (provenance $PROVENANCE); everything else from this checkout at $head"
fi

if [ "${P85_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "$LOCK_OWNER" env P85_LANE_LOCKED=1 P85_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"
# the pids of this run (the lock wrapper that holds the lock, and this runner): scripts/p85-stop.sh stops THIS run from them, never by a name pattern
printf '%s %s\n' "$PPID" "$$" >"$EVIDENCE_DIR/.runner-pids"
[ -x build/ubft ] || fail "build/ubft is missing (make build)"
echo "$RUN_MODE" | tee "$EVIDENCE_DIR/run-mode.txt"
[ -z "${PROVENANCE:-}" ] || cp -R "$PROVENANCE" "$EVIDENCE_DIR/ureth-provenance"
host_evidence before "$(host_evidence_file "$EVIDENCE_DIR" before)"
echo "bft-core head=$(git rev-parse HEAD) ureth=$M2_URETH_COMMIT ubft sha256=$(shasum -a 256 build/ubft | cut -d' ' -f1)" | tee "$EVIDENCE_DIR/heads.txt"
if [ "${ANYAGE_LANE:-0}" = 1 ]; then
  echo "contracts head=$(git -C "$P85_CONTRACTS" rev-parse HEAD) nbp head=$(git -C "${NBP_DIR:?set NBP_DIR}" rev-parse HEAD) aggregator sha256=$(shasum -a 256 "${AGG_BIN:?set AGG_BIN}" | cut -d' ' -f1) dnb-tool sha256=$(shasum -a 256 "${DNB_TOOL:?set DNB_TOOL}" | cut -d' ' -f1)" | tee -a "$EVIDENCE_DIR/heads.txt"
fi

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
export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1 P85_LANE=1 H3_RESTART_TOGETHER=1 P85_CONTRACTS M2_ROOT_FLAGS_FN=p85_root_flags
# P85_SHADOW=1 (X4 #58): the same genesis and devnet with the records hook and NO authoritative election; scripts/x4-shadow-steps.sh runs the shadow adapter
# against it with a scripted eligibility scenario instead of the recovery steps
export P85_SHADOW=${P85_SHADOW:-0}
[ "$P85_SHADOW" != 1 ] || [ "${ANYAGE_LANE:-0}${UTB_LANE:-0}${REWARD_LANE:-0}" = 000 ] || fail "P85_SHADOW=1 does not combine with the any-age, UTB or reward lanes"
# X4_REWARDS=1 (X4 step B3): the shadow chain (records hook, no election) with a SMALL reward allocation, so the pool runs dry; the reward steps of scripts/x4pos run on it
export X4_REWARDS=${X4_REWARDS:-0}
[ "$X4_REWARDS" != 1 ] || [ "$P85_SHADOW" = 1 ] || fail "X4_REWARDS=1 needs P85_SHADOW=1"
[ "$X4_REWARDS" != 1 ] || export P85_REWARD_FUNDING=${P85_REWARD_FUNDING:-2000000000000000000}
export ANYAGE_LANE=${ANYAGE_LANE:-0} UTB_LANE=${UTB_LANE:-0} EVIDENCE_LANE_LOG="$EVIDENCE_DIR/lane.log"
# the roots judge an assignment's committee continuity by the budget committed in the installed EVM configuration; it must be the one the election
# was priced under (the contracts' genesis parameter): adding a unit-weight joiner to four unit-weight members is D = 2/5, over the 1/4 default
export P85_DIST_NUM=${P85_DIST_NUM:-1} P85_DIST_DEN=${P85_DIST_DEN:-2}
export EVM_PARTITION_PARAMS_EXTRA=${EVM_PARTITION_PARAMS_EXTRA:-continuity_max_distance=$P85_DIST_NUM/$P85_DIST_DEN}

# archive replicas are derived by the node (#751): every P85 lane runs the default policy; EVM_ARCHIVE_DERIVED= (empty) restores the legacy fixed pairs
export EVM_ARCHIVE_DERIVED=${EVM_ARCHIVE_DERIVED-1}
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
# the execution side's logs only (never its data or keys: the publisher excludes evm*/ reth*/ whole): the last 4000 lines of each validator's node and client log, for a transaction that was never mined
mkdir -p "$EVIDENCE_DIR/exec-logs"
for f in test-nodes/evm*/debug.log test-nodes/reth*/reth.log; do [ -f "$f" ] && tail -n 4000 "$f" >"$EVIDENCE_DIR/exec-logs/$(basename "$(dirname "$f")")-$(basename "$f")" 2>/dev/null; done
# diagnosis of the validator-1 archive stall (bft-core#856 run 4): the non-spam WARN/ERROR/archive/frontier/journal/restart lines of every node from the START, not only the tail
for f in test-nodes/evm*/debug.log; do [ -f "$f" ] && grep -a "level=WARN\|level=ERROR\|archive replica\|frontier\|journal\|recover\|starting\|started" "$f" | grep -av "archive recovery source rejected" | head -n 8000 >"$EVIDENCE_DIR/exec-logs/$(basename "$(dirname "$f")")-filtered.log" 2>/dev/null; done
if [ "$ANYAGE_LANE" = 1 ]; then mkdir -p "$EVIDENCE_DIR/aggregator"; for d in test-nodes/agg test-nodes/agg[0-9]; do [ -d "$d" ] && { mkdir -p "$EVIDENCE_DIR/aggregator/$(basename "$d")"; cp "$d"/stdout.log "$d"/logs/*.log "$EVIDENCE_DIR/aggregator/$(basename "$d")/" 2>/dev/null || true; }; done; cp test-nodes/lane-config.json test-nodes/bridge-addresses.json "$EVIDENCE_DIR/" 2>/dev/null || true; fi
# what the lane's helpers read, kept so a failure can be replayed offline (go run ./scripts/h3-pdr, the weight checks, the trust-base tools): the roots'
# databases and public node info, the trust bases, the lane's flow directories; not the execution clients' data, the authorities' credentials or keys
rsync -a --exclude 'reth*/' --exclude 'evm*/' --exclude 'auth*/' --exclude '*.log' --exclude 'keys.json' --exclude '*.sock' --exclude '*.cred' \
  --exclude 'jwt.hex' --exclude 'p85/' test-nodes/ "$EVIDENCE_DIR/state/" 2>/dev/null || true
host_evidence after "$(host_evidence_file "$EVIDENCE_DIR" after)"
(cd "$EVIDENCE_DIR" && find . -type f ! -name SHA256SUMS ! -name '.devnet-pid' | LC_ALL=C sort | xargs shasum -a 256 >SHA256SUMS) || true
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "P85 recovery lane failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
if [ -n "${ANYAGE_PREP_ONLY:-}" ]; then
  grep -q '^anyage prep only:' "$EVIDENCE_DIR/lane.log" || fail "the prep-only run did not reach its end"
  pass "any-age prep-only run complete (nothing was started); inputs in $EVIDENCE_DIR/state"
  exit 0
fi
if [ "$P85_SHADOW" = 1 ]; then
  if [ "$X4_REWARDS" = 1 ]; then
    grep -q 'X4 rewards lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "the rewards lane ended without completing its steps (see $EVIDENCE_DIR/p85/run/x4pos)"
    pass "X4 rewards lane complete; evidence in $EVIDENCE_DIR (p85/run/x4pos)"
    exit 0
  fi
  grep -q 'X4 shadow lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "the shadow lane ended without completing its steps or without a PASS from the adapter (see $EVIDENCE_DIR/p85/run/shadow/REPORT.md)"
  pass "X4 shadow lane complete; evidence in $EVIDENCE_DIR (adapter report in p85/run/shadow)"
  exit 0
fi
grep -q 'P85 recovery lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing its steps"
[ "$ANYAGE_LANE" != 1 ] || grep -q 'any-age final lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "the any-age checkpoints did not complete"
[ "${UTB_LANE:-0}" != 1 ] || grep -q 'UTB lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "the UTB checkpoints did not complete"
pass "P85 recovery lane complete; evidence in $EVIDENCE_DIR"
