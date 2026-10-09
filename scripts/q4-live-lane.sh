#!/usr/bin/env bash
# Q4 #51 live lane (briefs/q4-design-v2.md section 6) on the fresh-B1 stack: REAL-PROCESS representatives of the weighted fault matrix on the paired devnet with F8's
# three aggregator shards, through the root fault shim (build/q4shim/ubft) and F8's callbacks. ONE devnet run: the Q3 weight-activation flow first (fresh-B1 unit
# PoA -> ONE coupled handoff to mirrored weights 6,1,1,1: scheme 2, weighted EVM requests, root-wrr-v1), then the Q4 fault rows in the activated weighted epoch.
# The gate (Q4_WEIGHTED_CHECK) is a function of the Q3 flow library that reads the activated epoch from the root's own verified state; the evidence keeps its
# command, output and exit status. Serialized with every other devnet run by briefs/devnet-lock.sh.
#
#   scripts/q4-live-lane.sh --dry-run        # no lock, no build, no process, no network: pins, steps, self-tests
#   Q4_BFT_COMMIT=<sha> Q4_URETH_COMMIT=<sha> RUGREGATOR_BIN=<F8 pin> RUGREGATOR_SOURCE=<F8 pin checkout> scripts/q4-live-lane.sh
#
# Pins have NO defaults. The run refuses a checkout that is not exactly the pinned bft-core commit with a clean tree, builds ubft and the q4shim binary from it,
# and builds ureth from the pinned commit in a fresh private target (Q4_URETH_BIN may name a prebuilt one; then the run is a DEVELOPMENT OVERRIDE and is not
# acceptance evidence unless Q4_URETH_FRESH_BUILD=1 attests that the operator built it from a fresh private target at exactly that commit).
# Teardown is ownership-checked (helper.sh owned_pid/stop_pidfile, never pkill); the devnet lock is released by briefs/devnet-lock.sh's own trap.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${Q4_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/q4-live-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

DRY_RUN=${Q4_LANE_DRY_RUN:-0}
for a in "$@"; do case "$a" in --dry-run) DRY_RUN=1 ;; *) fail "unknown argument: $a" ;; esac; done

cd "$REPO_ROOT"
# the lane's EXIT trap: capture the body's status FIRST (a cleanup step that succeeds would otherwise replace it with 0 and hide a failure or the BLOCKED exit 3)
LANE_EXIT_TRAP='s=$?; remove_isolation_root; (exit $s); cleanup'
REQUIRED_PINS="Q4_BFT_COMMIT Q4_URETH_COMMIT RUGREGATOR_BIN RUGREGATOR_SOURCE"

if [ "$DRY_RUN" = 1 ]; then
  # definitions only: nothing below starts a process
  # shellcheck source=/dev/null
  source helper.sh
  export Q3_LANE_DEFINE_ONLY=1 Q4_LANE_DEFINE_ONLY=1
  # shellcheck source=/dev/null
  source scripts/q4-live-steps.sh
  unset Q3_LANE_DEFINE_ONLY Q4_LANE_DEFINE_ONLY
  status=0
  echo "=== Q4 #51 live lane: DRY RUN (no lock, no build, no process, no network) ==="
  echo "bft-core head: $(git rev-parse HEAD)  tree: $([ -z "$(git status --porcelain)" ] && echo clean || echo DIRTY)"
  echo "--- required pins (a real run refuses if any is unset; there are no defaults)"
  for v in $REQUIRED_PINS; do printf '  %-20s %s\n' "$v" "${!v:-<unset>}"; done
  echo "--- the activation prefix (the Q3 flow library, fresh-B1 stack) and the Q4 rows, in order"
  for s in $Q4_ACTIVATION_STEPS $Q4_PRE_FAULT_STEPS; do printf '  %s\n' "$s"; done
  grep -o 'q4_step "[^"]*"' scripts/q4-live-steps.sh | sed 's/^q4_step /  /'
  echo "--- the weighted-epoch gate: Q4_WEIGHTED_CHECK=${Q4_WEIGHTED_CHECK:-q4_weighted_epoch_check} (a function of the Q3 flow library; its command, output and exit are kept in weighted-check.txt)"
  echo "--- self-tests"
  d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
  q4_selftest_docs "$d"
  [ "$(ls "$d" | wc -l)" -eq 4 ] || { echo "self-test: the control documents were not written" >&2; status=1; }
  for f in "$d"/*.json; do jq -e . "$f" >/dev/null || { echo "self-test: $f is not JSON" >&2; status=1; }; done
  q3_selftest || status=1
  bash -n scripts/q4-live-steps.sh scripts/q4-live-lane.sh scripts/lib/q4-lib.sh scripts/lib/q3-lib.sh scripts/lib/q3-flow-lib.sh && echo "  bash -n: ok" || status=1
  python3 scripts/q4-trace-check.py --help >/dev/null && echo "  trace checker runs" || status=1
  # information only: the helper lives beside the checkout (briefs/), not in it; a real run refuses without it
  [ -x "$LOCK_SCRIPT" ] && echo "  devnet lock helper present: $LOCK_SCRIPT (not taken)" || echo "  devnet lock helper not present at $LOCK_SCRIPT (information only; a real run refuses without it)"
  # the lane's exit status must survive its own EXIT cleanup (a body that fails with 1 or is BLOCKED with 3 must leave the lane with exactly that status)
  for want in 0 1 3; do
    got=$(bash -c 'cleanup() { local s=$?; exit "$s"; }; remove_isolation_root() { :; }; trap "$1" EXIT; exit "$2"' _ "$LANE_EXIT_TRAP" "$want" >/dev/null 2>&1; echo $?)
    [ "$got" = "$want" ] && echo "  exit-status self-test: a body exiting $want leaves the lane with $got: ok" || { echo "  exit-status self-test: a body exiting $want left the lane with $got" >&2; status=1; }
  done
  [ "$status" -eq 0 ] && echo "Q4 live lane dry run: OK (the devnet lane itself was NOT run)" || echo "Q4 live lane dry run: FAILED" >&2
  exit "$status"
fi

# ---- real run -------------------------------------------------------------------------------------------------------------------------------
for v in $REQUIRED_PINS; do [ -n "${!v:-}" ] || fail "set $v (no defaults: the lane runs only against exactly pinned artifacts)"; done
[ "$(git rev-parse HEAD)" = "$Q4_BFT_COMMIT" ] || fail "checkout HEAD $(git rev-parse HEAD) is not the pinned Q4_BFT_COMMIT $Q4_BFT_COMMIT"
[ -z "$(git status --porcelain)" ] || fail "the checkout is not clean: a pinned run needs exactly the pinned source"
[ -x "$RUGREGATOR_BIN" ] || fail "RUGREGATOR_BIN is not executable"
# shellcheck source=/dev/null
. scripts/f8-rugregator-pin.sh
[ "$(git -C "$RUGREGATOR_SOURCE" rev-parse HEAD)" = "$F8_RUGREGATOR_PIN" ] || fail "RUGREGATOR_SOURCE is not at the F8 pin $F8_RUGREGATOR_PIN"

if [ "${Q4_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "Q4 #51 live lane (dev3)" env Q4_LANE_LOCKED=1 Q4_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
mkdir -p "$EVIDENCE_DIR"
export Q4_EVIDENCE_DIR="$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"

# Ownership-checked cleanup on every exit: this checkout's processes only. The scenario runs in a child that restarts nodes on its own, so a signal to the
# lane must reach it and cleanup must wait for its own teardown first.
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
cleanup() { local s=$?; stop_devnet; ( source helper.sh; source scripts/lib/q3-lib.sh; q3_teardown ) >/dev/null 2>&1 || true; exit "$s"; }
ISOLATION_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/q4-lane.XXXXXX")
remove_isolation_root() { [ -n "${ISOLATION_ROOT:-}" ] && [ -d "$ISOLATION_ROOT" ] || return 0; chmod -R u+w "$ISOLATION_ROOT" 2>/dev/null || true; rm -rf "$ISOLATION_ROOT"; }
trap "$LANE_EXIT_TRAP" EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
avail=$(df -Pk "$ISOLATION_ROOT" | awk 'NR==2 {print $4}')
[ -n "${Q4_URETH_BIN:-}" ] || [ "$avail" -ge 5500000 ] || fail "only $avail KiB free; the clean ureth build needs 5.5 GiB"

# clean build of the pinned bft-core: the production binary (CLI and every non-root process) and the q4shim binary (the roots only)
rm -rf build/ubft build/q4shim test-nodes
mkdir -p build
GOFLAGS=-mod=readonly go build -o build/ubft ./cli/ubft || fail "clean ubft build failed"
make build-q4shim >/dev/null || fail "make build-q4shim"
[ -x build/q4shim/ubft ] || fail "build/q4shim/ubft is missing"
pass "clean ubft and q4shim builds at $Q4_BFT_COMMIT"

# shellcheck source=/dev/null
. scripts/lib/reth-pin.sh
RUN_MODE="clean build (evidence run)"
if [ -n "${Q4_URETH_BIN:-}" ]; then
  if [ "${Q4_URETH_FRESH_BUILD:-0}" = 1 ]; then RUN_MODE="clean build (evidence run; ureth built by the operator from a fresh private target at the pinned commit)"
  else RUN_MODE="DEVELOPMENT OVERRIDE: prebuilt ureth $Q4_URETH_BIN: NOT EVIDENCE"; fi
  urethPinVerifyBinary "$Q4_URETH_BIN" "$Q4_URETH_COMMIT" || fail "Q4_URETH_BIN does not report the pinned commit $Q4_URETH_COMMIT"
  URETH_BIN=$Q4_URETH_BIN
else
  URETH_PIN_COMMIT=$Q4_URETH_COMMIT URETH_PIN_REPO=${Q4_URETH_REMOTE:-https://github.com/ristik/ureth.git} \
    URETH_PIN_LOCAL=$ISOLATION_ROOT/no-local-ureth-allowed URETH_PIN_CACHE_DIR=$ISOLATION_ROOT/ureth-pin URETH_BIN= \
    urethPinResolve "$ISOLATION_ROOT/bin" | tee "$EVIDENCE_DIR/ureth-build.log"
  URETH_BIN=$ISOLATION_ROOT/bin/unicity-reth
  urethPinVerifyBinary "$URETH_BIN" "$Q4_URETH_COMMIT" || fail "built ureth does not report the pinned commit"
fi
export URETH_BIN
# the weighted-epoch gate is the Q3 flow library's function: any other command is a development override and the run is no evidence
if [ -n "${Q4_WEIGHTED_CHECK:-}" ] && [ "$Q4_WEIGHTED_CHECK" != q4_weighted_epoch_check ]; then RUN_MODE="DEVELOPMENT OVERRIDE: weighted-epoch gate '$Q4_WEIGHTED_CHECK' replaces q4_weighted_epoch_check: NOT EVIDENCE"; fi
printf 'Q4 run mode: %s\n' "$RUN_MODE" | tee "$EVIDENCE_DIR/run-mode.txt"

PINS=$EVIDENCE_DIR/pins.txt
{
  echo "run mode: $RUN_MODE"
  echo "bft-core commit: $Q4_BFT_COMMIT"
  echo "ubft sha256: $(sha256 build/ubft)"
  echo "ubft-q4shim sha256: $(sha256 build/q4shim/ubft)"
  echo "bft-go-base: $(go list -m -f '{{.Version}}' github.com/unicitynetwork/bft-go-base)"
  echo "ureth commit: $Q4_URETH_COMMIT"
  echo "ureth binary sha256: $(sha256 "$URETH_BIN")"
  echo "rugregator source: $RUGREGATOR_SOURCE @ $F8_RUGREGATOR_PIN"
  echo "rugregator binary sha256: $(sha256 "$RUGREGATOR_BIN")"
  echo "go: $(go version)"
} >"$PINS"
cat "$PINS"
export Q3_PINS_FILE=$PINS

# The execution clients are pinned to this deployment's chain: network id 3 and the genesis trust base's identity. The lane runs on the fresh-B1 stack: one profile
# (ubft engine-api b1-profile) is the source of the registry genesis (layout 3), ureth's --unicity.* bindings and the shard nodes' Update admission.
export URETH_PIN_NETWORK_ID=3 Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1
export EVM_PARTITION_PARAMS_EXTRA=${EVM_PARTITION_PARAMS_EXTRA:-continuity_max_distance=1/1}
# the roots run the q4shim binary from their first start; the shim directory is outside test-nodes (the devnet setup owns that tree)
export Q4_SHIM_DIR=$EVIDENCE_DIR/shim Q4_ROOT_BIN=$PWD/build/q4shim/ubft
mkdir -p "$Q4_SHIM_DIR"
set +e
DEVNET_PIDFILE="$EVIDENCE_DIR/.devnet-pid"; rm -f "$DEVNET_PIDFILE"
( set -o pipefail
  EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} H3_ASSIGNMENT_LANE=1 Q4_LIVE_LANE=1 F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=authority \
    POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$Q4_URETH_COMMIT" \
    M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" F8_LOG_DIR="$EVIDENCE_DIR/f8" \
    bash -c 'echo $$ >"$0"; exec bash ./scripts/reth-paired-devnet.sh 4 10' "$DEVNET_PIDFILE" 2>&1 | tee "$EVIDENCE_DIR/lane.log" ) &
wait "$!"
status=$?
set -e
rm -f "$DEVNET_PIDFILE"
cp -R test-nodes/q3 "$EVIDENCE_DIR/q3" 2>/dev/null || true
cp -R test-nodes/q4 "$EVIDENCE_DIR/q4" 2>/dev/null || true
for f in test-nodes/root*/debug.log test-nodes/evm*/debug.log; do
  [ -f "$f" ] && { mkdir -p "$EVIDENCE_DIR/node-logs/$(dirname "$f" | xargs basename)"; cp "$f" "$EVIDENCE_DIR/node-logs/$(dirname "$f" | xargs basename)/"; }
done
python3 - "$EVIDENCE_DIR" <<'PY'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1])
with (root/"SHA256SUMS").open("w",encoding="utf-8") as out:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in ("SHA256SUMS", "lane.log"):
            out.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n")
PY
if [ "$status" -eq 3 ]; then
  echo "BLOCKED: the weighted-epoch gate was not met; no fault was injected" | tee -a "$EVIDENCE_DIR/lane.log"
  exit 3
fi
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "Q4 live lane failed (exit $status); see $EVIDENCE_DIR/lane.log (checkout kept at $REPO_ROOT/test-nodes)"
fi
grep -q 'Q4 live lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing every step"
case "$RUN_MODE" in "clean build (evidence run"*) ;; *) false ;; esac || fail "run completed but is NOT EVIDENCE ($RUN_MODE)"
pass "Q4 live lane complete; evidence in $EVIDENCE_DIR"
