#!/usr/bin/env bash
# Q3 #50 slice E: the weight-activation acceptance lane (briefs/q3-design-v2.md section 5 item 3 and section 6 row E). One H3-style devnet lane:
# layout-2 unit PoA -> ONE coupled handoff to mirrored weights 6,1,1,1 that activates Q1
# scheme 2, Q2 weighted EVM requests and the #399 selector through the committed activation record -> progress, a real TC, a heavy-validator
# crash across E with original-message recovery/rebroadcast, two independently verifying pairs with identical bytes and state, pair refusal
# controls (wrong parent/job, substituted input, missing evidence, restart) -> the evidence pack.
#
#   scripts/q3-weight-activation-lane.sh --dry-run        # no lock, no build, no process, no network: pins, plan, self-test
#   Q3_BFT_COMMIT=<sha> Q3_URETH_COMMIT=<sha> Q3_CONTRACTS_COMMIT=<sha> Q3_GOBASE_PIN=<version> \
#   RUGREGATOR_BIN=<F8-pinned binary> RUGREGATOR_SOURCE=<F8-pinned checkout> scripts/q3-weight-activation-lane.sh
#
# Pins have NO defaults: every artifact must be named, and the run refuses a checkout that is not exactly the pinned bft-core commit with a clean
# tree. Q3_URETH_BIN may name a Ureth the operator built from a fresh private target at exactly Q3_URETH_COMMIT (verified against the binary's own
# reported commit; its sha256 is recorded) when Q3_URETH_FRESH_BUILD=1 attests that; otherwise it is a DEVELOPMENT OVERRIDE and the run is not evidence.
#
# Teardown is ownership-checked (#383): only processes of THIS checkout, matched by command and working directory, are signalled (helper.sh
# owned_pid/stop_pidfile, never pkill), and the devnet lock is released by briefs/devnet-lock.sh's own trap.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${Q3_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/q3-weights-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

DRY_RUN=${Q3_LANE_DRY_RUN:-0}
for a in "$@"; do case "$a" in --dry-run) DRY_RUN=1 ;; *) fail "unknown argument: $a" ;; esac; done

cd "$REPO_ROOT"
# definitions only: nothing below starts a process
# shellcheck source=/dev/null
source helper.sh
export Q3_LANE_DEFINE_ONLY=1
# shellcheck source=/dev/null
source scripts/q3-weight-activation-steps.sh
unset Q3_LANE_DEFINE_ONLY

REQUIRED_PINS="Q3_BFT_COMMIT Q3_URETH_COMMIT Q3_CONTRACTS_COMMIT Q3_GOBASE_PIN RUGREGATOR_BIN RUGREGATOR_SOURCE"

dry_run() {
  local v c status=0
  echo "=== Q3 #50 slice E weight-activation lane: DRY RUN (no lock, no build, no process, no network) ==="
  echo "bft-core head: $(git rev-parse HEAD)  tree: $([ -z "$(git status --porcelain)" ] && echo clean || echo DIRTY)"
  echo "--- required pins (a real run refuses if any is unset; there are no defaults)"
  for v in $REQUIRED_PINS; do printf '  %-24s %s\n' "$v" "${!v:-<unset>}"; done
  echo "--- mirrored weights: $Q3_WEIGHTS (W=$Q3_TOTAL_WEIGHT, root Q=$Q3_ROOT_QUORUM, faulty bound $Q3_FAULT_BOUND, EVM Q=$Q3_EVM_QUORUM)"
  echo "--- steps, in order"
  for c in $Q3_STEPS; do printf '  %s\n' "$c"; done
  echo "--- evidence the lane must produce (it fails if any is missing or empty)"
  for c in $Q3_EVIDENCE_REQUIRED; do printf '  %s\n' "$c"; done
  echo "--- self-test"
  q3_selftest || status=1
  echo "--- static checks of the lane scripts"
  bash -n scripts/q3-weight-activation-lane.sh scripts/q3-weight-activation-steps.sh scripts/lib/q3-lib.sh && echo "  bash -n: ok" || status=1
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x scripts/q3-weight-activation-lane.sh scripts/q3-weight-activation-steps.sh scripts/lib/q3-lib.sh && echo "  shellcheck: ok" || status=1
  else echo "  shellcheck: not installed on this host (not run)"; fi
  [ -x "$LOCK_SCRIPT" ] && echo "  devnet lock helper present: $LOCK_SCRIPT (not taken)" || { echo "  devnet lock helper MISSING: $LOCK_SCRIPT" >&2; status=1; }
  [ "$status" -eq 0 ] && echo "Q3 lane dry run: OK (the devnet lane itself was NOT run)" || echo "Q3 lane dry run: FAILED" >&2
  return "$status"
}
if [ "$DRY_RUN" = 1 ]; then dry_run; exit $?; fi

# ---- real run -------------------------------------------------------------------------------------------------------------------------------
for v in $REQUIRED_PINS; do [ -n "${!v:-}" ] || fail "set $v (no defaults: the lane runs only against exactly pinned, merged artifacts)"; done
[ "$(git rev-parse HEAD)" = "$Q3_BFT_COMMIT" ] || fail "checkout HEAD $(git rev-parse HEAD) is not the pinned Q3_BFT_COMMIT $Q3_BFT_COMMIT"
[ -z "$(git status --porcelain)" ] || fail "the checkout is not clean: a pinned run needs exactly the pinned source"
[ -n "$(go list -m -f '{{.Version}}' all 2>/dev/null | grep -F -x -e "$Q3_GOBASE_PIN" || true)" ] || fail "go.mod does not resolve the pinned bft-go-base version $Q3_GOBASE_PIN"

if [ "${Q3_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "Q3 weight-activation acceptance lane" env Q3_LANE_LOCKED=1 Q3_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"

# Ownership-checked cleanup on every exit: this checkout's processes only. A failing run keeps its test-nodes; the lock is released by the lock helper.
cleanup() { local s=$?; ( source helper.sh; source scripts/lib/q3-lib.sh; q3_teardown ) >/dev/null 2>&1 || true; exit "$s"; }
trap cleanup EXIT

# clean build of the pinned bft-core, then the pinned Ureth
ISOLATION_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/q3-lane.XXXXXX")
remove_isolation_root() { [ -n "${ISOLATION_ROOT:-}" ] && [ -d "$ISOLATION_ROOT" ] || return 0; chmod -R u+w "$ISOLATION_ROOT" 2>/dev/null || true; rm -rf "$ISOLATION_ROOT"; }
trap 'remove_isolation_root; cleanup' EXIT
avail=$(df -Pk "$ISOLATION_ROOT" | awk 'NR==2 {print $4}')
[ "$avail" -ge 5500000 ] || fail "only $avail KiB free; the clean Ureth build needs 5.5 GiB"
rm -rf build/ubft test-nodes
mkdir -p build
GOFLAGS=-mod=readonly go build -o build/ubft ./cli/ubft || fail "clean ubft build failed"
pass "clean ubft build at $Q3_BFT_COMMIT"

# shellcheck source=/dev/null
. scripts/lib/reth-pin.sh
RUN_MODE="clean build (evidence run)"
if [ -n "${Q3_URETH_BIN:-}" ]; then
  if [ "${Q3_URETH_FRESH_BUILD:-0}" = 1 ]; then RUN_MODE="clean build (evidence run; Ureth built by the operator from a fresh private target at the pinned commit)"
  else RUN_MODE="DEVELOPMENT OVERRIDE: prebuilt Ureth $Q3_URETH_BIN: NOT EVIDENCE"; fi
  urethPinVerifyBinary "$Q3_URETH_BIN" "$Q3_URETH_COMMIT" || fail "Q3_URETH_BIN does not report the pinned commit $Q3_URETH_COMMIT"
  URETH_BIN=$Q3_URETH_BIN
else
  URETH_PIN_COMMIT=$Q3_URETH_COMMIT URETH_PIN_REPO=${Q3_URETH_REMOTE:-https://github.com/ristik/ureth.git} \
    URETH_PIN_LOCAL=$ISOLATION_ROOT/no-local-ureth-allowed URETH_PIN_CACHE_DIR=$ISOLATION_ROOT/ureth-pin URETH_BIN= \
    urethPinResolve "$ISOLATION_ROOT/bin" | tee "$EVIDENCE_DIR/ureth-build.log"
  URETH_BIN=$ISOLATION_ROOT/bin/unicity-reth
  urethPinVerifyBinary "$URETH_BIN" "$Q3_URETH_COMMIT" || fail "built Ureth does not report the pinned commit"
fi
export URETH_BIN
printf 'Q3 run mode: %s\n' "$RUN_MODE" | tee "$EVIDENCE_DIR/run-mode.txt"
if [ -n "${Q3_CONTRACTS_CHECKOUT:-}" ]; then
  [ "$(git -C "$Q3_CONTRACTS_CHECKOUT" rev-parse HEAD)" = "$Q3_CONTRACTS_COMMIT" ] || fail "Q3_CONTRACTS_CHECKOUT is not at the pinned contracts commit"
fi

PINS=$EVIDENCE_DIR/pins.txt
{
  echo "run mode: $RUN_MODE"
  echo "bft-core commit: $Q3_BFT_COMMIT"
  echo "ubft sha256: $(sha256 build/ubft)"
  echo "bft-go-base: $Q3_GOBASE_PIN"
  echo "ureth commit: $Q3_URETH_COMMIT"
  echo "ureth binary sha256: $(sha256 "$URETH_BIN")"
  echo "contracts commit: $Q3_CONTRACTS_COMMIT"
  echo "rugregator source: $RUGREGATOR_SOURCE"
  echo "go: $(go version)"
} >"$PINS"
export Q3_PINS_FILE=$PINS

# The execution clients are pinned to this deployment's chain: network id 3 (every lane's genesis) and the genesis trust base's identity.
export URETH_PIN_NETWORK_ID=3
# the lane runs on the fresh-B1 stack: one profile (ubft engine-api b1-profile) is the source of the registry genesis (layout 3), ureth's --unicity.*
# bindings and the shard nodes' Update admission (scripts/reth-paired-devnet.sh), and the registry slots are read under the layout-3 names
export Q3_B1=${Q3_B1:-1}
[ "$Q3_B1" != 1 ] || export H3_SLOT_LAYOUT=3
# every shard node exposes its operator endpoint (the readiness check asks it what it has staged)
export EVM_OPERATOR_STATUS_RPC=1
# the weighted rotation (1,1,1,1 -> 6,1,1,1) must fit the continuity budget the genesis configuration commits; the DEV default admits no reweighting.
# (The coupling parameter is the genesis tool's own default for every launch genesis since #486.)
# The genesis configuration commits a continuity budget of 1/1: the normalized weight distance (sum |w/W - v/V|) between consecutive committees may not exceed it. The
# first handoff (1,1,1,1 -> 6,1,1,1) is 5/6, the later positive handoffs stay inside it, and the full heavy-weight swap (6,1,1,1 -> 1,6,1,1: 10/9) is the negative row.
export EVM_PARTITION_PARAMS_EXTRA=${EVM_PARTITION_PARAMS_EXTRA:-continuity_max_distance=1/1}
set +e
EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} H3_ASSIGNMENT_LANE=1 Q3_WEIGHT_LANE=1 F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=authority \
  POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$Q3_URETH_COMMIT" \
  M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" F8_LOG_DIR="$EVIDENCE_DIR/f8" \
  bash ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$EVIDENCE_DIR/lane.log"
status=${PIPESTATUS[0]}
set -e
cp -R test-nodes/q3 "$EVIDENCE_DIR/q3" 2>/dev/null || true
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
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "Q3 weight-activation lane failed (exit $status); see $EVIDENCE_DIR/lane.log (checkout kept at $REPO_ROOT/test-nodes)"
fi
grep -q 'Q3 weight-activation lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing every step"
( source scripts/lib/q3-lib.sh; q3_evidence_check "$EVIDENCE_DIR/q3" ) || fail "the evidence pack is incomplete"
case "$RUN_MODE" in "clean build (evidence run"*) ;; *) false ;; esac || fail "run completed but is NOT EVIDENCE ($RUN_MODE)"
pass "Q3 weight-activation lane complete; evidence in $EVIDENCE_DIR"
