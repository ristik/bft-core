#!/usr/bin/env bash
# H6 Abort rehearsal lane on the fresh-B1 layout (owner decisions section 16): one four-validator paired devnet, one paid certified block, then
# Abort BEFORE H (committed Abort evidence, a paid transaction shows the EVM unfroze, attempt+1 installs) and Abort AFTER H (refused "too late", the handoff
# still installs, a paid transaction certifies in epoch 3). The functions are scripts/lib/h6-abort-lib.sh; the helper is scripts/h6/prepare-handoff.py.
#
#   scripts/h6/abort-rehearsal-lane.sh --selftest    # no devnet, no lock: syntax, define-only sourcing, the helper's checks, a helper dry run on real trust bases
#   scripts/h6/abort-rehearsal-lane.sh --prep-only   # the whole preflight (tools, pins, the attested Ureth, a clean checkout, build/ubft) and --selftest; takes no lock
#   H6_URETH_ATTESTED=<binary> H6_URETH_ATTESTED_SHA256=<digest> H6_URETH_ATTESTED_PROVENANCE=<briefs/builds/ureth-<commit> dir> scripts/h6/abort-rehearsal-lane.sh
#
# Evidence-grade only with the ATTESTED Ureth of the pin (H6_URETH_COMMIT, default 47f5146b) and a clean checkout whose build/ubft is built from its HEAD.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
H6_URETH_COMMIT=${H6_URETH_COMMIT:-47f5146b59c01e2180aa66b250ec87330231658d}
EVIDENCE_DIR=${H6_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/h6-abort-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# ---- no devnet, no lock ----------------------------------------------------------------------------------------------------------------------
selftest() {
  local tmp ok=1 f fn
  cd "$REPO_ROOT"
  for f in scripts/h6/abort-rehearsal-lane.sh scripts/h6/abort-rehearsal-steps.sh scripts/lib/h6-abort-lib.sh scripts/lib/m2-handoff-lib.sh scripts/reth-paired-devnet.sh; do
    bash -n "$f" || fail "selftest: $f does not parse"
  done
  pass "selftest: every lane script parses"
  # the libraries only define: sourced in an empty directory they define their functions, leave no file and no process behind
  tmp=$(mktemp -d)
  ( cd "$tmp" && set -u && source "$REPO_ROOT/scripts/lib/m2-handoff-lib.sh" && source "$REPO_ROOT/scripts/lib/h6-abort-lib.sh" &&
    for fn in m2_config_only_handoff m2_install_epoch m2_send_paid h6_abort_before_h h6_abort_after_h h6_plan h6_abort h6_preamble h6_stage_candidate; do
      [ "$(type -t "$fn")" = function ] || { echo "not defined: $fn" >&2; exit 1; }
    done
    [ -z "$(ls -A "$tmp")" ] && [ -z "$(jobs -p)" ] ) || ok=0
  rm -rf "$tmp"
  [ "$ok" = 1 ] || fail "selftest: sourcing the libraries defined something missing or started something"
  pass "selftest: the libraries define only (every step function present; no file, no process at source time)"
  grep -q 'H6_ABORT_LANE' scripts/reth-paired-devnet.sh && grep -q 'abort-rehearsal-steps.sh' scripts/reth-paired-devnet.sh || fail "selftest: the paired devnet does not select the rehearsal steps"
  python3 -m unittest discover -s scripts/h6 -p test_prepare_handoff.py >/dev/null 2>&1 || fail "selftest: the helper's checks fail (scripts/h6/test_prepare_handoff.py)"
  rm -rf scripts/h6/__pycache__
  pass "selftest: the helper's in-process checks pass"
  go test ./cli/ubft/cmd -run TestPrepareHandoffHelper -count=1 >/dev/null 2>&1 || fail "selftest: the helper against the real operator routes fails"
  pass "selftest: the helper drives the real operator routes"
  # a helper dry run on REAL trust bases and receipt files shaped as q3-readiness writes them: every input check of the live steps that needs no process
  [ -x build/ubft ] || fail "selftest: build/ubft is missing (make build)"
  tmp=$(mktemp -d)
  local i
  for i in 1 2 3 4; do build/ubft root-node init --home "$tmp/root$i" --generate >/dev/null; done
  local infos=(); for i in 1 2 3 4; do infos+=(--node-info "$tmp/root$i/node-info.json"); done
  build/ubft trust-base generate --home "$tmp" --network-id 3 --epoch 1 --epoch-start 1 --output-file-name trust-base-epoch1.json "${infos[@]}" >/dev/null
  for i in 1 2 3 4; do build/ubft trust-base sign --home "$tmp/root$i" --trust-base "$tmp/trust-base-epoch1.json" >/dev/null; done
  build/ubft trust-base generate --home "$tmp" --network-id 3 --epoch 2 --epoch-start 200000 --previous-trust-base "$tmp/trust-base-epoch1.json" \
    --root-weights 1,1,1,1 --output-file-name trust-base-epoch2.json "${infos[@]}" >/dev/null
  local receipts=""
  for i in 1 2 3 4; do
    printf '{"nodeId":"%s","signature":"0x%s"}\n' "$(build/ubft node-id --home "$tmp/root$i" | tail -n1)" "$(printf '%0130d' "$i")" >"$tmp/receipt-$i.json"
    receipts+="${receipts:+,}$tmp/receipt-$i.json"
  done
  python3 scripts/h6/prepare-handoff.py --dry-run --old-trust-base "$tmp/trust-base-epoch1.json" --next-trust-base "$tmp/trust-base-epoch2.json" --receipts "$receipts" \
    --root-rpc http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25869 --out "$tmp/evidence" >"$tmp/dry.out" || { cat "$tmp/dry.out" >&2; rm -rf "$tmp"; fail "selftest: the helper dry run on real trust bases failed"; }
  [ ! -e "$tmp/evidence" ] || fail "selftest: the dry run created evidence"
  rm -rf "$tmp"
  pass "selftest: the helper dry run accepts real V3 trust bases and receipt files, and contacts no root"
  go build -o /dev/null ./scripts/evmtx ./scripts/m2slots ./scripts/b1genesis || fail "selftest: the lane's helper tools do not compile"
  pass "selftest: the lane's tools compile"
}

# ---- preflight, before the lock ----------------------------------------------------------------------------------------------------------------
preflight() {
  local missing=() c got
  for c in git go jq curl python3 awk tee lsof openssl make mktemp; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  [ -x "$LOCK_SCRIPT" ] || missing+=("$LOCK_SCRIPT")
  [ -n "${H6_URETH_ATTESTED:-}" ] && [ -x "$H6_URETH_ATTESTED" ] || missing+=("H6_URETH_ATTESTED (the attested Ureth binary)")
  [ -n "${H6_URETH_ATTESTED_SHA256:-}" ] || missing+=("H6_URETH_ATTESTED_SHA256")
  [ -n "${H6_URETH_ATTESTED_PROVENANCE:-}" ] || missing+=("H6_URETH_ATTESTED_PROVENANCE")
  if [ -x "${H6_URETH_ATTESTED:-/nonexistent}" ] && [ -n "${H6_URETH_ATTESTED_SHA256:-}" ]; then
    got=$(sha256 "$H6_URETH_ATTESTED"); [ "$got" = "$H6_URETH_ATTESTED_SHA256" ] || missing+=("attested sha256 ($got is not $H6_URETH_ATTESTED_SHA256)")
    "$H6_URETH_ATTESTED" --version 2>&1 | grep -Fq "Commit SHA: $H6_URETH_COMMIT" || missing+=("the attested Ureth does not report the pinned commit $H6_URETH_COMMIT")
  fi
  if [ -n "${H6_URETH_ATTESTED_PROVENANCE:-}" ]; then
    [ "$(tr -d '[:space:]' <"$H6_URETH_ATTESTED_PROVENANCE/commit.txt" 2>/dev/null)" = "$H6_URETH_COMMIT" ] || missing+=("provenance commit.txt is not the pin $H6_URETH_COMMIT")
    grep -q "^${H6_URETH_ATTESTED_SHA256:-?} " "$H6_URETH_ATTESTED_PROVENANCE/sha256.txt" 2>/dev/null || missing+=("provenance sha256.txt does not record ${H6_URETH_ATTESTED_SHA256:-?}")
  fi
  [ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ] || missing+=("a clean checkout (uncommitted changes)")
  [ -x "$REPO_ROOT/build/ubft" ] || missing+=("build/ubft (make build)")
  if [ -x "$REPO_ROOT/build/ubft" ]; then
    go version -m "$REPO_ROOT/build/ubft" | grep -q "vcs.revision=$(git -C "$REPO_ROOT" rev-parse HEAD)" || missing+=("build/ubft is not built from HEAD (make build)")
    go version -m "$REPO_ROOT/build/ubft" | grep -q 'vcs.modified=true' && missing+=("build/ubft was built from a modified tree")
  fi
  [ "${#missing[@]}" -eq 0 ] || { echo "FAIL: preflight: ${missing[*]}" >&2; exit 1; }
  pass "preflight: tools, lock helper, the attested Ureth ($H6_URETH_COMMIT, sha256 verified, provenance agrees), a clean checkout and build/ubft built from HEAD"
}

case "${1:-}" in
  --selftest) selftest; exit 0 ;;
  --prep-only) preflight; selftest; echo "prep only: nothing started, no lock taken"; exit 0 ;;
  "") ;;
  *) fail "unknown argument $1" ;;
esac

if [ "${H6_LANE_LOCKED:-0}" != 1 ]; then
  preflight
  selftest
  exec "$LOCK_SCRIPT" "H6 Abort rehearsal lane (fresh-B1)" env H6_LANE_LOCKED=1 H6_EVIDENCE_DIR="$EVIDENCE_DIR" H6_URETH_ATTESTED="$H6_URETH_ATTESTED" \
    H6_URETH_ATTESTED_SHA256="$H6_URETH_ATTESTED_SHA256" H6_URETH_ATTESTED_PROVENANCE="$H6_URETH_ATTESTED_PROVENANCE" H6_URETH_COMMIT="$H6_URETH_COMMIT" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"
# the run is evidence-grade only if the checks hold again under the lock (the file or the checkout could have changed while queued)
preflight
cp -R "$H6_URETH_ATTESTED_PROVENANCE" "$EVIDENCE_DIR/ureth-provenance"
printf 'RUN MODE: attested prebuilt Ureth %s sha256=%s commit=%s (provenance %s); everything else from this clean checkout (evidence run)\n' \
  "$H6_URETH_ATTESTED" "$H6_URETH_ATTESTED_SHA256" "$H6_URETH_COMMIT" "$H6_URETH_ATTESTED_PROVENANCE" | tee "$EVIDENCE_DIR/run-mode.txt"
echo "bft-core head=$(git rev-parse HEAD) branch=$(git rev-parse --abbrev-ref HEAD) ureth=$H6_URETH_COMMIT ubft sha256=$(sha256 build/ubft)" | tee "$EVIDENCE_DIR/heads.txt"

# A signal to the lane stops the scenario child and waits for its own teardown, by the child's pid alone (an orphaned child keeps restarting nodes here).
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

export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1

set +e
DEVNET_PIDFILE="$EVIDENCE_DIR/.devnet-pid"; rm -f "$DEVNET_PIDFILE"
( set -o pipefail
  H6_ABORT_LANE=1 EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} M2_PROFILE2=1 SIGNING=authority \
    POST_M2A_URETH_BIN="$H6_URETH_ATTESTED" POST_M2A_URETH_COMMIT="$H6_URETH_COMMIT" \
    M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" \
    bash -c 'echo $$ >"$0"; exec bash ./scripts/reth-paired-devnet.sh 4 10' "$DEVNET_PIDFILE" 2>&1 | tee "$EVIDENCE_DIR/lane.log" ) &
wait "$!"
status=$?
set -e
rm -f "$DEVNET_PIDFILE"
# the state is kept for offline replay: test-nodes stays where it is; the evidence below is a copy
cp -R test-nodes/q3 "$EVIDENCE_DIR/q3" 2>/dev/null || true
for n in root1 root2 root3 root4 evm1 evm2 evm3 evm4; do [ -f "test-nodes/$n/debug.log" ] && cp "test-nodes/$n/debug.log" "$EVIDENCE_DIR/$n-debug.log"; done
echo "state kept in $REPO_ROOT/test-nodes (nodes stopped by their own teardown); evidence copy in $EVIDENCE_DIR" | tee "$EVIDENCE_DIR/state.txt"
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "H6 Abort rehearsal failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'H6 Abort rehearsal: Abort before H committed' "$EVIDENCE_DIR/lane.log" || fail "lane ended without both rehearsed Aborts"
q3=$EVIDENCE_DIR/q3
for f in target.json status.json abort.out abort.status; do
  [ -s "$q3/h6-before-h/$f" ] && [ -s "$q3/h6-after-h/$f" ] || fail "missing evidence $f"
done
[ "$(cat "$q3/h6-before-h/abort.status")" = 0 ] && [ "$(cat "$q3/h6-after-h/abort.status")" != 0 ] || fail "the Abort exit statuses are not (committed, refused)"
[ "$(jq -r .state "$q3/h6-before-h/status.json")" = pending ] && [ "$(jq -r .state "$q3/h6-after-h/status.json")" = too_late ] || fail "the pre-Abort control states are not (pending, too_late)"
pass "H6 Abort rehearsal complete; evidence in $EVIDENCE_DIR"
