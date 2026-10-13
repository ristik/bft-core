#!/usr/bin/env bash
# M2 acceptance lane on the fresh-B1 layout (the one registry layout): a four-validator paired devnet, one paid certified block, then two root handoffs through
# the Q3 flow (V3 candidate, a readiness receipt from every entity, propose, install, activation, authority advance, paid transaction) with the same members,
# and the M2a restore of a validator across both epochs (the H4 restore probe), under the D1 monitor. Every step prints PASS or FAIL.
#
#   scripts/m2-lane.sh --selftest    # no devnet, no lock: syntax, define-only sourcing, the steps file's start guard, the tools
#   scripts/m2-lane.sh --prep-only   # the whole preflight (tools, the Ureth and its provenance, a clean checkout, build/ubft) and --selftest; takes no lock
#   M2_URETH_BIN=<the attested Ureth build> scripts/m2-lane.sh
#
# Evidence-grade only with the ATTESTED Ureth (M2_URETH_COMMIT, default the pin in scripts/lib/lane-runner-lib.sh; its provenance directory is
# briefs/builds/ureth-<commit> or M2_URETH_ATTESTED_PROVENANCE) and a clean checkout whose build/ubft is built from HEAD. M2_DEV_RUN=1 is a development
# run: it skips those checks and its run-mode.txt says so.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
source "$SCRIPT_DIR/lib/lane-runner-lib.sh"
LANE=M2
EVIDENCE_DIR=${M2_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/m2-$(date -u +%Y%m%dT%H%M%SZ)}
M2_URETH_COMMIT=${M2_URETH_COMMIT:-$LANE_URETH_PIN}

# ---- no devnet, no lock ------------------------------------------------------------------------------------------------------------------------
selftest() {
  cd "$REPO_ROOT"
  bash -n scripts/reth-paired-devnet.sh || lane_fail "$LANE selftest: scripts/reth-paired-devnet.sh does not parse"
  lane_selftest_defines scripts/lib/m2-handoff-lib.sh scripts/lib/h3-lib.sh -- m2_config_only_handoff m2_install_epoch m2_send_paid m2_wait_certified_idle m2_advance_authorities h3_restore_validator
  lane_selftest_steps scripts/m2-profile2-handoffs.sh m2_send_paid M2_PROFILE2=1 PAIRED_DEVNET_STEPS=1
  go build -o /dev/null ./scripts/evmtx ./scripts/m2slots ./scripts/h3slots ./scripts/b1genesis || lane_fail "$LANE selftest: the lane's helper tools do not compile"
  lane_pass "$LANE selftest: the lane's tools compile"
  bash scripts/check-no-global-kill.sh >/dev/null || lane_fail "$LANE selftest: a script can stop processes by name (scripts/check-no-global-kill.sh)"
  lane_pass "$LANE selftest: no script stops processes by name"
}
preflight() {
  LANE_HOLDS_LOCK=${M2_LANE_LOCKED:-0}
  lane_preflight "${M2_URETH_BIN:-}" "$M2_URETH_COMMIT" "${M2_DEV_RUN:-0}" "${M2_URETH_ATTESTED_PROVENANCE:-}"
  lane_pass "$LANE preflight: tools, lock helper, Ureth $LANE_URETH_COMMIT, build/ubft; $LANE_RUN_MODE"
}

case "${1:-}" in
  --selftest) selftest; exit 0 ;;
  --prep-only) preflight; selftest; echo "prep only: nothing started, no lock taken"; exit 0 ;;
  "") ;;
  *) lane_fail "unknown argument $1" ;;
esac

if [ "${M2_LANE_LOCKED:-0}" != 1 ]; then
  preflight
  selftest
  exec "$LOCK_SCRIPT" "M2 acceptance lane (fresh-B1)" env M2_LANE_LOCKED=1 M2_EVIDENCE_DIR="$EVIDENCE_DIR" M2_URETH_COMMIT="$M2_URETH_COMMIT" "$0" "$@"
fi
cd "$REPO_ROOT"
# the run is evidence only if the checks hold again under the lock (the binary or the checkout could have changed while queued)
preflight
lane_begin "$EVIDENCE_DIR"

# the single B1 layout: one B1 profile derived from the shard configuration and the root trust base; the registry slots are read under the layout-3 names;
# every shard node exposes its operator endpoint (the readiness check asks it what it has staged)
export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1
lane_run_devnet EVM_JOURNAL_CANDIDATES="${EVM_JOURNAL_CANDIDATES:-256}" M2_PROFILE2=1 M2A_FINAL_RESTORE="${M2A_FINAL_RESTORE:-1}" SIGNING=authority
lane_collect q3 h4-replaced
if [ "$LANE_STATUS" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  lane_fail "M2 acceptance lane failed (exit $LANE_STATUS); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'two profile-2 handoffs (same members, Q3 flow) certified paid transactions' "$EVIDENCE_DIR/lane.log" || lane_fail "lane ended without completing the two handoffs"
[ "${M2A_FINAL_RESTORE:-1}" != 1 ] || grep -q '^RESTORE PASS: epochs 2 and 3 activated' "$EVIDENCE_DIR/lane.log" || lane_fail "lane ended without the M2a restore"
lane_pass "M2 acceptance lane complete; evidence in $EVIDENCE_DIR"
