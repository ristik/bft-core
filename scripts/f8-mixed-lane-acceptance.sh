#!/usr/bin/env bash
# F8 mixed-lane acceptance on the fresh-B1 layout (the one registry layout): the EVM partition and three independent rugregator aggregator shards (a split
# partition A and an unsharded B) under one root committee. The aggregators certify alongside the EVM; the EVM is delayed, stopped and resumed, a non-default
# aggregator shard reconnects, an EVM proposal certifies during a root leader rotation, and one root handoff (same members, through the Q3 flow) leaves every
# aggregator shard live with root coverage. Every step prints PASS or FAIL.
#
#   scripts/f8-mixed-lane-acceptance.sh --selftest    # no devnet, no lock: syntax, define-only sourcing, the steps file's start guard, the tools
#   scripts/f8-mixed-lane-acceptance.sh --prep-only   # the whole preflight (tools, the Ureth and its provenance, a clean checkout, build/ubft, the rugregator pin) and --selftest; takes no lock
#   F8_URETH_BIN=<the attested Ureth build> RUGREGATOR_BIN=<binary built from the F8 pin> RUGREGATOR_SOURCE=<checkout at the F8 pin> scripts/f8-mixed-lane-acceptance.sh
#
# Evidence-grade only with the ATTESTED Ureth (F8_URETH_COMMIT, default the pin in scripts/lib/lane-runner-lib.sh; its provenance directory is
# briefs/builds/ureth-<commit> or F8_URETH_ATTESTED_PROVENANCE) and a clean checkout whose build/ubft is built from HEAD. F8_DEV_RUN=1 is a development
# run: it skips those checks and its run-mode.txt says so.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
source "$SCRIPT_DIR/lib/lane-runner-lib.sh"
LANE=F8
EVIDENCE_DIR=${F8_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/f8-$(date -u +%Y%m%dT%H%M%SZ)}
F8_URETH_COMMIT=${F8_URETH_COMMIT:-$LANE_URETH_PIN}
source "$SCRIPT_DIR/f8-rugregator-pin.sh"

# ---- no devnet, no lock ------------------------------------------------------------------------------------------------------------------------
selftest() {
  cd "$REPO_ROOT"
  bash -n scripts/reth-paired-devnet.sh || lane_fail "$LANE selftest: scripts/reth-paired-devnet.sh does not parse"
  lane_selftest_defines scripts/f8-mixed-lane.sh scripts/lib/m2-handoff-lib.sh -- f8_prepare f8_start f8_trace f8_inflight_evm_probe f8_slow_stop_resume_evm f8_reconnect_probe f8_stop m2_config_only_handoff m2_send_paid
  lane_selftest_steps scripts/m2-profile2-handoffs.sh m2_send_paid M2_PROFILE2=1 PAIRED_DEVNET_STEPS=1
  go build -o /dev/null ./scripts/evmtx ./scripts/m2slots ./scripts/h3slots ./scripts/b1genesis || lane_fail "$LANE selftest: the lane's helper tools do not compile"
  lane_pass "$LANE selftest: the lane's tools compile"
  bash scripts/check-no-global-kill.sh >/dev/null || lane_fail "$LANE selftest: a script can stop processes by name (scripts/check-no-global-kill.sh)"
  lane_pass "$LANE selftest: no script stops processes by name"
}
preflight() {
  LANE_HOLDS_LOCK=${F8_LANE_LOCKED:-0}
  lane_preflight "${F8_URETH_BIN:-}" "$F8_URETH_COMMIT" "${F8_DEV_RUN:-0}" "${F8_URETH_ATTESTED_PROVENANCE:-}"
  lane_rugregator_preflight "${F8_DEV_RUN:-0}" "${RUGREGATOR_ATTESTED_PROVENANCE:-}"
  lane_pass "$LANE preflight: tools, lock helper, Ureth $LANE_URETH_COMMIT, rugregator $F8_RUGREGATOR_PIN (binary sha256 $LANE_RUGREGATOR_SHA256), build/ubft; $LANE_RUN_MODE"
}

case "${1:-}" in
  --selftest) selftest; exit 0 ;;
  --prep-only) preflight; selftest; echo "prep only: nothing started, no lock taken"; exit 0 ;;
  "") ;;
  *) lane_fail "unknown argument $1" ;;
esac

if [ "${F8_LANE_LOCKED:-0}" != 1 ]; then
  preflight
  selftest
  exec "$LOCK_SCRIPT" "F8 mixed-lane acceptance (fresh-B1)" env F8_LANE_LOCKED=1 F8_EVIDENCE_DIR="$EVIDENCE_DIR" F8_URETH_COMMIT="$F8_URETH_COMMIT" "$0" "$@"
fi
cd "$REPO_ROOT"
# the run is evidence only if the checks hold again under the lock (the binary or the checkout could have changed while queued)
preflight
lane_begin "$EVIDENCE_DIR"

# the single B1 layout: one B1 profile derived from the shard configuration and the root trust base; the registry slots are read under the layout-3 names;
# every shard node exposes its operator endpoint (the readiness check asks it what it has staged)
export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1
lane_run_devnet EVM_JOURNAL_CANDIDATES="${EVM_JOURNAL_CANDIDATES:-256}" F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=authority F8_LOG_DIR="$EVIDENCE_DIR/f8"
lane_collect q3
if [ "$LANE_STATUS" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  lane_fail "F8 mixed-lane acceptance failed (exit $LANE_STATUS); see $EVIDENCE_DIR/lane.log"
fi
for want in 'three aggregator shards certified alongside the EVM partition' 'aggregators continued through delayed/stopped EVM; reconnect and in-flight EVM proposal passed' \
  'one root handoff (same members, Q3 flow) certified paid transactions' 'all three aggregator shards remained live through the root handoff'; do
  grep -Fq "$want" "$EVIDENCE_DIR/lane.log" || lane_fail "lane ended without: $want"
done
lane_pass "F8 mixed-lane acceptance complete; evidence in $EVIDENCE_DIR"
