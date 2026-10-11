#!/usr/bin/env bash
# H3 acceptance lane (briefs/h3-evm-assignment-design.md section 8, amended: validator-set changes are always coupled): a fresh
# fresh-B1 genesis (the one registry layout, validator_coupling=true) with F8's three aggregator shards; a configuration-only epoch
# advance as the baseline, a refused bad-PoP coupled proposal, a coupled rotation (root entity and its delegated EVM validator)
# during an in-flight old proposal with a held acknowledgement and a root quorum restart, retired-key rejection (hard
# assertions), the F7 inclusion proof verified offline with the new-epoch trust base, the H4 restore at s=1, a coupled s=2 whose joiner
# is behind the chain (it restores from an archive and gives readiness before the Commit), and the derived recovery K (the s=1 set) that supersedes
# s=2 and whose late s=2 acknowledgement is refused (at the root when the node reaches one, otherwise at the archive: the log says which). Every step prints PASS or FAIL; the first FAIL exits nonzero. Every validator signs through
# its own signing authority (SIGNING=authority, the only mode): joiners' proofs of possession are signed on the operator channel,
# retained validators' authorities advance at each activation and a restored validator restores through its surviving authority.
#
#   scripts/h3-assignment-lane.sh --selftest    # no devnet, no lock: syntax, define-only sourcing, the steps file's start guard, the tools
#   scripts/h3-assignment-lane.sh --prep-only   # the whole preflight (tools, the Ureth and its provenance, a clean checkout, build/ubft, the rugregator pin) and --selftest; takes no lock
#   H3_URETH_BIN=<the attested Ureth build> RUGREGATOR_BIN=<F8-pinned binary> RUGREGATOR_SOURCE=<F8-pinned checkout> scripts/h3-assignment-lane.sh
#
# Evidence-grade only with the ATTESTED Ureth (H3_URETH_COMMIT, default the pin in scripts/lib/lane-runner-lib.sh; its provenance directory is
# briefs/builds/ureth-<commit> or H3_URETH_ATTESTED_PROVENANCE) and a clean checkout whose build/ubft is built from HEAD. H3_DEV_RUN=1 is a development
# run: it skips those checks and its run-mode.txt says so.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
source "$SCRIPT_DIR/lib/lane-runner-lib.sh"
LANE=H3
EVIDENCE_DIR=${H3_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/h3-assignment-$(date -u +%Y%m%dT%H%M%SZ)}
H3_URETH_COMMIT=${H3_URETH_COMMIT:-$LANE_URETH_PIN}
source "$SCRIPT_DIR/f8-rugregator-pin.sh"

# ---- no devnet, no lock ------------------------------------------------------------------------------------------------------------------------
selftest() {
  cd "$REPO_ROOT"
  bash -n scripts/reth-paired-devnet.sh || lane_fail "$LANE selftest: scripts/reth-paired-devnet.sh does not parse"
  lane_selftest_defines scripts/f8-mixed-lane.sh scripts/lib/m2-handoff-lib.sh scripts/lib/h3-lib.sh scripts/lib/q3-lib.sh scripts/lib/q3-flow-lib.sh scripts/lib/h3-q3-lib.sh -- \
    h3_restore_validator h3_paid h3_mint h3_verify_mint h3_advance_authorities h3_q3_init h3_q3_handoff h3_q3_activate_coupled h3_q3_config_handoff h3_q3_start_joiner \
    h3_q3_joiner_shard_restore h3_q3_trust_base q3_build_assignment q3_attempt m2_advance_authorities m2_send_paid f8_trace
  lane_selftest_steps scripts/h3-assignment-steps.sh h3_teardown H3_LANE_LOCKED=1 H3_ASSIGNMENT_LANE=1 PAIRED_DEVNET_STEPS=1
  go build -o /dev/null ./scripts/evmtx ./scripts/m2slots ./scripts/h3slots ./scripts/b1genesis || lane_fail "$LANE selftest: the lane's helper tools do not compile"
  lane_pass "$LANE selftest: the lane's tools compile"
  bash scripts/check-no-global-kill.sh >/dev/null || lane_fail "$LANE selftest: a script can stop processes by name (scripts/check-no-global-kill.sh)"
  lane_pass "$LANE selftest: no script stops processes by name"
}
preflight() {
  lane_preflight "${H3_URETH_BIN:-}" "$H3_URETH_COMMIT" "${H3_DEV_RUN:-0}" "${H3_URETH_ATTESTED_PROVENANCE:-}"
  lane_rugregator_preflight
  lane_pass "$LANE preflight: tools, lock helper, Ureth $LANE_URETH_COMMIT, rugregator $F8_RUGREGATOR_PIN, build/ubft; $LANE_RUN_MODE"
}

case "${1:-}" in
  --selftest) selftest; exit 0 ;;
  --prep-only) preflight; selftest; echo "prep only: nothing started, no lock taken"; exit 0 ;;
  "") ;;
  *) lane_fail "unknown argument $1" ;;
esac

if [ "${H3_LANE_LOCKED:-0}" != 1 ]; then
  preflight
  selftest
  exec "$LOCK_SCRIPT" "H3 EVM assignment acceptance lane" env H3_LANE_LOCKED=1 H3_EVIDENCE_DIR="$EVIDENCE_DIR" H3_URETH_COMMIT="$H3_URETH_COMMIT" "$0" "$@"
fi
cd "$REPO_ROOT"
# the run is evidence only if the checks hold again under the lock (the binary or the checkout could have changed while queued)
preflight
lane_begin "$EVIDENCE_DIR"

# the single B1 layout: one B1 profile derived from the shard configuration and the root trust base; the registry slots are read under the layout-3 names;
# every shard node exposes its operator endpoint (the readiness check asks it what it has staged)
export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1
# the rotations replace one root entity (distance 1/2 between four equal-weight committees) and two EVM validators (distance 1): the genesis configuration
# commits a budget that admits them; the DEV default (1/4) admits no replacement of a four-member committee
export EVM_PARTITION_PARAMS_EXTRA=${EVM_PARTITION_PARAMS_EXTRA:-continuity_max_distance=1/1}
echo "NOTE: SIGNING=authority: every validator signs through its own signing authority (the only mode of this lane)."
lane_run_devnet EVM_JOURNAL_CANDIDATES="${EVM_JOURNAL_CANDIDATES:-256}" H3_LANE_LOCKED=1 H3_ASSIGNMENT_LANE=1 F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=authority F8_LOG_DIR="$EVIDENCE_DIR/f8"
lane_collect h3 q3
if [ "$LANE_STATUS" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  lane_fail "H3 acceptance lane failed (exit $LANE_STATUS); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'H3 acceptance lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || lane_fail "lane ended without completing every step"
lane_pass "H3 acceptance lane complete; evidence in $EVIDENCE_DIR"
