#!/usr/bin/env bash
# X4 #58: the shadow lane's steps. Sourced by reth-paired-devnet.sh (P85_LANE=1, P85_SHADOW=1) after the first paid certified block, in place of
# p85-recovery-steps.sh. Design: briefs/x4-shadow-campaign-design.md section 2 and briefs/x4-shadow-adapter-brief.md (A.3).
#
# The chain carries the staking modules and the records hook but NO authoritative election (the profile has none, the roots run without the PoS flags),
# so an election is due and never taken: the contract's state stays the one a real election would be asked about. scripts/shadow/adapter.py samples that
# certified state every few seconds and runs the REAL election on a disposable fork of it, against an independent reference. This file scripts the
# eligibility changes between the samples with the relayer's own join commands, so that the due comparisons cover an unchanged candidate, a changed one
# and a refusal beyond the weight bound:
#
#   baseline   the shadow profile and roots are what they must be; four genesis identities are live; no result is open
#   passive    the election's thresholds are reached (due) and, with the hook absent, nothing elects
#   spare 1    one unit-weight identity registers, bonds and is admitted: a valid changed candidate (weight distance 1/5, within the 1/2 bound)
#   spare 2    a four-unit identity does the same: the candidate would shift more than the weight bound allows, a refusal
#   report     the adapter's report is read; the lane passes only when the adapter says PASS
#
# Spare identities exist on the chain only (no root, no shard node): their keys are generated here, their node ids are labels, their EVM key is local.
# Sourcing this file only defines the steps; they run when the runner (scripts/p85-lane.sh, under the devnet lock) asks for it.
source scripts/lib/m2-handoff-lib.sh
H3_DIR=${P85_RUN_DIR:-test-nodes/p85/run}
mkdir -p "$H3_DIR"
source scripts/lib/h3-lib.sh
source scripts/lib/q3-lib.sh
source scripts/lib/p85-lib.sh

X4_CADENCE=${X4_CADENCE:-10}         # seconds between samples
X4_PHASE_SECONDS=${X4_PHASE_SECONDS:-90}   # how long each scripted state is sampled (>= 8 samples at the default cadence)
X4_DIR=$H3_DIR/shadow
P85_DEPLOY=$P85_DIR/pos-deployment.json
x4_eth() { echo "http://127.0.0.1:$rethEthBase"; }
x4_call() { "$P85_CAST" call --rpc-url "$(x4_eth)" "$@"; }
x4_election() { jq -r .election "$P85_DEPLOY"; }
x4_registry() { jq -r .registry "$P85_DEPLOY"; }
x4_pass() { echo "  PASS: $*"; }
x4_die() { echo "  FAIL: $*" >&2; [ -z "${X4_ADAPTER_PID:-}" ] || kill "$X4_ADAPTER_PID" 2>/dev/null; q3_teardown; exit 1; }
x4_step() { local name=$1; shift; echo "--- X4 shadow step: $name"; "$@" || x4_die "$name"; x4_pass "$name"; }
x4_live_count() { x4_call "$(x4_election)" "liveCount()(uint32)" | awk '{print $1}'; }
x4_num() { x4_call "$@" | awk 'NR==1{print $1}'; }

x4_baseline() {
  [ -s "${EVM_B1_PROFILE:-}" ] || { echo "no B1 profile" >&2; return 1; }
  p85_assert_shadow_profile "$EVM_B1_PROFILE" || return 1
  p85_assert_shadow_roots || return 1
  [ "$(x4_live_count)" = 4 ] || { echo "the election's live index holds $(x4_live_count) identities, not the four genesis entities" >&2; return 1; }
  [ "$(x4_call "$(x4_election)" 'openResult()(bytes32)')" = "0x0000000000000000000000000000000000000000000000000000000000000000" ] || { echo "an election result is open" >&2; return 1; }
  cp "$P85_DEPLOY" "$H3_DIR/pos-deployment.json"; cp "$EVM_B1_PROFILE" "$H3_DIR/b1-profile.json"
}

# a spare identity: owner key (funded by the joiner account), root/EVM keys (generated), labels for the node ids
x4_spare_file() { # n
  local n=$1 d=$P85_DIR/spare$n
  mkdir -p "$d"
  [ -s "$d/owner.key" ] || for k in owner root evm; do printf '0x%s\n' "$(openssl rand -hex 32)" >"$d/$k.key"; done
  chmod 600 "$d"/*.key
  jq -n --arg owner "$(cat "$d/owner.key")" --arg root "$(cat "$d/root.key")" --arg evm "$(cat "$d/evm.key")" \
    --arg w "0x$(printf 'x4-shadow/withdrawal/%s' "$n" | shasum -a 256 | cut -c1-40)" --arg p "0x$(printf 'x4-shadow/payee/%s' "$n" | shasum -a 256 | cut -c1-40)" \
    --arg rid "x4-shadow-root-$n" --arg eid "x4-shadow-evm-$n" \
    '{ownerKey: $owner, rootKey: $root, evmKey: $evm, withdrawal: $w, payee: $p, rootNodeId: $rid, evmNodeId: $eid, expiry: 4000000000}' >"$d/spare.json"
  chmod 600 "$d/spare.json"
}
x4_join() { # n step [args]
  local n=$1 step=$2; shift 2
  build/ubft pos-relayer tx join "$step" --eth-rpc "$(x4_eth)" --pos-deployment "$P85_DEPLOY" --joiner "$P85_DIR/spare$n/spare.json" "$@"
}
x4_onboard() { # n units
  local n=$1 units=$2 id owner
  x4_spare_file "$n" || return 1
  owner=$("$P85_CAST" wallet address --private-key "$(cat "$P85_DIR/spare$n/owner.key")") || return 1
  "$P85_CAST" send --rpc-url "$(x4_eth)" --private-key "$(cat "$P85_DIR/joiner/owner.key")" --value "$(python3 -c "print($P85_BOND_UNIT * ($units + 2))")" "$owner" >/dev/null || return 1
  id=$(x4_join "$n" register 2>"$X4_DIR/spare$n-register.log") || { cat "$X4_DIR/spare$n-register.log" >&2; return 1; }
  echo "$id" >"$X4_DIR/spare$n-id"
  x4_join "$n" bond --id "$id" --value-wei "$(python3 -c "print($P85_BOND_UNIT * $units)")" || return 1
  x4_join "$n" admit --id "$id" || return 1
  echo "spare $n: custody id $id, $units unit(s), live count $(x4_live_count)"
}

# the election is due when the registry's progress and UC time have passed both thresholds (the chain, with no election hook, does nothing about it)
x4_due() {
  local th_p th_t p t
  read -r th_p th_t < <(x4_call "$(x4_election)" 'thresholds()(uint256,uint256)' | awk '{print $1}' | tr '\n' ' ')
  p=$(x4_num "$(x4_registry)" 'progress()(uint64)'); t=$(x4_num "$(x4_registry)" 'ucTime()(uint64)')
  [ -n "$th_p" ] && [ "$p" -ge "$th_p" ] && [ "$t" -ge "$th_t" ]
}
x4_wait_due() {
  local i
  for i in $(seq 1 1800); do x4_due && { echo "the election is due (after $i s)"; return 0; }; sleep 1; done
  echo "the election did not become due in 1800 s" >&2; return 1
}
x4_passive() {
  x4_wait_due || return 1
  [ "$(x4_call "$(x4_election)" 'attemptCursor()(uint64)')" = 0 ] || { echo "an election attempt was recorded on a chain with no election hook" >&2; return 1; }
}

x4_run_lane() {
  local s
  mkdir -p "$X4_DIR"; rm -f "$X4_DIR/stop"
  H3_ONLINE="1 2 3 4"
  echo "=== X4 shadow lane: PoS genesis, records hook, NO authoritative election; the shadow adapter samples certified state ==="
  x4_step baseline x4_baseline
  python3 scripts/shadow/adapter.py run --rpc "$(x4_eth)" --deployment "$P85_DIR/genesis/deployment.json" --out "$X4_DIR/adapter" \
    --cadence "$X4_CADENCE" --samples 100000 --stop-file "$X4_DIR/stop" >"$X4_DIR/adapter.log" 2>&1 &
  X4_ADAPTER_PID=$!
  echo "adapter pid $X4_ADAPTER_PID (cadence ${X4_CADENCE}s, log $X4_DIR/adapter.log)"
  x4_step passive x4_passive
  sleep "$X4_PHASE_SECONDS"                      # the unchanged candidate, sampled
  x4_step "spare 1: a one-unit identity" x4_onboard 1 1
  sleep "$X4_PHASE_SECONDS"                      # a valid changed candidate, sampled
  x4_step "spare 2: a four-unit identity" x4_onboard 2 4
  sleep "$X4_PHASE_SECONDS"                      # a candidate beyond the weight bound: refused, sampled
  touch "$X4_DIR/stop"
  wait "$X4_ADAPTER_PID"; local rc=$?
  X4_ADAPTER_PID=
  cp "$X4_DIR/adapter/REPORT.md" "$X4_DIR/REPORT.md" 2>/dev/null || true
  local status; status=$(jq -r .status "$X4_DIR/adapter/report.json" 2>/dev/null)
  echo "shadow adapter exit $rc, status ${status:-none}: $(jq -c '{scheduled,accounted,verdicts,dueComparisons,cases}' "$X4_DIR/adapter/report.json" 2>/dev/null)"
  [ "$rc" != 0 ] && x4_die "the shadow adapter reported a divergence (FAIL), see $X4_DIR/adapter"
  [ "$status" = PASS ] || x4_die "the shadow adapter's status is ${status:-none}, not PASS: $(jq -r '.reasons | join("; ")' "$X4_DIR/adapter/report.json" 2>/dev/null)"
  x4_step "the chain stayed passive" x4_still_passive
  echo "X4 shadow lane: all steps PASSED"
  q3_teardown
}
x4_still_passive() {
  [ "$(x4_call "$(x4_election)" 'attemptCursor()(uint64)')" = 0 ] && p85_assert_shadow_roots
}
x4_lane_may_run() {
  [ "${P85_LANE_LOCKED:-0}" = 1 ] && [ "${P85_LANE_DEFINE_ONLY:-0}" != 1 ] && [ "${P85_SHADOW:-0}" = 1 ] || return 1
  [ "$(cat "${DEVNET_LOCK_DIR:-$PWD/../.devnet-lock}/owner" 2>/dev/null)" = p85-recovery ]
}
if x4_lane_may_run; then x4_run_lane; fi
