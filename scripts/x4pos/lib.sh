#!/usr/bin/env bash
# X4 #58 step B: what the PoS scenario steps (scripts/x4pos/steps/*.sh) share. Sourcing this file only DEFINES functions and variables: it never starts, stops or
# restarts a node and never sends a transaction.
#
# A step runs as a child of scripts/x4pos/driver.py, which exports X4_STEP_ID, X4_STEP_DIR, X4_CURSOR_DIR, X4_SEED and X4_STEP_ARGS (JSON). The devnet the steps act on is
# described by $X4_CURSOR_DIR/env.sh, written by the lane that built it (exports P85_DIR, P85_CAST, rethEthBase, H3_ONLINE, M2_CHAIN_ID, LANE_TOOLS_DIR and PATH): the steps
# are plain processes, so nothing of the lane's shell state is assumed.

: "${X4_CURSOR_DIR:?run under scripts/x4pos/driver.py}" "${X4_STEP_DIR:?run under scripts/x4pos/driver.py}"
mkdir -p "$X4_STEP_DIR" "$X4_CURSOR_DIR/state"
# shellcheck disable=SC1091
[ -r "$X4_CURSOR_DIR/env.sh" ] && source "$X4_CURSOR_DIR/env.sh"
source scripts/lib/portable.sh
source scripts/lib/p85-lib.sh

P85_DEPLOY=${P85_DEPLOY:-$P85_DIR/pos-deployment.json}
# the same one-liners as scripts/p85-recovery-steps.sh (which cannot be sourced: it acts at source time under the lane's lock)
declare -F p85_eth >/dev/null || p85_eth() { echo "http://127.0.0.1:$rethEthBase"; }
declare -F p85_custody >/dev/null || p85_custody() { jq -r .custody "$P85_DEPLOY"; }
declare -F p85_election >/dev/null || p85_election() { jq -r .election "$P85_DEPLOY"; }
declare -F p85_call >/dev/null || p85_call() { "$P85_CAST" call --rpc-url "$(p85_eth)" "$@"; }
declare -F p85_sender_key >/dev/null || p85_sender_key() { echo "$P85_DIR/joiner/owner.key"; }
source scripts/lib/rewards-lib.sh

x4p_arg() { local a=${X4_STEP_ARGS:-}; [ -n "$a" ] || a='{}'; jq -r --arg k "$1" --arg d "${2-}" '.[$k] // $d' <<<"$a"; }
x4p_log() { printf '%s %s: %s\n' "$(date -u +%FT%TZ)" "${X4_STEP_ID:-step}" "$*" | tee -a "$X4_STEP_DIR/step.log" >&2; }
x4p_die() { x4p_log "FAIL: $*"; return 1; }

# ---- rewards (B3) ------------------------------------------------------------------------------------------------------------------------------------------

# The pool's whole life replayed event by event against the chain (scripts/rewards_check.py replay): every closed interval, every funding and every claim, with the
# funding available at that moment, so an interval closed while the pool was empty is checked to have stayed at budget 0. Extra flags pass through; the output line
# goes to $1.
x4p_reward_replay() { # <out file> [rewards_check.py replay flags]
  local out=$1 gen; shift
  gen=$(grep -o '0x[0-9a-fA-F]\{64\}' "$P85_DIR/genesis-assignment.txt" | head -1)
  python3 scripts/rewards_check.py replay --rpc "$(p85_eth)" --cast "$P85_CAST" --pool "$(rw_pool)" --custody "$(p85_custody)" \
    --registry "$(jq -r .registry "$P85_DEPLOY")" --election "$(p85_election)" --policy "$(jq -r .policy "$P85_DIR/genesis/deployment.json")" \
    --genesis-assignment "$gen" --initial-funding "$(jq -r .rewardFunding "$P85_DIR/genesis/deployment.json")" "$@" | tee "$out"
  grep -q '^REWARDS-REPLAY ok' "$out"
}
x4p_replay_field() { sed -n 's/^REWARDS-REPLAY ok //p' "$1" | jq -r ".$2"; }   # <out file> <field>

# conservation at one block: nothing is owed that the pool does not hold, and (no value is ever forced into the pool in this campaign) nothing is held that is not allocated
x4p_reward_conserved() {
  local pool bal avail credits
  pool=$(rw_pool); bal=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$pool"); avail=$(rw_uint "$pool" 'available()(uint256)'); credits=$(rw_uint "$pool" 'totalCredits()(uint256)')
  rw_assert "$bal == $avail + $credits" "the pool's balance $bal is not available $avail + credits $credits"
}

# reward-interval: settle everything the pool accepts, replay its whole life, require the closed intervals so far to be at least args.minIntervals, conservation.
x4p_reward_interval() {
  local min out=$X4_STEP_DIR/replay.txt
  min=$(x4p_arg minIntervals 0)
  rw_settle_run "$X4_STEP_DIR/settle.log" || return 1
  x4p_reward_replay "$out" || return 1
  [ "$(x4p_replay_field "$out" intervals)" -ge "$min" ] || x4p_die "fewer than $min intervals are closed ($(x4p_replay_field "$out" intervals))" || return 1
  x4p_reward_conserved || return 1
  x4p_log "settled; $(x4p_replay_field "$out" intervals) interval(s) closed, $(x4p_replay_field "$out" paid) paid, $(x4p_replay_field "$out" zeroBudget) at zero budget"
}
x4p_reward_interval_check() { # read-only: the replay agrees with the chain and enough intervals are closed
  local min out=$X4_STEP_DIR/check-replay.txt; min=$(x4p_arg minIntervals 0)
  x4p_reward_replay "$out" >/dev/null && [ "$(x4p_replay_field "$out" intervals)" -ge "$min" ]
}

# reward-exhaust-refill: the pool, funded small at genesis, has run dry (a closed interval at zero budget while the rate is positive); fund() it through the relayer
# AFTER every earlier interval is closed (nothing is backfilled), wait for a later interval to be paid, and replay the whole life with both facts required.
x4p_reward_exhaust_refill() {
  local refill wait out=$X4_STEP_DIR/replay-before.txt i
  refill=$(x4p_arg refillWei 2000000000000000000); wait=$(x4p_arg waitSeconds 900)
  rw_settle_run "$X4_STEP_DIR/settle-before.log" || return 1
  x4p_reward_replay "$out" --require-exhaustion || x4p_die "the pool never ran dry before the refill: the genesis funding is too large for this schedule" || return 1
  [ "$(x4p_replay_field "$out" zeroBudget)" -ge 1 ] || x4p_die "no zero-budget interval was observed before the refill" || return 1
  if ! x4p_reward_replay "$X4_STEP_DIR/replay-probe.txt" --require-refill >/dev/null 2>&1; then   # not funded yet (a resumed step must not fund twice)
    build/ubft pos-relayer tx reward fund --eth-rpc "$(rw_eth_all)" --pos-deployment "$P85_DEPLOY" --sender-key "$(p85_sender_key)" --value-wei "$refill" || return 1
  fi
  for i in $(seq 1 "$wait"); do
    rw_settle_run "$X4_STEP_DIR/settle-after.log" >/dev/null 2>&1 || true
    x4p_reward_replay "$X4_STEP_DIR/replay-after.txt" --require-exhaustion --require-refill >/dev/null 2>&1 && break
    sleep 1
  done
  x4p_reward_replay "$X4_STEP_DIR/replay-after.txt" --require-exhaustion --require-refill || x4p_die "no interval was paid after the refill within ${wait}s" || return 1
  x4p_reward_conserved || return 1
  x4p_log "refilled $refill wei after $(x4p_replay_field "$X4_STEP_DIR/replay-before.txt" zeroBudget) zero-budget interval(s); $(x4p_replay_field "$X4_STEP_DIR/replay-after.txt" paid) paid interval(s) in all"
}
x4p_reward_exhaust_refill_check() { x4p_reward_replay "$X4_STEP_DIR/check-replay.txt" --require-exhaustion --require-refill >/dev/null; }

# ---- exits (B3b) ---------------------------------------------------------------------------------------------------------------------------------------------
# An exit is the owner's one call, requestRetirement(id), on custody: every root started with --pos-deployment and --pos-evm-rpc finds the RetirementRequested log, builds
# the Retirement control against its parent's EVM state and proposes it (arch ruling (c), briefs/x4-retirement-control-design.md); the step only waits for RetirementImported.
# Nothing here POSTs to a node. The identity is args.id, or args.operator looked up in $X4_CURSOR_DIR/state/operators.json ({"<operator>": <stakingId>}, written by the
# replacement steps).

x4p_exit_id() {
  local id op
  id=$(x4p_arg id ""); [ -z "$id" ] || { echo "$id"; return; }
  op=$(x4p_arg operator ""); [ -n "$op" ] && [ -r "$X4_CURSOR_DIR/state/operators.json" ] || { x4p_die "no args.id and no operator mapping for '$op'"; return 1; }
  id=$(jq -er --arg o "$op" '.[$o]' "$X4_CURSOR_DIR/state/operators.json") || { x4p_die "operator '$op' is not in operators.json"; return 1; }
  echo "$id"
}
x4p_exit() { # <exit_check.py subcommand> <id> [flags]
  local sub=$1 id=$2; shift 2
  python3 scripts/x4pos/exit_check.py "$sub" --rpc "$(p85_eth)" --cast "$P85_CAST" --custody "$(p85_custody)" --id "$id" "$@"
}
x4p_exit_field() { jq -r ".$2" "$1"; }   # <state json> <field>
x4p_owner_key() { echo "$P85_DIR/owner-keys/owner-$1.key"; }
x4p_withdrawal_key() { echo "$P85_DIR/owner-keys/withdrawal-$1.key"; }
x4p_address_of() { "$P85_CAST" wallet address --private-key "0x$(tr -d '[:space:]' <"$1" | sed 's/^0x//')"; }
# a contract call from a key file: <key file> <to> <signature> [args...]; the gas limit is fixed (no estimate: see rw_send_value)
x4p_send_call() {
  local key=$1 to=$2 sig=$3; shift 3
  RW_SEND_DATA=$("$P85_CAST" calldata "$sig" "$@") RW_SEND_GAS=${X4P_CALL_GAS:-400000} rw_send_value "$key" "$to" 0
}
# the key's account holds enough for a call (the genesis owners are funded nothing): top up from the lane's sender
x4p_ensure_gas() { # <key file>
  local addr bal; addr=$(x4p_address_of "$1") || return 1
  bal=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$addr")
  rw_assert "$bal >= 20000000000000000" "" 2>/dev/null || rw_send_value "$(p85_sender_key)" "$addr" 100000000000000000
}
# the proposer's own evidence from the roots' logs: one JSON line per 'retirement requested' / 'retirement proof ready' of this identity
x4p_exit_root_log() { # <id> <out file>
  local id=$1 out=$2 f
  : >"$out"
  for f in test-nodes/root*/debug.log; do
    [ -r "$f" ] || continue
    grep -E "retirement (requested|proof ready)" "$f" | grep -E "[[:space:]]id=$id([[:space:]]|$)" | sed "s|^|$(dirname "$f" | xargs basename) |" >>"$out" || true
  done
}

# exit-request: wait until the identity has no live exposure, call requestRetirement from the owner key, wait for the Retirement to be imported; request.json is the evidence.
x4p_exit_request() {
  local id st="$X4_STEP_DIR/state-before.json" wait_exp imp key t0 now blk=
  id=$(x4p_exit_id) || return 1; key=$(x4p_owner_key "$id")
  [ -r "$key" ] || x4p_die "no owner key $key (the campaign needs X4_HELD_KEYS=1)" || return 1
  wait_exp=$(x4p_arg exposureWaitSeconds 600); imp=$(x4p_arg importWaitSeconds 900)
  t0=$(date +%s)
  while :; do
    x4p_exit state "$id" >"$st" || return 1
    [ "$(x4p_exit_field "$st" liveExposures)" -eq 0 ] && break
    [ $(( $(date +%s) - t0 )) -lt "$wait_exp" ] || x4p_die "identity $id still has $(x4p_exit_field "$st" liveExposures) live exposure(s) after ${wait_exp}s" || return 1
    sleep 2
  done
  if [ "$(x4p_exit_field "$st" retirementRequested)" != true ]; then   # a resumed step must not request twice
    x4p_ensure_gas "$key" || return 1
    x4p_send_call "$key" "$(p85_custody)" 'requestRetirement(uint64)' "$id" || x4p_die "requestRetirement($id) was not mined" || return 1
    blk=$("$P85_CAST" block-number --rpc-url "$(p85_eth)")
    x4p_log "requestRetirement($id) mined by block $blk"
  fi
  t0=$(date +%s)
  while :; do
    x4p_exit state "$id" >"$X4_STEP_DIR/state-after.json" || return 1
    [ "$(x4p_exit_field "$X4_STEP_DIR/state-after.json" imported)" = true ] && break
    [ $(( $(date +%s) - t0 )) -lt "$imp" ] || { x4p_exit_root_log "$id" "$X4_STEP_DIR/roots.log"; x4p_die "the Retirement of identity $id was not imported within ${imp}s (roots.log has what the proposers logged)"; return 1; }
    sleep 3
  done
  now=$(date +%s)
  x4p_exit_root_log "$id" "$X4_STEP_DIR/roots.log"
  grep -q 'retirement proof ready' "$X4_STEP_DIR/roots.log" || x4p_die "the Retirement was imported but no root logged 'retirement proof ready' for identity $id" || return 1
  jq -n --argjson st "$(cat "$X4_STEP_DIR/state-after.json")" --arg blk "${blk:-}" --argjson waited "$((now - t0))" \
    '{id:$st.id, generation:$st.generation, requestBlock:(if $blk=="" then null else ($blk|tonumber) end), imported:$st.imported, pRet:$st.pRet, tRet:$st.tRet, importWaitSeconds:$waited, lots:($st.lots|length)}' >"$X4_STEP_DIR/request.json"
  x4p_log "identity $id: Retirement imported (pRet $(x4p_exit_field "$X4_STEP_DIR/request.json" pRet), tRet $(x4p_exit_field "$X4_STEP_DIR/request.json" tRet))"
}
x4p_exit_request_check() { # read-only: requested, imported, and a root logged the proof
  local id; id=$(x4p_exit_id) || return 1
  x4p_exit state "$id" >"$X4_STEP_DIR/check-state.json" || return 1
  [ "$(x4p_exit_field "$X4_STEP_DIR/check-state.json" retirementRequested)" = true ] && [ "$(x4p_exit_field "$X4_STEP_DIR/check-state.json" imported)" = true ]
}

# exit-claim: before maturity `mature` refuses for a lawful early reason (never a missing Retirement), then matures exactly the lots' principal into the withdrawal
# credit and claims it to a fresh recipient with exact balance deltas. args.expectReason (EvidenceHoldPending): an offender's exit stays refused (EvidenceHoldPending) while
# its evidence is unsettled, and the step records that refusal before waiting.
x4p_exit_claim() {
  local id st="$X4_STEP_DIR/state-pre.json" wait t0 ids recip credit before wkey out="$X4_STEP_DIR/refusal.json" did_mature=0 expect
  id=$(x4p_exit_id) || return 1; wkey=$(x4p_withdrawal_key "$id")
  [ -r "$wkey" ] || x4p_die "no withdrawal key $wkey (the campaign needs X4_HELD_KEYS=1)" || return 1
  wait=$(x4p_arg matureWaitSeconds 900)
  x4p_exit state "$id" >"$st" || return 1
  [ "$(x4p_exit_field "$st" imported)" = true ] || x4p_die "identity $id has no imported Retirement: run exit-request first" || return 1
  if [ "$(x4p_exit_field "$st" credit)" = 0 ] && ! python3 -c "import json,sys;sys.exit(0 if all(l['category']==4 for l in json.load(open('$st'))['lots']) else 1)"; then   # not yet matured
    x4p_exit refusal "$id" --allow-success >"$out" || return 1   # a refusal must be lawful; a mature-now answer is allowed once the gates have passed
    x4p_log "mature before the gates: $(cat "$out")"
    expect=$(x4p_arg expectReason "")   # the held offender (S4): the first refusal must be the evidence hold, not a gate
    jq --arg e "$expect" '. + {expected: $e}' "$out" >"$out.tmp" && mv "$out.tmp" "$out"
    [ -z "$expect" ] || jq -e --arg e "$expect" '.outcome=="refused" and .reason==$e' "$out" >/dev/null || x4p_die "the exit was not refused for $expect: $(cat "$out")" || return 1
    t0=$(date +%s)
    until x4p_exit refusal "$id" --allow-success 2>/dev/null | jq -e '.outcome=="mature-now"' >/dev/null; do
      [ $(( $(date +%s) - t0 )) -lt "$wait" ] || { x4p_exit refusal "$id" --allow-success >"$X4_STEP_DIR/refusal-last.json" 2>&1 || true; x4p_die "identity $id did not mature within ${wait}s: $(cat "$X4_STEP_DIR/refusal-last.json")"; return 1; }
      sleep 5
    done
    ids="[$(jq -r '[.lots[].id]|map(tostring)|join(",")' "$st")]"
    x4p_ensure_gas "$wkey" || return 1
    x4p_send_call "$wkey" "$(p85_custody)" 'mature(uint256[])' "$ids" || x4p_die "mature($ids) was not mined" || return 1
    did_mature=1
  fi
  # a resumed step that matured before it was interrupted has no "before" to compare with: the credit and lots are checked at the claim instead
  [ "$did_mature" = 0 ] || x4p_exit matured "$id" --before "$st" >"$X4_STEP_DIR/matured.json" || return 1
  credit=$(x4p_exit state "$id" | jq -r .credit)
  if [ "$credit" != 0 ]; then
    recip=$("$P85_CAST" wallet new --json | jq -r '(.data // .)[0].address'); before=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$recip")
    x4p_send_call "$wkey" "$(p85_custody)" 'claim(uint256,address)' "$credit" "$recip" || x4p_die "claim($credit) was not mined" || return 1
    x4p_exit claimed "$id" --recipient "$recip" --recipient-before "$before" --credit "$credit" >"$X4_STEP_DIR/claimed.json" || return 1
    x4p_log "identity $id: matured and claimed $credit wei to $recip"
  fi
}
x4p_exit_claim_check() { # read-only: the lots are released and nothing remains credited
  local id; id=$(x4p_exit_id) || return 1
  x4p_exit state "$id" | python3 -c "import json,sys;s=json.load(sys.stdin);sys.exit(0 if s['lots'] and all(l['category']==4 and l['remaining']==0 for l in s['lots']) and s['credit']==0 else 1)"
}
