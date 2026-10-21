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
