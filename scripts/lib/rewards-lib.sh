#!/usr/bin/env bash
# T8 lane step (briefs/t8-p7-design.md, section 7.4): the funded operator reward pool over the real acknowledged history of the P85 lane.
# Sourcing this file only DEFINES the step; scripts/p85-recovery-steps.sh adds it to the lane's steps when REWARD_LANE=1, so it runs under the
# devnet lock like every other step and never starts, stops or restarts a node.
#
#   rw_step_settle   fund the pool, let the relayer settle every interval the pool accepts (reading its timeline from the registry's records),
#                    recompute the whole schedule from scratch at one pinned block and compare every cursor and credit, repeat the settlement
#                    (nothing may move), have a payee claim in two parts (the second part is retried after an over-claim is refused), and compare
#                    the exact balances.
#
# The genesis identities' payees hold keys in this lane (scripts/p85-genesis-plan.py with P85_PLAN_PAYEE_KEYS), so a claim is real.

RW_EXTRA_FUNDING_WEI=${RW_EXTRA_FUNDING_WEI:-500000000000000000}   # 0.5 UCT on top of the genesis allocation
RW_GAS_WEI=${RW_GAS_WEI:-20000000000000000}                       # what a payee needs for the gas of its claims

rw_assert() { python3 -c "import sys;sys.exit(0 if ($1) else 1)" || { echo "$2" >&2; return 1; }; }   # wei amounts overflow bash arithmetic
rw_dep() { jq -r ".$1" "$P85_DEPLOY"; }
rw_pool() { rw_dep rewardPool; }
rw_uint() { p85_call "$@" | awk '{print $1}'; }   # a cast call answer that is one unsigned integer
rw_settle_run() { # <log>: settle until the pool accepts nothing more
  build/ubft pos-relayer tx reward settle --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$(p85_sender_key)" --max-steps 200 2>&1 | tee "$1"
  grep -q "reward pool idle after" "$1" || { echo "the reward pool did not go idle (see $1)" >&2; return 1; }
}
rw_check_run() { # <out> [extra funding wei]
  local gen; gen=$(grep -o '0x[0-9a-fA-F]\{64\}' "$P85_DIR/genesis-assignment.txt" | head -1)
  python3 scripts/rewards_check.py check --rpc "$(p85_eth)" --cast "$P85_CAST" --pool "$(rw_pool)" --custody "$(p85_custody)" \
    --registry "$(jq -r .registry "$P85_DEPLOY")" --election "$(p85_election)" --policy "$(jq -r .policy "$P85_DIR/genesis/deployment.json")" \
    --genesis-assignment "$gen" --initial-funding "$(jq -r .rewardFunding "$P85_DIR/genesis/deployment.json")" --extra-funding "${2:-0}" | tee "$1"
  grep -q '^REWARDS-CHECK ok' "$1" || return 1
}

rw_step_settle() {
  local dir=$P85_DIR/run/rewards pool key payee to credit half bal0 bal1 pool0 pool1 total0 total1 funding bal
  mkdir -p "$dir"; pool=$(rw_pool); key=$P85_DIR/payee-keys/payee-1.key
  [[ "$pool" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "the deployment file pins no rewardPool" >&2; return 1; }
  funding=$(jq -r .rewardFunding "$P85_DIR/genesis/deployment.json")
  # 1. the genesis allocation is real: the pool holds it from block 0 and has closed nothing yet
  rw_assert "$(rw_uint "$pool" 'available()(uint256)') == $funding" "the pool does not hold its genesis allocation before any interval is closed" || return 1
  rw_assert "$($P85_CAST balance --rpc-url "$(p85_eth)" "$pool") >= $funding" "the pool balance is below its allocation" || return 1
  # 2. explicit funding on top, through the relayer
  build/ubft pos-relayer tx reward fund --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$(p85_sender_key)" --value-wei "$RW_EXTRA_FUNDING_WEI" || return 1
  # 3. settle across the real acknowledged history, then recompute everything from scratch and compare
  rw_settle_run "$dir/settle-1.log" || return 1
  rw_check_run "$dir/check-1.txt" "$RW_EXTRA_FUNDING_WEI" || return 1
  # 4. retry: a second settlement does nothing and moves nothing
  rw_settle_run "$dir/settle-2.log" || return 1
  grep -q "idle after 0 step" "$dir/settle-2.log" || { echo "a repeated settlement moved the pool (see $dir/settle-2.log)" >&2; return 1; }
  rw_check_run "$dir/check-2.txt" "$RW_EXTRA_FUNDING_WEI" || return 1
  diff <(sed 's/"block": [0-9]*, //' "$dir/check-1.txt") <(sed 's/"block": [0-9]*, //' "$dir/check-2.txt") >/dev/null \
    || { echo "the pool's state differs between the two checks although nothing was sent" >&2; return 1; }
  # 5. a payee claims in two parts; an over-claim is refused; exact balances
  [ -s "$key" ] || { echo "no payee key (REWARD_LANE sets P85_PLAN_PAYEE_KEYS before the plan)" >&2; return 1; }
  payee=$("$P85_CAST" wallet address --private-key "$(cat "$key")")
  credit=$(rw_uint "$pool" 'credits(address)(uint256)' "$payee")
  rw_assert "${credit:-0} > 1" "payee 1 has no credit to claim ($credit)" || return 1
  to=0x$(printf 'p85-lane/reward-recipient' | shasum -a 256 | cut -c1-40)
  "$P85_CAST" send --rpc-url "$(p85_eth)" --private-key "$(cat "$(p85_sender_key)")" --value "$RW_GAS_WEI" "$payee" >/dev/null || return 1
  bal0=$($P85_CAST balance --rpc-url "$(p85_eth)" "$to"); pool0=$($P85_CAST balance --rpc-url "$(p85_eth)" "$pool"); total0=$(rw_uint "$pool" 'totalCredits()(uint256)')
  half=$(python3 -c "print($credit // 2)")
  build/ubft pos-relayer tx reward claim --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$key" --amount-wei "$half" --to "$to" || return 1
  bal1=$($P85_CAST balance --rpc-url "$(p85_eth)" "$to"); pool1=$($P85_CAST balance --rpc-url "$(p85_eth)" "$pool"); total1=$(rw_uint "$pool" 'totalCredits()(uint256)')
  rw_assert "$bal1 - $bal0 == $half and $pool0 - $pool1 == $half and $total0 - $total1 == $half and $(rw_uint "$pool" 'credits(address)(uint256)' "$payee") == $credit - $half" \
    "the first claim moved other amounts than $half (recipient +$((bal1 - bal0)), pool balance $pool0 -> $pool1, totalCredits $total0 -> $total1)" || return 1
  if build/ubft pos-relayer tx reward claim --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$key" \
       --amount-wei "$(python3 -c "print($credit - $half + 1)")" --to "$to" >"$dir/over-claim.log" 2>&1; then
    echo "an over-claim was paid" >&2; return 1
  fi
  build/ubft pos-relayer tx reward claim --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$key" --amount-wei "$(python3 -c "print($credit - $half)")" --to "$to" || return 1
  rw_assert "$(rw_uint "$pool" 'credits(address)(uint256)' "$payee") == 0" "the payee still has credit after claiming all of it" || return 1
  rw_assert "$($P85_CAST balance --rpc-url "$(p85_eth)" "$to") == $bal0 + $credit" "the recipient did not receive exactly the credit" || return 1
  # 6. conservation: nothing is owed that the pool does not hold, and nothing was forced into it
  bal=$($P85_CAST balance --rpc-url "$(p85_eth)" "$pool")
  rw_assert "$bal == $(rw_uint "$pool" 'available()(uint256)') + $(rw_uint "$pool" 'totalCredits()(uint256)')" "the pool's balance is not available + credits" || return 1
  echo "rewards: settled $(sed -n 's/.*"intervals": \([0-9]*\).*/\1/p' "$dir/check-1.txt") interval(s), claimed $credit wei by payee 1 in two parts"
}
