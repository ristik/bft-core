# X4 B6c: the reward steps of the PoS campaign on the RECOVERY lane's chain (election, custody, offences, exit on the same accumulated state), not on the shadow chain they were
# proven on (X4_REWARDS, scripts/x4-shadow-steps.sh). Definitions only: sourcing this file starts nothing. Lane steps (p85_step): x4r_intervals, x4r_dry_refill, x4r_claim.
# The pool is a small genesis alloc (P85_REWARD_FUNDING, run-lane sets it for run-inputs "rewards": true), so it runs dry; x4e_run (scripts/p85-recovery-steps.sh) runs the same
# scripts/x4pos/steps/reward-*.sh the driver runs. NOT yet proven on this chain: whether the settle/replay agree with the K -> J -> K acknowledged history and the slashed lots.

# WHAT THE CHAIN CAN SHOW. RewardPool.closeInterval (unicity-pos-contracts b17829ca, src/p85/RewardPool.sol:271-290) reverts NotCaughtUp for the TAIL of the latest assignment while
# ELECTION.openResult() != 0, and on this authoritative-election chain a result is open from the baseline on (live probe, x4-rew-4: openResult non-zero, every cursor equal, closeInterval ->
# NotCaughtUp). Only ENDED segments close: the genesis K segment (ended by the J install) and the J segment (ended by the recovery) = 2 intervals, at any progress. So on this chain the
# campaign shows 2 closed intervals, a pool that runs dry (a 0.5 UCT pool: interval 1 takes it all, interval 2 is at zero budget), the refill transaction and a payee's claim, all under the
# accounting checker. NOT shown here: a LATER interval paid after the refill, or 4 intervals (both are shown by the shadow-chain x4-rewards lane; campaign.json lists them as notCovered).
# The steps run after the epoch switches, when the J segment has ended.
X4R_PROGRESS=${X4R_PROGRESS:-3600}   # the registry's progress waited for before the first settle (as in the shadow rewards lane)
X4R_MIN_INTERVALS=${X4R_MIN_INTERVALS:-2}

# every term of RewardPool.closeInterval's precondition (src/p85/RewardPool.sol:271-290), printed when a reward step fails, so the next run says WHICH one held
x4r_diag() {
  local pool reg cus el out=${X4A_DIR:-$H3_DIR/x4pos}/rewards-diag.txt; pool=$(jq -r .rewardPool "$P85_DEPLOY"); reg=$(jq -r .registry "$P85_DEPLOY"); cus=$(jq -r .custody "$P85_DEPLOY"); el=$(jq -r .election "$P85_DEPLOY")
  mkdir -p "$(dirname "$out")"
  {
    echo "x4r diag $(date -u +%FT%TZ)"
    for c in "pool recordCursor $pool recordCursor()(uint64)" "pool nextStart $pool nextStart()(uint64)" "pool segmentCursor $pool segmentCursor()(uint256)" "pool START $pool START()(uint64)" \
             "pool available $pool available()(uint256)" "roots progress $reg progress()(uint64)" "roots recordCount $reg recordCount()(uint64)" "custody recordCursor $cus recordCursor()(uint64)" "election openResult $el openResult()(bytes32)"; do
      set -- $c; local n="$1 $2" to=$3 sig=$4
      echo "$n = $(p85_call "$to" "$sig" 2>&1 | head -n 2 | tr '\n' ' ')"
    done
    echo "closeInterval simulation: $("$P85_CAST" call --rpc-url "$(p85_eth)" --from "$("$P85_CAST" wallet address --private-key "$(tr -d '[:space:]' <"$(p85_sender_key)")")" "$pool" 'closeInterval()' 2>&1 | head -n 3 | tr '\n' ' ')"
    echo "advanceRecords simulation: $("$P85_CAST" call --rpc-url "$(p85_eth)" "$pool" 'advanceRecords(uint32)' 64 2>&1 | head -n 3 | tr '\n' ' ')"
  } | tee "$out" >&2
}

x4r_intervals() {
  local p i reg; reg=$(jq -r .registry "$P85_DEPLOY")
  for i in $(seq 1 7200); do
    p=$(p85_call "$reg" 'progress()(uint64)' | awk 'NR==1{print $1}'); [ "${p:-0}" -ge "$X4R_PROGRESS" ] && break; sleep 1
  done
  [ "${p:-0}" -ge "$X4R_PROGRESS" ] || { echo "x4r: the registry's progress did not reach $X4R_PROGRESS in 7200 s (at ${p:-none})" >&2; return 1; }
  x4e_run ri1 reward-interval.sh "{\"minIntervals\":$X4R_MIN_INTERVALS}" && x4e_run ri1 reward-interval.check.sh "{\"minIntervals\":$X4R_MIN_INTERVALS}" || { x4r_diag; return 1; }
}

# the dry pool and its refill (awaitPaid false: no later interval is expected on this chain)
x4r_dry_refill() {
  x4e_run xr reward-exhaust-refill.sh '{"refillWei":"1500000000000000000","awaitPaid":"false"}' && x4e_run xr reward-exhaust-refill.check.sh '{"awaitPaid":"false"}' || { x4r_diag; return 1; }
}

# a payee (genesis payee 1, a key the lane holds) claims its whole credit to a fresh address: exact amounts, the pool's balance, availability and totalCredits move by the credit and
# nothing else, and the claim is a Claimed event the collector reads (the first live use of its pool-payment decoding)
x4r_claim() {
  local pool key payee to credit bal0 pool0 total0
  pool=$(jq -r .rewardPool "$P85_DEPLOY"); key=$P85_DIR/payee-keys/payee-1.key
  [ -s "$key" ] || { echo "x4r: no payee key (X4_REWARDS_POS makes the genesis plan keep them)" >&2; return 1; }
  payee=$("$P85_CAST" wallet address --private-key "$(cat "$key")")
  credit=$(p85_call "$pool" 'credits(address)(uint256)' "$payee" | awk '{print $1}')
  python3 -c "import sys;sys.exit(0 if $credit > 0 else 1)" || { echo "x4r: payee 1 has no credit to claim ($credit)" >&2; return 1; }
  to=0x$(printf 'x4r/reward-recipient' | shasum -a 256 | cut -c1-40)
  rw_send_value "$(p85_sender_key)" "$payee" "$RW_GAS_WEI" || return 1   # gas for the payee's claim
  bal0=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$to"); pool0=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$pool"); total0=$(p85_call "$pool" 'totalCredits()(uint256)' | awk '{print $1}')
  build/ubft pos-relayer tx reward claim --eth-rpc "$(rw_eth_all)" --pos-deployment "$P85_DEPLOY" --sender-key "$key" --amount-wei "$credit" --to "$to" || return 1
  rw_assert "$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$to") == $bal0 + $credit and $pool0 - $("$P85_CAST" balance --rpc-url "$(p85_eth)" "$pool") == $credit and $total0 - $(p85_call "$pool" 'totalCredits()(uint256)' | awk '{print $1}') == $credit and $(p85_call "$pool" 'credits(address)(uint256)' "$payee" | awk '{print $1}') == 0" \
    "x4r: the claim of $credit wei moved other amounts than the credit" || return 1
  echo "PASS: x4r: payee 1 claimed exactly its credit $credit wei"
}
