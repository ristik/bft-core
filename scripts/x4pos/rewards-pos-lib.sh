# X4 B6c: the reward steps of the PoS campaign on the RECOVERY lane's chain (election, custody, offences, exit on the same accumulated state), not on the shadow chain they were
# proven on (X4_REWARDS, scripts/x4-shadow-steps.sh). Definitions only: sourcing this file starts nothing. Lane steps (p85_step): x4r_intervals, x4r_dry_refill, x4r_claim.
# The pool is a small genesis alloc (P85_REWARD_FUNDING, run-lane sets it for run-inputs "rewards": true), so it runs dry; x4e_run (scripts/p85-recovery-steps.sh) runs the same
# scripts/x4pos/steps/reward-*.sh the driver runs. NOT yet proven on this chain: whether the settle/replay agree with the K -> J -> K acknowledged history and the slashed lots.

# WHAT THE CHAIN CAN SHOW. RewardPool.closeInterval (unicity-pos-contracts, src/p85/RewardPool.sol) closes the TAIL of the latest assignment only up to the open election result's reservation progress
# (contracts#72; before it, it reverted NotCaughtUp for the whole tail while ELECTION.openResult() != 0, and a result was open on this chain from the recovery on, bft-core#814). Ended segments close
# at any progress, and a tail closes interval by interval on the pool's progress grid. On this chain the segments are the genesis K (ended by the J install), J (ended by the recovery), K (ended by the
# second handoff, X4_H2_LANE) and K' (the tail): with the handoff lane no result is open by the time these steps run (the second handoff's Ack, offence 2's lost result rejected by the roots), so the
# campaign closes at least X4R_MIN_INTERVALS = 4 intervals, runs the small pool (0.5 UCT: interval 1 takes it all, the later ones are at zero budget) dry, refills it and then sees a LATER interval paid
# (awaitPaid), and a payee's exact claim, all under the accounting checker. Without the handoff lane (the first design) only the 2 ended segments close and no later interval is paid after the refill.
# The steps run after the epoch switches, when the J segment has ended.
X4R_PROGRESS=${X4R_PROGRESS:-3600}   # the registry's progress waited for before the first settle (as in the shadow rewards lane)
X4R_MIN_INTERVALS=${X4R_MIN_INTERVALS:-$([ "${X4_H2_LANE:-0}" = 1 ] && echo 4 || echo 2)}

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

# the dry pool and its refill. With the handoff lane (X4_H2_LANE) a LATER interval must be paid after the refill (awaitPaid, as the shadow chain shows); without it none is expected on this chain
x4r_dry_refill() {
  local await=false wait=900
  [ "${X4_H2_LANE:-0}" != 1 ] || { await=true; wait=${X4R_AWAIT_SECONDS:-2400}; }
  x4e_run xr reward-exhaust-refill.sh "{\"refillWei\":\"1500000000000000000\",\"awaitPaid\":\"$await\",\"waitSeconds\":$wait}" && x4e_run xr reward-exhaust-refill.check.sh "{\"awaitPaid\":\"$await\"}" || { x4r_diag; return 1; }
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
