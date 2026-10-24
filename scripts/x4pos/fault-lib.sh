# X4 B7: the four faults of the PoS campaign, as lane steps (p85_step), on the ACCUMULATED chain. Definitions only: sourcing this file starts, stops and restarts nothing.
#
# They are lane steps (not driver steps) because they act through the lane shell's node control (h3_restart_roots, stop_one_evm_validator, start_one_evm_validator, the
# signing-authority sessions); a separate process has none of it. Each one waits for its `at` in scripts/x4pos/campaign.json (seconds since the first accounting snapshot, x4f_wait),
# so the faults are spread over the campaign instead of run back to back, then writes $X4F_DIR/<name>.json: what was measured before and after. scripts/x4pos/lane-check.sh
# (phase fault-<name>) reads those files; a fault is done only if the step passed AND its file shows the effect.
#
#   root-restart      the four running roots restart together (the quorum restart of p85_restarts) in the current root epoch; state identical, a paid transaction certifies
#   evm-restart       validator 2 (not the one the lane reads) stops and returns in its scope; its head catches up to validator 1's; a paid transaction certifies
#   pair-restart      validator 3's node AND its execution client (ureth) restart; the head block it retained is byte-identical to validator 1's block of the same number, and the
#                     reward pool (balance, available, credits) and the custody credits are unchanged: the reward-settling side resumes from durable state (orchestrator, 2026-10-24)
#   delayed-episode   ALL four EVM validators stop for X4F_DELAY seconds while the roots keep extending: the shard's import of root extensions is delayed as a whole. After they return the
#                     registry log is contiguous and ordered, the custody cursor has converged, and nothing a gate depends on moved (last acknowledged assignment, open result and its
#                     lost mark, lot count, credits)
# The evidence collector (S4) holds no runtime state and its submitter resumes from the on-chain cursor: both offences already show that (submit-1.txt / submit-2.txt), see campaign.json.

X4F_DIR=${X4F_DIR:-$H3_DIR/x4pos/steps/faults}
X4F_DELAY=${X4F_DELAY:-300}
X4F_CAMPAIGN=${X4F_CAMPAIGN:-scripts/x4pos/campaign.json}

# sleep until the step's `at` (seconds from the first accounting snapshot); a step already past its time runs at once and records how late
x4f_wait() { # <campaign step id>
  local at t0 now late
  at=$(jq -r --arg id "$1" '.steps[] | select(.id == $id) | .at' "$X4F_CAMPAIGN") || return 1
  [[ "$at" =~ ^[0-9]+$ ]] || { echo "x4f: no step $1 in $X4F_CAMPAIGN" >&2; return 1; }
  [ -s "$X4A_DIR/t0" ] || { echo "x4f: no campaign start ($X4A_DIR/t0): no snapshot was taken" >&2; return 1; }
  t0=$(cat "$X4A_DIR/t0"); now=$(( $(date +%s) - t0 ))
  if [ "$now" -lt "$at" ]; then echo "x4f: $1 waits $((at - now)) s (at $at s)"; sleep "$((at - now))"; late=0; else late=$((now - at)); fi
  mkdir -p "$X4F_DIR"; echo "$late" >"$X4F_DIR/$1.late"
}

x4f_probe() { # a JSON object of the chain as the roots and the lane's validator see it
  local ri
  ri=$(h3_root_info | jq -c '{rootRound: .roundNumber, evmRound: (.partitionShards[] | select(.partitionId==8) | .roundNumber)}') || return 1
  jq -c --arg open "$(p85_open_result)" --arg acked "$(p85_last_acked)" --argjson head "$(p85_eth_block)" --argjson cursor "$(p85_cursor)" --argjson count "$(p85_log_count)" \
    --argjson lots "$(p85_call "$(p85_custody)" 'nextLotID()(uint256)' | awk '{print $1}')" --argjson credits "$(p85_call "$(p85_custody)" 'totalCredits()(uint256)' | awk '{print $1}')" \
    '. + {openResult: $open, lastAcked: ($acked | ascii_downcase), head: $head, cursor: $cursor, count: $count, lots: $lots, credits: $credits}' <<<"$ri"
}

# the registry log is a contiguous, ordered sequence: indices 0..n-1, progress and UC time never decreasing (a delayed import must not reorder or skip an anchor)
x4f_log_ordered() {
  p85_log_dump | python3 -c "
import sys
rows = [l.split() for l in sys.stdin if l.strip()]
if not rows: sys.exit('the registry log is empty')
prev = (-1, -1)
for n, r in enumerate(rows):
    idx, p, t = int(r[0]), int(r[2]), int(r[3])
    if idx != n: sys.exit('record %d has index %d' % (n, idx))
    if (p, t) < prev: sys.exit('record %d goes back: progress/UC time %r after %r' % (n, (p, t), prev))
    prev = (p, t)
print(len(rows))"
}

# a validator stopped and started again in its scope (the signing-authority session is replaced as in p85_restart_validator)
x4f_stop_val() { stop_one_evm_validator "$1" || return 1; }
x4f_start_val() { # id
  local i=$1 rootBoot bootnodes
  rootBoot=$(m2_root_addr "$(h3_first_root)") || return 1
  build/ubft signing-authority replace-session --operator-socket "test-nodes/auth$i/operator.sock" --operator-credential "test-nodes/auth$i/operator.cred" \
    --out "test-nodes/auth$i/client.cred" || return 1
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $H3_ONLINE) || return 1
  start_one_evm_validator "$i" "$validators" "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
}
# the execution client alone (copy of q3_restart_reth_same_secret, scripts/q3-weight-activation-steps.sh, which the P85 lane does not source)
x4f_restart_reth() { # entity
  local i=$1 old waited=0
  old=$(cat "test-nodes/reth$i/pid" 2>/dev/null)
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
  while [ -n "$old" ] && kill -0 "$old" 2>/dev/null; do
    waited=$((waited + 1)); [ "$waited" -le 180 ] || { echo "x4f: execution client $old of entity $i still running 90 s after ctrl-c" >&2; return 1; }
    sleep 0.5
  done
  "$URETH_BIN" node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug \
    --rpc.eth-proof-window 64 --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    --engine.persistence-threshold "$d2cPersistenceThreshold" --builder.gaslimit "${URETH_BUILDER_GASLIMIT:-30000000}" \
    $(urethPinUnicityFlags) >>"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
  for _ in $(seq 1 120); do rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_blockNumber '[]' | grep -q '"result"' && return 0; sleep 1; done
  echo "x4f: execution client of entity $i did not answer" >&2; return 1
}
# validator i's block N (hash) over its own RPC
x4f_block_hash() { # entity number
  "$P85_CAST" block --rpc-url "http://127.0.0.1:$((rethEthBase + $1 - 1))" "$2" --json 2>/dev/null | jq -r .hash
}
# validator i reaches at least the head validator 1 had (a restarted node catches up): waits up to 240 s
x4f_caught_up() { # entity targetHead
  local i h
  for i in $(seq 1 240); do
    h=$("$P85_CAST" block-number --rpc-url "http://127.0.0.1:$((rethEthBase + $1 - 1))" 2>/dev/null) && [ "$h" -ge "$2" ] 2>/dev/null && { echo "$h"; return 0; }
    sleep 1
  done
  echo "x4f: validator $1 did not reach block $2 in 240 s" >&2; return 1
}
x4f_epoch() { s4_epoch 1; }
x4f_write() { # name beforeJSON afterJSON extraJSON
  mkdir -p "$X4F_DIR"
  jq -n --argjson b "$2" --argjson a "$3" --argjson x "$4" --arg late "$(cat "$X4F_DIR/${5:-$1}.late" 2>/dev/null || echo 0)" \
    '{fault: "'"$1"'", before: $b, after: $a, stable: ($a.lastAcked == $b.lastAcked and $a.openResult == $b.openResult and $a.lots == $b.lots and $a.credits == $b.credits and $a.cursor >= $b.cursor and $a.count >= $b.count and $a.head >= $b.head), lateSeconds: ($late | tonumber)} + $x' >"$X4F_DIR/$1.json"
}

x4f_root_restart() {
  local before after epoch; x4f_wait fault-root-restart || return 1
  epoch=$(x4f_epoch) || return 1; before=$(x4f_probe) || return 1
  H3_ROOTS="1 2 3 4" h3_restart_roots "$epoch" || return 1
  p85_paid "$epoch" >/dev/null || { echo "x4f: a paid transaction (root epoch $epoch) was not certified after the root restart" >&2; return 1; }
  p85_progress after-root-restart 8 || return 1
  after=$(x4f_probe) || return 1
  x4f_write root-restart "$before" "$after" "$(jq -n --argjson e "$epoch" '{rootEpoch: $e, paidTxOk: true, rootsRestarted: [1,2,3,4]}')" fault-root-restart || return 1
  jq -e '.stable' "$X4F_DIR/root-restart.json" >/dev/null || { echo "x4f: state changed across the root restart: $(cat "$X4F_DIR/root-restart.json")" >&2; return 1; }
  echo "PASS: x4f: root quorum restarted in epoch $epoch; state identical, a paid transaction certifies"
}

x4f_evm_restart() {
  local before after epoch head; x4f_wait fault-evm-restart || return 1
  epoch=$(x4f_epoch) || return 1; before=$(x4f_probe) || return 1; head=$(jq -r .head <<<"$before")
  x4f_stop_val 2 || return 1; sleep 20; x4f_start_val 2 || return 1
  x4f_caught_up 2 "$head" >/dev/null || return 1
  p85_paid "$epoch" >/dev/null || { echo "x4f: a paid transaction was not certified after the validator restart" >&2; return 1; }
  p85_progress after-evm-restart 8 || return 1
  after=$(x4f_probe) || return 1
  x4f_write evm-restart "$before" "$after" "$(jq -n '{validator: 2, paidTxOk: true, caughtUp: true}')" fault-evm-restart || return 1
  jq -e '.stable' "$X4F_DIR/evm-restart.json" >/dev/null || { echo "x4f: state changed across the validator restart: $(cat "$X4F_DIR/evm-restart.json")" >&2; return 1; }
  echo "PASS: x4f: validator 2 restarted in its scope and caught up; a paid transaction certifies"
}

x4f_pair_restart() {
  local before after epoch head pool b0 a0 c0 av0 b1 av1 c1 n h1 h3 x
  x4f_wait fault-pair-restart || return 1
  epoch=$(x4f_epoch) || return 1; before=$(x4f_probe) || return 1; head=$(jq -r .head <<<"$before")
  pool=$(jq -r .rewardPool "$P85_DEPLOY")
  b0=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$pool" | awk '{print $1}'); av0=$(p85_call "$pool" 'available()(uint256)' | awk '{print $1}'); c0=$(p85_call "$pool" 'totalCredits()(uint256)' | awk '{print $1}')
  n=$((head > 3 ? head - 2 : head))
  x4f_stop_val 3 || return 1; x4f_restart_reth 3 || return 1; x4f_start_val 3 || return 1
  x4f_caught_up 3 "$head" >/dev/null || return 1
  p85_paid "$epoch" >/dev/null || { echo "x4f: a paid transaction was not certified after the pair restart" >&2; return 1; }
  p85_progress after-pair-restart 8 || return 1
  h1=$(x4f_block_hash 1 "$n"); h3=$(x4f_block_hash 3 "$n")
  [ -n "$h1" ] && [ "$h1" != null ] && [ "$h1" = "$h3" ] || { echo "x4f: block $n differs after the pair restart: validator 1 $h1, validator 3 $h3" >&2; return 1; }
  b1=$("$P85_CAST" balance --rpc-url "$(p85_eth)" "$pool" | awk '{print $1}'); av1=$(p85_call "$pool" 'available()(uint256)' | awk '{print $1}'); c1=$(p85_call "$pool" 'totalCredits()(uint256)' | awk '{print $1}')
  [ "$b0" = "$b1" ] && [ "$av0" = "$av1" ] && [ "$c0" = "$c1" ] || { echo "x4f: the reward pool moved across the restart: balance $b0->$b1 available $av0->$av1 credits $c0->$c1" >&2; return 1; }
  after=$(x4f_probe) || return 1
  x4f_write pair-restart "$before" "$after" "$(jq -n --argjson n "$n" --arg h "$h1" --arg b "$b1" --arg av "$av1" --arg c "$c1" '{validator: 3, block: $n, blockHash: $h, byteIdentical: true, pool: {balance: $b, available: $av, credits: $c, unchanged: true}, paidTxOk: true}')" fault-pair-restart || return 1
  jq -e '.stable' "$X4F_DIR/pair-restart.json" >/dev/null || { echo "x4f: state changed across the pair restart: $(cat "$X4F_DIR/pair-restart.json")" >&2; return 1; }
  echo "PASS: x4f: validator 3 and its execution client restarted; block $n identical to validator 1's, reward pool and credits unchanged"
}

# all four EVM validators are down while the roots continue: the shard imports no root extension for X4F_DELAY seconds, then everything returns
x4f_delayed_episode() {
  local before mid after epoch i r0 r1 e0 e1 n
  x4f_wait fault-delayed-episode || return 1
  epoch=$(x4f_epoch) || return 1; before=$(x4f_probe) || return 1
  r0=$(jq -r .rootRound <<<"$before"); e0=$(jq -r .evmRound <<<"$before")
  for i in 1 2 3 4; do x4f_stop_val "$i" || return 1; done
  sleep "$X4F_DELAY"
  mid=$(h3_root_info | jq -c '{rootRound: .roundNumber, evmRound: (.partitionShards[] | select(.partitionId==8) | .roundNumber)}') || return 1
  r1=$(jq -r .rootRound <<<"$mid"); e1=$(jq -r .evmRound <<<"$mid")
  [ "$r1" -gt "$((r0 + X4F_DELAY / 3))" ] || { echo "x4f: the roots did not extend during the outage (round $r0 -> $r1)" >&2; return 1; }
  [ "$e1" -le "$((e0 + 1))" ] || { echo "x4f: the EVM shard kept certifying with all validators stopped (round $e0 -> $e1)" >&2; return 1; }
  for i in 1 2 3 4; do x4f_start_val "$i" || return 1; done
  p85_progress after-delayed-episode 10 120 || return 1
  p85_paid "$epoch" >/dev/null || { echo "x4f: a paid transaction was not certified after the delayed episode" >&2; return 1; }
  for i in $(seq 1 120); do [ "$(p85_cursor)" = "$(p85_log_count)" ] && break; sleep 1; done
  n=$(x4f_log_ordered) || return 1
  after=$(x4f_probe) || return 1
  x4f_write delayed-episode "$before" "$after" "$(jq -n --argjson mid "$mid" --argjson d "$X4F_DELAY" --argjson n "$n" '{outageSeconds: $d, during: $mid, rootsExtendedDuringOutage: true, shardFrozenDuringOutage: true, registryRecords: $n, logOrdered: true, paidTxOk: true}')" fault-delayed-episode || return 1
  jq -e '.stable and .after.cursor == .after.count' "$X4F_DIR/delayed-episode.json" >/dev/null || { echo "x4f: after the delayed episode state changed or the cursor did not converge: $(cat "$X4F_DIR/delayed-episode.json")" >&2; return 1; }
  echo "PASS: x4f: shard import delayed ${X4F_DELAY} s (root round $r0 -> $r1, EVM round $e0 -> $e1), then recovered; registry log ordered ($n records), cursor converged, gates unchanged"
}

# the soak between the last fault and the final reconcile: the chain runs on its own and an accounting snapshot is taken every X4F_SOAK_EVERY seconds, so the checker sees the accumulated state over time
X4F_SOAK_EVERY=${X4F_SOAK_EVERY:-1200}
x4f_soak() {
  local until t0 now left n=0
  until=$(jq -r '.steps[] | select(.id == "final-reconcile") | .at' "$X4F_CAMPAIGN") || return 1
  t0=$(cat "$X4A_DIR/t0") || return 1
  while now=$(( $(date +%s) - t0 )); [ "$now" -lt "$until" ]; do
    left=$((until - now)); [ "$left" -le "$X4F_SOAK_EVERY" ] || left=$X4F_SOAK_EVERY
    sleep "$left"; x4a_snapshot || return 1; n=$((n + 1))
  done
  mkdir -p "$X4F_DIR"; jq -n --argjson n "$n" --argjson e "$X4F_SOAK_EVERY" --argjson u "$until" '{snapshots: $n, everySeconds: $e, untilSeconds: $u}' >"$X4F_DIR/soak.json"
  echo "PASS: x4f: soaked to $until s with $n snapshots"
}

# the final reconcile: the registry/custody cursors have converged, a last snapshot, then the reward pool replayed event by event (scripts/x4pos/steps/reconcile.sh)
x4f_reconcile() {
  local cursor count target
  x4f_wait final-reconcile || return 1
  cursor=$(p85_cursor) && count=$(p85_log_count) && target=$(p85_log_target) || return 1
  [ "$cursor" = "$count" ] && [ "$count" = "$target" ] || { echo "x4f: the records did not converge: cursor $cursor count $count target $target" >&2; return 1; }
  x4a_snapshot || return 1
  mkdir -p "$X4F_DIR"; jq -n --argjson c "$cursor" --argjson n "$count" --argjson t "$target" '{cursor: $c, count: $n, target: $t, converged: true}' >"$X4F_DIR/reconcile-cursors.json"
  x4e_run reconcile reconcile.sh '{}' && x4e_run reconcile reconcile.check.sh '{}'
}

# the campaign's verdict: the driver verifies every lane step from the lane's own record and runs the accounting checker over the snapshots (after x4a_final, which writes accounting.txt)
x4_report() {
  X4_LANE_DIR=$H3_DIR/x4pos X4_S4B_DIR=${X4O_DIR:-test-nodes/p85/s4b} python3 scripts/x4pos/driver.py run "$X4F_CAMPAIGN" --dir "$H3_DIR/x4pos" | tee "$H3_DIR/x4pos/driver-report.txt"
}
