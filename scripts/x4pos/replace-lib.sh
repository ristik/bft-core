#!/usr/bin/env bash
# X4 #58 step B2b, slice 1 (research): what the chain does when the primary committee J = K + joiner STAYS alive after the install, i.e. an ordinary acknowledged membership
# change and not the lane's stalled-J recovery. Definitions only; sourced by scripts/p85-recovery-steps.sh when X4_REPLACE_LANE=1 (which runs the lane up to the install and then x4r_observe).
# Registry record kinds (p85_log_dump): 1 SessionClosed, 2 Ack, 3 RecoveryAck, 4 Closure. No assertion about the replacement is made here: the step records the facts the real
# replace step (and its manifest budgets) needs, and fails only if nothing is acknowledged within the wait.

x4r_observe() {
  local d=$H3_DIR/x4r t0 now g acked n=0 i waited=${X4R_WAIT_SECONDS:-1500}
  mkdir -p "$d"
  g=$(p85_last_acked | tr 'A-F' 'a-f')
  t0=$(date +%s)
  : >"$d/timeline.jsonl"
  while :; do
    now=$(date +%s)
    acked=$(p85_last_acked | tr 'A-F' 'a-f')
    jq -nc --argjson t "$((now - t0))" --arg acked "$acked" --argjson cursor "$(p85_cursor)" --argjson count "$(p85_log_count)" --argjson target "$(p85_log_target)" \
      --argjson head "$("$P85_CAST" block-number --rpc-url "$(p85_eth)")" --argjson live "$(p85_live_count)" \
      '{tSeconds:$t, lastAcked:$acked, recordCursor:$cursor, recordCount:$count, recordTarget:$target, evmHead:$head, electionLive:$live}' >>"$d/timeline.jsonl"
    [ "$acked" = "$g" ] || break
    [ $((now - t0)) -lt "$waited" ] || break
    n=$((n + 1)); [ $((n % 6)) -ne 0 ] || echo "x4r: waiting for an acknowledgement of the new committee ($((now - t0)) s, evm head $("$P85_CAST" block-number --rpc-url "$(p85_eth)"))"
    x4r_tick
  done
  p85_log_dump >"$d/registry-log.txt" || return 1
  jq -n --arg genesis "$g" --arg acked "$acked" --argjson waitedSeconds "$((now - t0))" --argjson kinds "$(awk '{print $2}' "$d/registry-log.txt" | sort | uniq -c | awk '{printf "%s\"%s\":%s", (NR>1?",":"{"), $2, $1} END {print "}"}')" \
    '{genesisAssignment:$genesis, lastAcknowledged:$acked, acknowledgedChanged:($genesis != $acked), recordKinds:$kinds, observedSeconds:$waitedSeconds}' >"$d/observe.json"
  cat "$d/observe.json"
  [ "$acked" != "$g" ] || { echo "x4r: no new assignment was acknowledged within ${waited}s (see $d/timeline.jsonl)" >&2; return 1; }
}
# one paid transfer per tick, sent to every online validator (the lane's pools do not gossip), keeps the shard's blocks moving: a harness measure, as scripts/x4pos/lib.sh x4p_tick
source scripts/lib/rewards-lib.sh
x4r_tick() { rw_send_value "$(p85_sender_key)" 0x000000000000000000000000000000000000dEaD 1 >/dev/null 2>&1 || sleep 5; }
