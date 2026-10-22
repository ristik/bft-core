#!/usr/bin/env bash
# X4 #58 step B2b, slice 1 (research): what the chain does when the primary committee J = K + joiner STAYS alive after the install, i.e. an ordinary acknowledged membership
# change and not the lane's stalled-J recovery. Definitions only; sourced by scripts/p85-recovery-steps.sh when X4_REPLACE_LANE=1 (which runs the lane up to the install and then x4r_observe).
# Registry record kinds (p85_log_dump): 1 SessionClosed, 2 Ack, 3 RecoveryAck, 4 Closure. No assertion about the replacement is made here: the step records the facts the real
# replace step (and its manifest budgets) needs, and fails only if nothing is acknowledged within the wait. Every sample and every tick is bounded and timestamped: the first run
# (39726416936) printed nothing and was killed by the lane deadline, so a call that does not answer must show as a line, not as silence.

source scripts/lib/rewards-lib.sh

# a command that does not answer within <seconds> is stopped (its own children only) and counts as failed
x4r_bounded() { local sec=$1 pid w rc; shift; "$@" & pid=$!; ( sleep "$sec"; pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null ) & w=$!; wait "$pid"; rc=$?; kill "$w" 2>/dev/null; wait "$w" 2>/dev/null; return $rc; }
x4r_log() { printf '%s x4r: %s\n' "$(date -u +%FT%TZ)" "$*"; }
# one sample of the chain: written to $1 as one JSON line
x4r_sample() { # <out file> <seconds since start>
  jq -nc --argjson t "$2" --arg at "$(date -u +%FT%TZ)" --arg acked "$(p85_last_acked | tr 'A-F' 'a-f')" --argjson cursor "$(p85_cursor)" --argjson count "$(p85_log_count)" \
    --argjson target "$(p85_log_target)" --argjson head "$("$P85_CAST" block-number --rpc-url "$(p85_eth)")" --argjson live "$(p85_live_count)" \
    '{tSeconds:$t, at:$at, lastAcked:$acked, recordCursor:$cursor, recordCount:$count, recordTarget:$target, evmHead:$head, electionLive:$live}' >"$1"
}
# one paid transfer to every online validator keeps the shard's blocks moving (a harness measure, as scripts/x4pos/lib.sh x4p_tick)
x4r_tick() { x4r_bounded 120 rw_send_value "$(p85_sender_key)" 0x000000000000000000000000000000000000dEaD 1 >/dev/null 2>&1 || x4r_log "tick failed or timed out"; }

x4r_observe() {
  local d=$H3_DIR/x4r t0 now g="" acked="" s waited=${X4R_WAIT_SECONDS:-1500} n=0
  mkdir -p "$d"; : >"$d/timeline.jsonl"
  t0=$(date +%s)
  x4r_log "observe starts (wait ${waited}s)"
  while :; do
    now=$(date +%s)
    s=$d/sample.json; rm -f "$s"
    if x4r_bounded 120 x4r_sample "$s" "$((now - t0))" && [ -s "$s" ]; then
      cat "$s" >>"$d/timeline.jsonl"; acked=$(jq -r .lastAcked "$s")
      [ -n "$g" ] || g=$acked
      n=$((n + 1)); [ $((n % 4)) -ne 1 ] || x4r_log "$(cat "$s")"
    else
      jq -nc --argjson t "$((now - t0))" '{tSeconds:$t, sample:"timed out or failed"}' >>"$d/timeline.jsonl"; x4r_log "a sample did not answer within 120 s"
    fi
    [ -z "$g" ] || [ "$acked" = "$g" ] || break
    [ $((now - t0)) -lt "$waited" ] || break
    x4r_tick; sleep 5
  done
  x4r_bounded 300 p85_log_dump >"$d/registry-log.txt" || x4r_log "the registry log could not be dumped"
  jq -n --arg genesis "$g" --arg acked "$acked" --argjson observed "$(( $(date +%s) - t0 ))" --argjson samples "$n" \
    --argjson kinds "$(awk '{print $2}' "$d/registry-log.txt" | sort | uniq -c | awk 'BEGIN{printf "{"} {printf "%s\"%s\":%s", (NR>1?",":""), $2, $1} END {print "}"}')" \
    '{genesisAssignment:$genesis, lastAcknowledged:$acked, acknowledgedChanged:($genesis != "" and $genesis != $acked), recordKinds:$kinds, observedSeconds:$observed, samples:$samples}' >"$d/observe.json"
  cat "$d/observe.json"
  [ -n "$g" ] && [ "$acked" != "$g" ] || { echo "x4r: no new assignment was acknowledged within ${waited}s (see $d/timeline.jsonl)" >&2; return 1; }
}
