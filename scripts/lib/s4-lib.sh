# S4 (#57): the focused live slashing exercise on the P85 lane family (briefs/s4-live-slashing-brief.md; design briefs/s3-evidence-service-design.md §5).
# Definitions only: sourcing this file starts nothing and reads nothing. The steps are selected by S4_LANE=1 (scripts/p85-recovery-steps.sh adds them).
#
#   s4_equivocate               after the install of epoch 2, while the joiner is a committee member: the harness signs two scheme 2 votes of the joiner's root key for one
#                               past epoch-2 round (harness-only alternate signer: the genuine root5 process is untouched) and delivers one to each of two
#                               roots over the real root vote protocol, the second only after the round is behind the receiver (stale)
#   s4_collect_after_rotation   after the recovery to K (the joiner evicted): stop each observer root in turn, copy its journal, restart it; scan each copy alone and both together
#   s4_submit_settle            a third party, holding a fresh funded account and no root or owner key, submits the pair through the real Evidence contract and settles it; the
#                               submitter is killed once between admission and settlement and rerun
#   s4_assert                   the named assertions on the journals, the calldata and the certified EVM effects (scripts/s4/s4_assert.py)

S4_DIR=${S4_DIR:-test-nodes/p85/s4}
S4_OFFENDER_ROOT=${S4_OFFENDER_ROOT:-5}   # the joiner's root

s4_pass() { printf 'PASS: s4: %s\n' "$1"; }
s4_cast() { "${P85_CAST:-cast}" "$@"; }
s4_round() { curl -fsS "$(h3_rpc_url "$1")/api/v1/roundInfo" 2>/dev/null | jq -r '.roundNumber'; }
s4_epoch() { curl -fsS "$(h3_rpc_url "$1")/api/v1/roundInfo" 2>/dev/null | jq -r '.epochNumber'; }
s4_short() { grep -a -m1 -o 'node_id=16\*[A-Za-z0-9]*' "test-nodes/root$1/debug.log" | head -1 | sed 's/node_id=//'; }

# the root that was the leader of round $1+1 (the one a vote of round $1 is sent to), from the roots' own round log; empty if no root logged it
s4_next_leader_root() {
  local r=$1 n line short
  for n in 1 2 3 4 5; do
    line=$(grep -a 'round has lasted minimum required duration; next leader' "test-nodes/root$n/debug.log" 2>/dev/null | grep -a " round=$r " | head -1)
    [ -z "$line" ] || break
  done
  [ -n "$line" ] || return 1
  short=$(echo "$line" | sed -n 's/.*next leader <peer.ID \(16\*[A-Za-z0-9]*\)>.*/\1/p')
  for n in 1 2 3 4 5; do [ "$(s4_short "$n")" = "$short" ] && { echo "$n"; return 0; }; done
  return 1
}

# the harness tool (a prebuilt binary in a CI run job, else go run)
s4_tool() { lane_go_run s4-equivocate "$@"; }

s4_equivocate() {
  local d=$S4_DIR cur start R leader a="" b="" n cfg net gen epoch=2 utb=() ra rb t0
  mkdir -p "$d"
  [ "$(s4_epoch 1)" = "$epoch" ] || { echo "root 1 is not in epoch $epoch (the joiner is a committee member only there)" >&2; return 1; }
  cfg=$H3_DIR/candidate-config-2.json
  net=$(jq -r .network "$cfg"); gen=$(jq -r .genesis "$cfg")
  [ "$(jq -r .signingScheme "$cfg")" = 2 ] || { echo "epoch 2 is not a scheme 2 epoch" >&2; return 1; }
  [ "${UTB_LANE:-0}" != 1 ] || utb=(--utb)
  start=$(jq -r .activationRound "$H3_DIR/activation-record-2.json")
  # a round a few rounds back that belongs to epoch 2 and whose next leader is known (the genuine vote of the joiner for that round went to that root, so
  # the two observers are chosen among the others: no journal then holds a genuine third statement of the slot)
  for t0 in $(seq 1 120); do
    cur=$(s4_round 1) || return 1
    R=$((cur - 3))
    if [ "$R" -ge $((start + 3)) ] && leader=$(s4_next_leader_root "$R"); then break; fi
    leader=""; sleep 1
  done
  [ -n "$leader" ] || { echo "no round of epoch 2 with a known next leader (activation round $start, current $cur)" >&2; return 1; }
  for n in 1 2 3 4; do
    [ "$n" != "$leader" ] || continue
    if [ -z "$a" ]; then a=$n; elif [ -z "$b" ]; then b=$n; fi
  done
  [ -n "$b" ] || { echo "fewer than two observer roots besides the next leader $leader" >&2; return 1; }
  s4_tool make --keys "test-nodes/root$S4_OFFENDER_ROOT/keys.json" --network "$net" --genesis "$gen" ${utb[@]+"${utb[@]}"} --epoch "$epoch" --round "$R" --out "$d/votes" || return 1
  # half A to the first observer now; half B to the second only once the round is behind it by several rounds (stale by then, and still seen by the tap before the stale filter)
  ra=$(s4_round "$a"); s4_tool send --keys "test-nodes/root$S4_OFFENDER_ROOT/keys.json" --vote "$d/votes/a.vote" --to "$(m2_root_addr "$a")" || return 1
  for t0 in $(seq 1 60); do rb=$(s4_round "$b"); [ "$rb" -ge $((R + 4)) ] && break; sleep 1; done
  [ "$rb" -gt "$R" ] || { echo "root $b did not move past round $R" >&2; return 1; }
  s4_tool send --keys "test-nodes/root$S4_OFFENDER_ROOT/keys.json" --vote "$d/votes/b.vote" --to "$(m2_root_addr "$b")" || return 1
  jq -n --argjson epoch "$epoch" --argjson round "$R" --argjson a "$a" --argjson b "$b" --argjson leader "$leader" --argjson ra "$ra" --argjson rb "$rb" \
    --arg offender "$(h3_root_id "$S4_OFFENDER_ROOT")" '{epoch:$epoch, round:$round, offenderNode:$offender, nextLeaderRoot:$leader, halfA:{root:$a, rootRoundAtSend:$ra, stale:($ra>$round)},
      halfB:{root:$b, rootRoundAtSend:$rb, stale:($rb>$round)}}' >"$d/delivery.json"
  jq -e '.halfB.stale == true' "$d/delivery.json" >/dev/null || { echo "half B was not stale at its receiver" >&2; return 1; }
  s4_pass "two statements of one slot (epoch $epoch, round $R) delivered to roots $a (round $ra) and $b (round $rb, stale), the next leader $leader holds the genuine vote"
}

# stop root $1 (TERM, then wait for the process), copy its journal, start it again in the current epoch
s4_snapshot_journal() {
  local i=$1 ref pid epoch k
  epoch=$(s4_epoch "$i"); ref=
  for k in 1 2 3 4; do [ "$k" = "$i" ] || { ref=$k; break; }; done
  pid=$(cat "test-nodes/root$i/pid" 2>/dev/null)
  stop_pidfile "test-nodes/root$i/pid" 'ubft root-node' || return 1
  for k in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
  kill -0 "$pid" 2>/dev/null && { echo "root $i did not stop" >&2; return 1; }
  cp "test-nodes/root$i/evidence.db" "$S4_DIR/journal-root$i.db" || return 1
  grep -a 'evidence observer stats' "test-nodes/root$i/debug.log" | tail -1 >"$S4_DIR/observer-stats-root$i.txt"
  m2_start_root "$i" "$epoch" "$(m2_root_addr "$ref")" || return 1
  for k in $(seq 1 60); do [ "$(s4_round "$i" 2>/dev/null)" -gt 0 ] 2>/dev/null && break; sleep 1; done
}

s4_collect_after_rotation() {
  local d=$S4_DIR a b epoch
  a=$(jq -r .halfA.root "$d/delivery.json"); b=$(jq -r .halfB.root "$d/delivery.json")
  epoch=$(s4_epoch 1)
  [ "$epoch" -ge 3 ] || { echo "the roots are in epoch $epoch: the joiner has not been rotated out" >&2; return 1; }
  # the rotation: the committee of the current epoch does not name the offender's root
  jq -e --arg id "$(h3_root_id "$S4_OFFENDER_ROOT")" '[.commit.signers[]?.nodeId] | index($id) | not' "$H3_DIR/activation-record-3.json" >/dev/null \
    || { echo "the joiner's root is still in the committee of the current epoch" >&2; return 1; }
  s4_snapshot_journal "$a" || return 1
  s4_snapshot_journal "$b" || return 1
  # a collector which holds no runtime state: each scan is a new process reading only the journal copies
  build/ubft evidence scan --journal "$d/journal-root$a.db" >"$d/scan-root$a.json" || return 1
  build/ubft evidence scan --journal "$d/journal-root$b.db" >"$d/scan-root$b.json" || return 1
  build/ubft evidence scan --journal "$d/journal-root$a.db" --journal "$d/journal-root$b.db" >"$d/scan-both.json" || return 1
  python3 scripts/s4/s4_assert.py journals --delivery "$d/delivery.json" --statements "$d/votes/statements.json" --scan-a "$d/scan-root$a.json" --scan-b "$d/scan-root$b.json" \
    --scan-both "$d/scan-both.json" --stats "$d/observer-stats-root$a.txt" --stats "$d/observer-stats-root$b.txt" --offender-key "$(jq -r .sigKey.publicKey "test-nodes/root$S4_OFFENDER_ROOT/node-info.json" 2>/dev/null || true)" || return 1
}
