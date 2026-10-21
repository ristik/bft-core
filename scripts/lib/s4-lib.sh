# S4 (#57): the focused live slashing exercise on the P85 lane family (briefs/s4-live-slashing-brief.md; design briefs/s3-evidence-service-design.md §5).
# Definitions only: sourcing this file starts nothing and reads nothing. The steps are selected by S4_LANE=1 (scripts/p85-recovery-steps.sh adds them).
#
#   s4_equivocate               after the install of epoch 2, while the joiner is a committee member: the harness signs two scheme 2 votes of the joiner's root key for one
#                               past epoch-2 round (harness-only alternate signer: the genuine root5 process is untouched) and delivers one to each of two
#                               roots over the real root vote protocol, the second only after the round is behind the receiver (stale)
#   s4_collect_after_rotation   after the recovery to K (the joiner evicted): stop each observer root in turn, copy its journal, restart it; scan each copy alone and both together
#   s4_submit_settle            a third party, holding a fresh funded account and no root or owner key, submits the pair through the real Evidence contract and settles it; the
#                               submitter is killed once between admission and settlement and rerun
#   s4_claim                    (later, where the execution chain is healthy) the reporter claims exactly the bounty; the throw-away key is removed after it
#   s4_check                    the named assertions on the journals, the calldata and the certified EVM effects (scripts/s4/s4_assert.py)

S4_DIR=${S4_DIR:-test-nodes/p85/s4}
# the reporter's throw-away key lives outside the archived directories under a name the lane's state copy excludes (*.cred)
S4_KEY=${S4_KEY:-test-nodes/s4-reporter/reporter.cred}
S4_OFFENDER_ROOT=${S4_OFFENDER_ROOT:-5}   # the joiner's root

s4_pass() { printf 'PASS: s4: %s\n' "$1"; }
s4_cast() { "${P85_CAST:-cast}" "$@"; }
s4_round() { curl -fsS "$(h3_rpc_url "$1")/api/v1/roundInfo" 2>/dev/null | jq -r '.roundNumber'; }
s4_epoch() { curl -fsS "$(h3_rpc_url "$1")/api/v1/roundInfo" 2>/dev/null | jq -r '.epochNumber'; }
s4_short() { grep -a -m1 -o 'node_id=16\*[A-Za-z0-9]*' "test-nodes/root$1/debug.log" | head -1 | sed 's/node_id=//'; }

# the root that was the leader of round $1+1: the one the offender's own genuine vote of round $1 went to. The offender root logs it itself ("next leader" at that round);
# the LAST such line of its log is taken (an earlier epoch's log can carry the same round number)
s4_next_leader_root() {
  local r=$1 n line short
  line=$(grep -a 'round has lasted minimum required duration; next leader' "test-nodes/root$S4_OFFENDER_ROOT/debug.log" 2>/dev/null | grep -a " round=$r " | tail -1)
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
  cfg=$H3_DIR/candidate-config-1.json   # the first handoff installs epoch 2
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
# Copy root $1's journal. By default the root is only PAUSED (SIGSTOP) while the file is copied and continued at once: a bbolt file is copy-on-write with the meta page
# written last, so a copy taken while the process is stopped is a consistent crash-point snapshot, and no root restart disturbs the lane (S4_RESTART_ROOTS=1 stops and
# restarts the root instead, as the first S4 runs did: in those runs the execution chain stopped certifying afterwards in the milestone runs, see docs/root-evidence.md).
s4_snapshot_journal() {
  local i=$1 ref pid epoch k
  pid=$(cat "test-nodes/root$i/pid" 2>/dev/null)
  if [ "${S4_RESTART_ROOTS:-0}" != 1 ]; then
    kill -0 "$pid" 2>/dev/null || { echo "root $i is not running" >&2; return 1; }
    kill -STOP "$pid" || return 1
    cp "test-nodes/root$i/evidence.db" "$S4_DIR/journal-root$i.db"; k=$?
    kill -CONT "$pid"
    [ "$k" = 0 ] || return 1
    sleep 16   # the next periodic counter line (every 15 s) after the pause
    grep -a 'evidence observer stats' "test-nodes/root$i/debug.log" | tail -1 >"$S4_DIR/observer-stats-root$i.txt"
    return 0
  fi
  epoch=$(s4_epoch "$i"); ref=
  for k in 1 2 3 4; do [ "$k" = "$i" ] || { ref=$k; break; }; done
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
  # the rotation: the first epoch-3 certificate (K signs it, the joiner's root cannot) names three of the four K roots and not the offender
  jq -e --arg id "$(h3_root_id "$S4_OFFENDER_ROOT")" '.epoch == 3 and ([.signers[].nodeId] | index($id) | not)' "$H3_DIR/first-epoch3-certificate.json" >/dev/null \
    || { echo "the first epoch-3 certificate is missing or names the joiner's root" >&2; return 1; }
  s4_snapshot_journal "$a" || return 1
  s4_snapshot_journal "$b" || return 1
  # a collector which holds no runtime state: each scan is a new process reading only the journal copies
  build/ubft evidence scan --journal "$d/journal-root$a.db" >"$d/scan-root$a.json" || return 1
  build/ubft evidence scan --journal "$d/journal-root$b.db" >"$d/scan-root$b.json" || return 1
  build/ubft evidence scan --journal "$d/journal-root$a.db" --journal "$d/journal-root$b.db" >"$d/scan-both.json" || return 1
  s4_py journals --delivery "$d/delivery.json" --statements "$d/votes/statements.json" --scan-a "$d/scan-root$a.json" --scan-b "$d/scan-root$b.json" \
    --scan-both "$d/scan-both.json" --stats "$d/observer-stats-root$a.txt" --stats "$d/observer-stats-root$b.txt" --offender-key "$(jq -r .sigKey.publicKey "test-nodes/root$S4_OFFENDER_ROOT/node-info.json" 2>/dev/null || true)" || return 1
}

s4_json_addr() { jq -r ".$1" "$P85_DEPLOY"; }
s4_evidence() { s4_cast call --rpc-url "$(p85_eth)" "$(p85_custody)" 'evidence()(address)' | awk '{print $1}'; }
s4_py() { python3 scripts/s4/s4_assert.py "$@"; }

# the candidate assignments the offence's exposure is resolved among: the primary J's (the election result the lane opened) and the genesis one
s4_assignments() {
  local r a_j a_g
  r=$(cat "$H3_DIR/result-id.txt")
  a_j=$(p85_call "$(p85_election)" 'result(bytes32)' "$r" | p85_dec result | jq -r .assignmentID) || return 1
  a_g=$(grep -o '0x[0-9a-fA-F]\{64\}' "$P85_DIR/genesis-assignment.txt" | head -1)
  echo "$a_j $a_g"
}

# one signed transaction of a key, sent to every online validator of the lane's EVM chain (the chain refuses eth_estimateGas: "bound parent hash mismatch", so no
# cast send) and waited for until its receipt shows success; the receipt (JSON) goes to the file
s4_send() { # private-key(hex) nonce to value data gas-limit receipt-file
  local id sent expected= i receipt status n=0
  s4_send_all() { # the same signed bytes (evmtx signs deterministically) to every online validator: a resend is "already known" where the first send arrived
    expected=
    for id in $(s4_targets); do
      sent=$(lane_go_run evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+id-1))" -chain-id "${M2_CHAIN_ID:-31337}" -private-key "${1#0x}" -nonce "$2" -to "$3" -value "$4" -data "$5" -gas-limit "$6" 2>&1) \
        || { case "$sent" in *"already known"*|*"known transaction"*|*"already exists"*) sent=$(echo "$sent" | grep -o '0x[0-9a-f]\{64\}' | head -1) ;; *) echo "$sent" >&2; return 1 ;; esac; }
      [ -z "$expected" ] || [ -z "$sent" ] || [ "$expected" = "$sent" ] || { echo "validators disagree on the transaction hash" >&2; return 1; }
      [ -n "$sent" ] && expected=$sent
    done
  }
  s4_send_all "$@" || return 1
  for i in $(seq 1 300); do
    # a receipt on ANY online validator (each applies the same certified blocks)
    for id in $H3_ONLINE; do
      receipt=$(rpc "http://127.0.0.1:$((rethEthBase+id-1))" eth_getTransactionReceipt "[\"$expected\"]")
      status=$(echo "$receipt" | pyget "['result']['status']" 2>/dev/null)
      if [ "$status" = 0x1 ]; then echo "$receipt" | jq .result >"$7"; return 0; fi
      [ "$status" != 0x0 ] || { echo "transaction $expected reverted" >&2; return 1; }
    done
    # still nothing: send it again every 30 s (a pool that lost it, a validator that was not yet accepting)
    if [ $((i % 30)) = 0 ]; then n=$((n+1)); echo "s4_send: no receipt for $expected after $i s; send $((n+1))" >&2; s4_send_all "$@" || true; fi
    sleep 1
  done
  echo "no receipt for $expected after 300 s" >&2; s4_diag "$expected" "$2" "$1"; return 1
}

# the state a failed wait needs to be understood from the pack (the EVM logs are not published): per online validator the head, the transaction by hash, the pool
# counters and the sender's latest/pending nonce
s4_diag() { # tx-hash nonce private-key
  local id u addr
  addr=$("${P85_CAST:-cast}" wallet address --private-key "0x${3#0x}" 2>/dev/null)
  echo "s4_send diagnostics for $1 (nonce $2, sender $addr, H3_ONLINE='$H3_ONLINE'):" >&2
  for id in $H3_ONLINE; do
    u="http://127.0.0.1:$((rethEthBase+id-1))"
    echo "  validator $id head=$(rpc "$u" eth_blockNumber '[]' | pyget "['result']") tx=$(rpc "$u" eth_getTransactionByHash "[\"$1\"]" | jq -c '.result // "null" | if type=="object" then {blockNumber,nonce,gas,maxFeePerGas} else . end' 2>/dev/null)" \
         "txpool=$(rpc "$u" txpool_status '[]' | jq -c '.result // .error.message' 2>/dev/null) nonce_latest=$(rpc "$u" eth_getTransactionCount "[\"$addr\",\"latest\"]" | pyget "['result']") nonce_pending=$(rpc "$u" eth_getTransactionCount "[\"$addr\",\"pending\"]" | pyget "['result']") baseFee=$(rpc "$u" eth_getBlockByNumber '["latest",false]' | jq -r '.result.baseFeePerGas' 2>/dev/null)" >&2
  done
  for id in 1 2 3 4 5; do [ -f "test-nodes/evm$id/pid" ] && echo "  evm$id pid $(cat test-nodes/evm$id/pid) alive=$(kill -0 "$(cat test-nodes/evm$id/pid)" 2>/dev/null && echo yes || echo no)" >&2; done
  for id in $H3_ONLINE; do echo "  evm$id log tail:" >&2; tail -n 5 "test-nodes/evm$id/debug.log" 2>/dev/null | cut -c1-240 >&2; done
}

# a fresh reporter: a new key, funded by the lane's funded account, which is neither a root key nor an owner key of any entity (the owner key only pays)
s4_reporter() {
  local d=$S4_DIR k
  if [ ! -s "$S4_KEY" ]; then
    mkdir -p "$(dirname "$S4_KEY")"
    k=$(s4_cast wallet new --json | jq -r '(.data // .)[0].private_key') || return 1
    ( umask 077; printf '%s\n' "$k" >"$S4_KEY" )
    s4_cast wallet address --private-key "$k" >"$d/reporter.addr" || return 1
    # funded from the lane's paid-transaction account (the funded default key of scripts/evmtx), not from the joiner's owner key
    s4_send ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 "$(p85_chain_nonce)" "$(cat "$d/reporter.addr")" 1000000000000000000 0x 21000 "$d/reporter-funding.json" || return 1
  fi
}

# a transaction in the EVM chain every few seconds while a command runs (the blocks of the lane's chain come from transactions)
s4_with_traffic() {
  local pid
  "$@" & pid=$!
  while kill -0 "$pid" 2>/dev/null; do p85_paid 1 >/dev/null 2>&1 || true; sleep 2; done
  wait "$pid"
}

s4_snapshot() { # tag [case]
  s4_py snapshot --rpc "$(p85_eth)" --custody "$(p85_custody)" --evidence "$EV" --exposure "$EXPOSURE" --reporter "$(cat "$S4_DIR/reporter.addr")" \
    $(for l in $OTHER_LOTS; do printf -- '--other-lot %s ' "$l"; done) ${OFFENCE:+--offence $OFFENCE} ${CASE:+--case $CASE} --out "$S4_DIR/snapshot-$1.json"
}

s4_submit_settle() {
  local d=$S4_DIR EV a ids=() pid out n both key
  mkdir -p "$d"
  EV=$(s4_evidence) || return 1
  read -r -a ids <<<"$(s4_assignments)" || return 1
  key=$(jq -r '.Pairs[0].Key' "$d/scan-both.json")
  s4_py resolve --rpc "$(p85_eth)" --custody "$(p85_custody)" --key "$key" --epoch 2 $(for a in "${ids[@]}"; do printf -- '--assignment %s ' "$a"; done) --out "$d/resolved.json" || return 1
  EXPOSURE=$(jq -r .exposure "$d/resolved.json"); OTHER_LOTS=$(jq -r '.otherLots[]' "$d/resolved.json" | head -3 | tr '\n' ' ')
  jq -e '.lots|length>=1' "$d/resolved.json" >/dev/null || return 1
  a=$(jq -r .assignment "$d/resolved.json")
  s4_reporter || return 1
  CASE=; OFFENCE=; s4_snapshot before || return 1
  # the control calls, from the real pair (they are eth_calls: nothing is sent): reordered/altered payloads and the identical pair are refused before admission
  s4_tool calldata --journal "$d/journal-root$(jq -r .halfA.root "$d/delivery.json").db" --journal "$d/journal-root$(jq -r .halfB.root "$d/delivery.json").db" \
    --network-word "$(s4_cast call --rpc-url "$(p85_eth)" "$EV" 'network()(bytes32)' 2>/dev/null | awk '{print $1}')" --root-network "$(jq -r .network "$H3_DIR/candidate-config-1.json")" \
    --genesis "$(jq -r .genesis "$H3_DIR/candidate-config-1.json")" --exposure "$EXPOSURE" --out "$d/calldata" || return 1
  local rep; rep=$(cat "$d/reporter.addr")
  s4_py refusal --rpc "$(p85_eth)" --to "$EV" --sender "$rep" --data "$d/calldata/identical.hex" --error 'IdenticalStatements()' || return 1
  s4_py refusal --rpc "$(p85_eth)" --to "$EV" --sender "$rep" --data "$d/calldata/altered.hex" --error 'BadSignature()' || return 1
  s4_py refusal --rpc "$(p85_eth)" --to "$EV" --sender "$rep" --data "$d/calldata/sealstripped.hex" --error 'SealSignatureMissing()' || return 1
  # the real submission; the submitter is killed once it has printed the admitted case, and rerun: it must resume from the on-chain cursor
  out=$d/submit-1.txt
  s4_with_traffic s4_submit_once "$out" "$EV" "${ids[@]}" || true
  CASE=$(sed -n 's/.*case=\([0-9a-f]\{64\}\).*/0x\1/p' "$out" | head -1)
  [ -n "$CASE" ] || { echo "the submitter admitted no case: $(cat "$out")" >&2; return 1; }
  s4_pass "the submitter was interrupted after admission (case $CASE) and its output kept ($out)"
  OFFENCE=$(s4_cast call --rpc-url "$(p85_eth)" "$EV" 'caseInfo(bytes32)(bytes32,bytes32,uint64,address,uint256,uint256,uint32,uint32)' "$CASE" | head -1 | awk '{print $1}')
  s4_snapshot admitted || return 1
  [ -z "${S4_ADMITTED_HOOK:-}" ] || "$S4_ADMITTED_HOOK" || return 1   # X4 B3b: the exit probe, while the case is admitted and not yet settled (the holds are installed)
  out=$d/submit-2.txt
  s4_with_traffic s4_submit_once "$out" "$EV" "${ids[@]}" --wait || return 1
  grep -q 'settled in' "$out" || { echo "the second submitter run did not settle: $(cat "$out")" >&2; return 1; }
  s4_snapshot settled || return 1
}

# the validators a transaction is sent to: every online one (older ureth: pools do not gossip), or only the first with LANE_TX_FANOUT=one (ureth with transaction gossip)
s4_targets() { local o=${H3_ONLINE:-1}; [ "${LANE_TX_FANOUT:-all}" != one ] || o=${o%% *}; echo "$o"; }
s4_eth_all() { local i out=; for i in $(s4_targets); do out="${out:+$out,}http://127.0.0.1:$((rethEthBase + i - 1))"; done; echo "$out"; }

# one submitter process. The first run has no --settle and is stopped as soon as it has printed the case line (the submitter dies after admission: with the lane's
# single-lot exposure a settling run would finish before it could be interrupted); the second run (--wait) submits again and settles from the on-chain cursor
s4_submit_once() {
  local out=$1 ev=$2; shift 2
  local ids=() wait=0 f pid settle=()
  for f in "$@"; do [ "$f" = --wait ] && { wait=1; settle=(--settle); } || ids+=(--assignment "$f"); done
  local d=$S4_DIR eth id
  # the lane's validators do not gossip transactions: --eth-rpc lists every online validator (the first decides reads)
  eth=$(s4_eth_all)
  build/ubft evidence submit --journal "$d/journal-root$(jq -r .halfA.root "$d/delivery.json").db" --journal "$d/journal-root$(jq -r .halfB.root "$d/delivery.json").db" \
    --eth-rpc "$eth" --evidence "$ev" "${ids[@]}" --sender-key "$S4_KEY" ${settle[@]+"${settle[@]}"} >"$out" 2>&1 &
  pid=$!
  if [ "$wait" = 0 ]; then
    for f in $(seq 1 3000); do grep -q "case=" "$out" 2>/dev/null && break; kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    return 0
  fi
  wait "$pid"
}

s4_assert_effects() {
  local d=$S4_DIR EV rep tx bal0 bal1 bounty
  EV=$(s4_evidence) || return 1; rep=$(cat "$d/reporter.addr")
  tx=$(sed -n 's/.* tx=\(0x[0-9a-f]\{64\}\).*/\1/p' "$d/submit-1.txt" | head -1)
  [ -n "$tx" ] || { echo "no transaction hash in the first submit output" >&2; return 1; }
  s4_cast receipt --rpc-url "$(p85_eth)" --json "$tx" >"$d/receipt-submit.json" || return 1
  jq -e '(.data // .) | .status == "0x1" or .status == 1 or .status == "1 (success)" or .status == "success"' "$d/receipt-submit.json" >/dev/null || { echo "the submitting transaction failed" >&2; return 1; }
  s4_pass "inclusion: the evidence transaction $tx is in block $(jq -r "(.data // .).blockNumber" "$d/receipt-submit.json") with status success"
  s4_py calldata --rpc "$(p85_eth)" --tx "$tx" --statements "$d/votes/statements.json" || return 1
  s4_py effects --before "$d/snapshot-before.json" --admitted "$d/snapshot-admitted.json" --settled "$d/snapshot-settled.json" || return 1
  # negatives after admission: the same pair again, and the pair the other way round, are the same offence; the settled case takes no second debit
  s4_py refusal --rpc "$(p85_eth)" --to "$EV" --sender "$rep" --data "$d/calldata/canonical.hex" --error 'DuplicateOffence()' || return 1
  s4_py refusal --rpc "$(p85_eth)" --to "$EV" --sender "$rep" --data "$d/calldata/reordered.hex" --error 'DuplicateOffence()' || return 1
  s4_with_traffic s4_submit_once "$d/submit-3.txt" "$EV" $(s4_assignments) --wait || return 1
  grep -q 'already-admitted' "$d/submit-3.txt" || { echo "the repeated submission did not report AlreadyAdmitted: $(cat "$d/submit-3.txt")" >&2; return 1; }
  CASE=$(sed -n 's/.*case=\([0-9a-f]\{64\}\).*/0x\1/p' "$d/submit-1.txt" | head -1)
  OFFENCE=$(jq -r .case.offenceID "$d/snapshot-settled.json"); EXPOSURE=$(jq -r .exposure "$d/resolved.json"); OTHER_LOTS=$(jq -r '.otherLots[]' "$d/resolved.json" | head -3 | tr '\n' ' ')
  s4_snapshot final || return 1
  cmp -s <(jq -S 'del(.block)' "$d/snapshot-settled.json") <(jq -S 'del(.block)' "$d/snapshot-final.json") || { echo "state moved after the repeated submission" >&2; return 1; }
  s4_pass "negatives: duplicate resubmission (submitter AlreadyAdmitted; eth_call DuplicateOffence for the pair and the reordered pair) takes no second debit, hold or credit (state identical)"

}

# The reporter claims the bounty (the unrelated-path control: a plain withdrawal of credit is not blocked by the case). Its own step, run where the lane's execution chain
# is healthy (before rw_step_settle): in four of six S4 milestone runs the claim, the last transaction of s4_check, never got a block in the 3-validator window right after
# the observer roots' restarts (diagnostics of runs 39518175232 and 39526082463: the leader re-proposed the same block, the quorum never certified it) while every other
# S4 assertion passed. The credit stays on chain, so the claim has no deadline.
s4_claim() {
  local d=$S4_DIR rep bounty bal0 bal1
  rep=$(cat "$d/reporter.addr")
  bounty=$(jq -r '.creditReporter' "$d/snapshot-final.json")
  bal0=$(s4_cast balance --rpc-url "$(p85_eth)" "$rep")
  s4_send "$(cat "$S4_KEY")" "$(s4_cast nonce --rpc-url "$(p85_eth)" "$rep")" "$(p85_custody)" 0 "$(s4_cast calldata 'claim(uint256,address)' "$bounty" "$rep")" 300000 "$d/claim-receipt.json" || return 1
  bal1=$(s4_cast balance --rpc-url "$(p85_eth)" "$rep")
  python3 - "$bal0" "$bal1" "$bounty" "$d/claim-receipt.json" <<'PY' || return 1
import json, sys
b0, b1, bounty = int(sys.argv[1].split()[0]), int(sys.argv[2].split()[0]), int(sys.argv[3])
r = json.load(open(sys.argv[4]))
gas = int(r["gasUsed"], 16) * int(r["effectiveGasPrice"], 16)
if b1 - b0 + gas != bounty: sys.exit("FAIL: s4: the reporter's balance moved by %d (+ gas %d), the bounty is %d" % (b1 - b0, gas, bounty))
print("PASS: s4: the reporter claimed exactly the bounty %d (balance +%d, gas %d)" % (bounty, b1 - b0, gas))
PY
  s4_archive && rm -f "$S4_KEY"
}

# the archive of the exercise: public artifacts only (the harness' statements hold signatures, never a key; the journals hold signed votes)
s4_archive() {
  local d=$S4_DIR
  ( cd "$d" && rm -f SHA256SUMS && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs shasum -a 256 >SHA256SUMS )
  s4_pass "archive: $(wc -l <"$d/SHA256SUMS" | tr -d ' ') files with SHA256SUMS in $d "
}

s4_check() { s4_assert_effects && s4_archive; }
