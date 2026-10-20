# The transaction-gossip step of the lane (definitions only; GOSSIP_LANE=1 adds gossip_step_proof after p85_baseline). Needs the paired devnet's helpers (rpc, pyget, lane_go_run).
#
# ureth with transaction-only gossip (ristik/ureth#34): validators connect as trusted peers and a pending transaction submitted to one of them reaches the others' pools. The step
# proves it on the running devnet. It takes the validator V that sealed the latest block (its next turn is some blocks away), sends ONE transaction to V's execution client only, and
# requires that the block which includes it was sealed by a DIFFERENT validator, before V's own next turn: without gossip a transaction in V's private pool can only be included by V.
# The sealer of a block is the validator whose log holds `sealed execution payload` for that block hash (the others log `verified execution payload`).

gossip_sealer_of() { # block hash (0x...) -> the validator that sealed it, or nothing
  local h=${1#0x} i
  for i in $(seq 1 "${validators:-4}"); do
    [ -f "test-nodes/evm$i/debug.log" ] || continue
    if grep -aq "msg=\"sealed execution payload\".*blockHash=$h" "test-nodes/evm$i/debug.log" 2>/dev/null; then echo "$i"; return 0; fi
  done
  return 1
}

gossip_block_field() { # url number-hex field
  rpc "$1" eth_getBlockByNumber "[\"$2\", false]" | pyget "['result']['$3']"
}

gossip_step_proof() {
  local attempt v url head headHash nonce sent receipt block blockHash sealer n h s turnBefore ok=0 j
  : "${M2_CHAIN_ID:=31337}"
  for attempt in 1 2 3 4; do
    url="http://127.0.0.1:$((rethEthBase + $(echo "${H3_ONLINE:-1}" | awk '{print $1}') - 1))"
    head=$(gossip_block_field "$url" latest number) || return 1
    headHash=$(gossip_block_field "$url" latest hash) || return 1
    for j in $(seq 1 20); do v=$(gossip_sealer_of "$headHash") && break; sleep 1; done
    [ -n "${v:-}" ] || { echo "gossip: no validator logged having sealed block $head ($headHash)" >&2; continue; }
    nonce=$(p85_chain_nonce) || return 1
    url="http://127.0.0.1:$((rethEthBase + v - 1))"
    sent=$(lane_go_run evmtx -send -eth-url "$url" -chain-id "$M2_CHAIN_ID" -nonce "$nonce" 2>&1) || { echo "gossip: evmtx failed on validator $v: $sent" >&2; return 1; }
    [[ "$sent" = 0x* ]] || { echo "gossip: validator $v returned no transaction hash: $sent" >&2; return 1; }
    echo "GOSSIP attempt $attempt: validator $v sealed block $head; transaction $sent (nonce $nonce) sent to validator $v ONLY"
    block= ; blockHash=
    for j in $(seq 1 120); do
      receipt=$(rpc "$url" eth_getTransactionReceipt "[\"$sent\"]")
      blockHash=$(echo "$receipt" | pyget "['result']['blockHash']")
      block=$(echo "$receipt" | pyget "['result']['blockNumber']")
      [ -n "$blockHash" ] && [ "$blockHash" != None ] && break
      sleep 1
    done
    [ -n "$blockHash" ] && [ "$blockHash" != None ] || { echo "gossip: the transaction was not included within 120 s" >&2; return 1; }
    block=$((block))
    sealer=$(for j in $(seq 1 20); do gossip_sealer_of "$blockHash" && break; sleep 1; done) || true
    # did the submitter seal any block between its own latest one and the including block?
    turnBefore=0
    for n in $(seq $((head + 1)) "$block"); do
      h=$(gossip_block_field "$url" "$(printf '0x%x' "$n")" hash); s=$(gossip_sealer_of "$h" || true)
      echo "GOSSIP   block $n sealed by validator ${s:-?}"
      [ "$s" != "$v" ] || turnBefore=1
    done
    if [ -n "$sealer" ] && [ "$sealer" != "$v" ]; then
      echo "GOSSIP: the transaction sent to validator $v only was included in block $block, sealed by validator $sealer (validator $v's own turn had not come: ${turnBefore} own blocks in between)"
      ok=1; break
    fi
    echo "GOSSIP: attempt $attempt inconclusive: the including block $block was sealed by the submitter itself (validator ${sealer:-?}); trying again" >&2
  done
  [ "$ok" = 1 ] || { echo "gossip: in $attempt attempts the transaction was only ever included by the validator it was sent to: no sign of transaction gossip" >&2; return 1; }
  M2_NEXT_NONCE=$((nonce + 1))
}
