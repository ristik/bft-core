# The transaction-gossip step of the lane (definitions only; GOSSIP_LANE=1 adds gossip_step_proof after p85_baseline). Needs the paired devnet's helpers (rpc, pyget, lane_go_run).
#
# ureth with transaction-only gossip (ristik/ureth#34): validators connect as trusted peers and a pending transaction submitted to one of them reaches the others' pools. The step
# proves it on the running devnet. It takes the validator V that sealed the latest block (its next turn is some blocks away), sends ONE transaction to V's execution client only, and
# requires evidence that another validator had it: (1) PRIMARY, pool presence: while no block includes the transaction, another online validator's execution client reports it pending
# (eth_getTransactionByHash answers from the pool with a null block number; the txpool namespace is not enabled on the lane's clients). That does not depend on the leader rotation. (2) the block which
# includes it was sealed by a DIFFERENT validator. Without gossip a transaction in V's private pool is in no other pool and can only be included by V; the sealing rotation only decides how long the
# submitter's own pool holds the transaction, which is why inclusion timing alone is not proof (a validator that seals every other block can include it first; bft-core #737).
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

gossip_pending_elsewhere() { # tx hash, submitter -> the first other online validator whose pool holds it (pending, no block number yet), or nothing
  local u i r
  for i in ${H3_ONLINE:-$(seq 1 "${validators:-4}")}; do
    [ "$i" != "$2" ] || continue
    u="http://127.0.0.1:$((rethEthBase + i - 1))"
    r=$(rpc "$u" eth_getTransactionByHash "[\"$1\"]")
    [ "$(echo "$r" | jq -r '.result.hash // empty' 2>/dev/null)" = "$1" ] || continue
    [ "$(echo "$r" | jq -r '.result.blockNumber // "null"' 2>/dev/null)" = null ] || continue
    echo "$i"; return 0
  done
  return 1
}

gossip_step_proof() {
  local pooled attempt v url head headHash nonce sent receipt block blockHash sealer n h s turnBefore ok=0 j
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
    block= ; blockHash= ; pooled=
    for j in $(seq 1 600); do
      [ -n "$pooled" ] || pooled=$(gossip_pending_elsewhere "$sent" "$v" || true)
      receipt=$(rpc "$url" eth_getTransactionReceipt "[\"$sent\"]")
      blockHash=$(echo "$receipt" | pyget "['result']['blockHash']")
      block=$(echo "$receipt" | pyget "['result']['blockNumber']")
      [ -n "$blockHash" ] && [ "$blockHash" != None ] && break
      sleep 0.2
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
    if [ -n "$pooled" ]; then
      echo "GOSSIP: the transaction sent to validator $v only was pending in validator $pooled's pool before any block included it (included in block $block, sealed by validator ${sealer:-?})"
      ok=1; break
    fi
    if [ -n "$sealer" ] && [ "$sealer" != "$v" ]; then
      echo "GOSSIP: the transaction sent to validator $v only was included in block $block, sealed by validator $sealer (validator $v sealed a block in between: $([ "$turnBefore" = 1 ] && echo yes || echo no))"
      ok=1; break
    fi
    echo "GOSSIP: attempt $attempt inconclusive: the including block $block was sealed by the submitter itself (validator ${sealer:-?}); trying again" >&2
  done
  [ "$ok" = 1 ] || { echo "gossip: in $attempt attempts the transaction was only ever included by the validator it was sent to: no sign of transaction gossip" >&2; return 1; }
  M2_NEXT_NONCE=$((nonce + 1))
}
