# X4 B6e: the governance steps of the PoS campaign, as lane steps (p85_step): x4g_queue (right after the baseline), x4g_execute and x4g_check (late, after the delays). Definitions only: sourcing
# this file starts nothing. Contract: unicity-pos-contracts b17829ca src/p85/GovernanceParams.sol. `queue` is by the fixed AUTHORITY only (here a key the lane holds: the genesis plan sets the
# authority to its address when X4_GOV_LANE=1); `execute` is permissionless after BOTH delays (2000 progress rounds, 3600 UC seconds) and only SCHEDULES the proposal; it becomes the policy in
# force only when ElectionPolicy.elect calls activateDue at its next eligible boundary (no unresolved election). On the recovery chain an election result is open from the baseline on, so
# whether that ever happens is exactly what this experiment finds out: x4g_check waits X4G_WAIT seconds for the policy ID to move and RECORDS the outcome (activated true/false), it does not
# assert activation. The campaign counts governanceActivated only when the record says activated.

X4G_DIR=${X4G_DIR:-$H3_DIR/x4pos/steps/gov}
X4G_WAIT=${X4G_WAIT:-1800}
POLICY_T='(uint16,uint16,uint16,uint128,uint64,uint64,uint64,uint64,uint64,uint64)'

x4g_gov() { jq -r .policy "$P85_DIR/genesis/deployment.json"; }
x4g_uint() { p85_call "$@" | awk 'NR==1{print $1}'; }   # one unsigned integer answer (annotations like "[1e18]" dropped)
x4g_roots() { jq -r .registry "$P85_DEPLOY"; }
x4g_json() { mkdir -p "$X4G_DIR"; jq -n "$@"; }

# the ten Policy fields of the policy in force, as the tuple literal cast wants
x4g_policy_tuple() {
  p85_call "$(x4g_gov)" "policy()($POLICY_T)" | python3 -c "
import re,sys
s=re.sub(r'\[[^\]]*\]','',sys.stdin.read())
n=re.findall(r'\d+',s)
if len(n)!=10: sys.exit('policy() did not answer ten numbers: '+s)
print('('+','.join(n)+')')"
}

x4g_queue() {
  local gov key auth rate new hash nonce tuple data
  gov=$(x4g_gov); key=$P85_DIR/gov-authority.key
  [ -s "$key" ] || { echo "x4g: no governance authority key (X4_GOV_LANE makes the genesis plan keep one)" >&2; return 1; }
  auth=$("$P85_CAST" wallet address --private-key "$(tr -d '[:space:]' <"$key")")
  [ "$(echo "$auth" | tr A-F a-f)" = "$(jq -r .governanceAuthority "$P85_DIR/genesis/deployment.json" | tr A-F a-f)" ] || { echo "x4g: the key's address $auth is not the deployed AUTHORITY" >&2; return 1; }
  rw_send_value "$(p85_sender_key)" "$auth" "$RW_GAS_WEI" || return 1
  rate=$(x4g_uint "$gov" 'currentRewardRate()(uint128)'); new=$(python3 -c "print($rate // 2)")
  hash=$(p85_call "$gov" 'currentPolicyHash()(bytes32)'); nonce=$(x4g_uint "$gov" 'nextNonce()(uint64)'); tuple=$(x4g_policy_tuple) || return 1
  data=$("$P85_CAST" calldata "queue($POLICY_T,uint128,bytes32,uint64)" "$tuple" "$new" "$hash" "$nonce")
  RW_SEND_DATA=$data RW_SEND_GAS=${X4G_QUEUE_GAS:-1500000} rw_send_value "$key" "$gov" 0 || return 1
  [ "$(x4g_uint "$gov" 'nextNonce()(uint64)')" = "$((nonce + 1))" ] || { echo "x4g: the queue transaction did not consume nonce $nonce" >&2; return 1; }
  x4g_json --argjson nonce "$nonce" --arg rate "$rate" --arg new "$new" --argjson id "$(x4g_uint "$gov" 'currentPolicyID()(uint32)')" --argjson p "$(x4g_uint "$(x4g_roots)" 'progress()(uint64)')" --argjson t "$(x4g_uint "$(x4g_roots)" 'ucTime()(uint64)')" \
    '{nonce: $nonce, rateBefore: $rate, rateProposed: $new, policyIdBefore: $id, queuedAtProgress: $p, queuedAtUcTime: $t}' >"$X4G_DIR/queued.json"
  echo "PASS: x4g: queued nonce $nonce (reward rate $rate -> $new), policy $(jq -r .policyIdBefore "$X4G_DIR/queued.json") in force"
}

# after both delays: execute (permissionless) -> the proposal is Scheduled
x4g_execute() {
  local gov nonce p0 t0 i p t
  gov=$(x4g_gov); [ -s "$X4G_DIR/queued.json" ] || { echo "x4g: nothing was queued" >&2; return 1; }
  nonce=$(jq -r .nonce "$X4G_DIR/queued.json"); p0=$(jq -r .queuedAtProgress "$X4G_DIR/queued.json"); t0=$(jq -r .queuedAtUcTime "$X4G_DIR/queued.json")
  for i in $(seq 1 7200); do
    p=$(x4g_uint "$(x4g_roots)" 'progress()(uint64)'); t=$(x4g_uint "$(x4g_roots)" 'ucTime()(uint64)')
    [ "$p" -ge "$((p0 + 2000))" ] && [ "$t" -ge "$((t0 + 3600))" ] && break; sleep 1
  done
  [ "$p" -ge "$((p0 + 2000))" ] && [ "$t" -ge "$((t0 + 3600))" ] || { echo "x4g: the delays did not pass in 7200 s (progress $p of $((p0 + 2000)), UC time $t of $((t0 + 3600)))" >&2; return 1; }
  RW_SEND_DATA=$("$P85_CAST" calldata 'execute(uint64)' "$nonce") RW_SEND_GAS=${X4G_EXEC_GAS:-500000} rw_send_value "$(p85_sender_key)" "$gov" 0 || return 1
  echo "PASS: x4g: executed nonce $nonce at progress $p, UC time $t (scheduled; activation needs an election boundary)"
}

# the experiment: does the scheduled snapshot become the policy in force within X4G_WAIT seconds? recorded, not asserted
x4g_check() {
  local gov id0 id1 i open rate1
  gov=$(x4g_gov); id0=$(jq -r .policyIdBefore "$X4G_DIR/queued.json")
  for i in $(seq 1 "$X4G_WAIT"); do id1=$(x4g_uint "$gov" 'currentPolicyID()(uint32)'); [ "$id1" -gt "$id0" ] && break; sleep 1; done
  rate1=$(x4g_uint "$gov" 'currentRewardRate()(uint128)'); open=$(p85_open_result 2>/dev/null || echo unreadable)
  x4g_json --argjson id0 "$id0" --argjson id1 "$id1" --arg rate "$rate1" --arg open "$open" --argjson waited "$i" --argjson proposed "$(jq .rateProposed "$X4G_DIR/queued.json")" \
    '{policyIdBefore: $id0, policyIdAfter: $id1, activated: ($id1 > $id0), rateAfter: $rate, rateProposed: $proposed, openResultAtEnd: $open, waitedSeconds: $waited}' >"$X4G_DIR/outcome.json"
  echo "PASS: x4g: outcome recorded: $(jq -c . "$X4G_DIR/outcome.json")"
}
