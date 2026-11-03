# X4 B6e: the governance steps of the PoS campaign, as lane steps (p85_step): x4g_queue (right after the baseline), x4g_execute and x4g_check (late, after the delays). Definitions only: sourcing
# this file starts nothing. Contract: unicity-pos-contracts b17829ca src/p85/GovernanceParams.sol. `queue` is by the fixed AUTHORITY only (here a key the lane holds: the genesis plan sets the
# authority to its address when X4_GOV_LANE=1); `execute` is permissionless after BOTH delays (2000 progress rounds, 3600 UC seconds) and only SCHEDULES the proposal; it becomes the policy in
# force only when ElectionPolicy.elect calls activateDue at its next eligible, due boundary (no unresolved election). The first campaign run could not reach that (an election result was open from
# the recovery on, bft-core#856); with the X4 handoff lane (X4_H2_LANE) the open results are resolved (the second handoff's Ack, offence 2's lost result rejected by the roots), so x4g_check
# ASSERTS the activation within X4G_WAIT seconds. Without it the outcome is only recorded.

X4G_DIR=${X4G_DIR:-$H3_DIR/x4pos/steps/gov}
X4G_WAIT=${X4G_WAIT:-1800}
POLICY_T='(uint16,uint16,uint16,uint128,uint64,uint64,uint64,uint64,uint64,uint64)'

x4g_gov() { jq -r .policy "$P85_DIR/genesis/deployment.json"; }
x4g_uint() { p85_call "$@" | awk 'NR==1{print $1}'; }   # one unsigned integer answer (annotations like "[1e18]" dropped)
x4g_roots() { jq -r .registry "$P85_DEPLOY"; }

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
  mkdir -p "$X4G_DIR" || return 1   # before any redirect into it: the first live run lost queued.json because the directory was made after the redirect had failed
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
  jq -n --argjson nonce "$nonce" --arg rate "$rate" --arg new "$new" --argjson id "$(x4g_uint "$gov" 'currentPolicyID()(uint32)')" --argjson p "$(x4g_uint "$(x4g_roots)" 'progress()(uint64)')" --argjson t "$(x4g_uint "$(x4g_roots)" 'ucTime()(uint64)')" \
    '{nonce: $nonce, rateBefore: $rate, rateProposed: $new, policyIdBefore: $id, queuedAtProgress: $p, queuedAtUcTime: $t}' >"$X4G_DIR/queued.json" || return 1
  jq -e '.nonce >= 1 and .policyIdBefore >= 1' "$X4G_DIR/queued.json" >/dev/null || { echo "x4g: queued.json is not a record of the queued proposal" >&2; return 1; }
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

# does the scheduled snapshot become the policy in force within X4G_WAIT seconds? In the X4 campaign (X4_H2_LANE, scripts/x4pos/handoff-lib.sh) it MUST: the second handoff was driven and offence 2's
# lost result was rejected by the roots, so no election result is open (the later elections find too few eligible identities, nMin 4) and every due boundary runs ElectionPolicy.elect, whose first act
# is GovernanceParams.activateDue. Without the handoff lane the outcome is recorded, not asserted (the first campaign run could not reach it, bft-core#856).
x4g_check() {
  local gov id0 id1 i open rate1 want=${X4_H2_LANE:-0}
  gov=$(x4g_gov); id0=$(jq -r .policyIdBefore "$X4G_DIR/queued.json")
  for i in $(seq 1 "$X4G_WAIT"); do id1=$(x4g_uint "$gov" 'currentPolicyID()(uint32)'); [ "$id1" -gt "$id0" ] && break; sleep 1; done
  rate1=$(x4g_uint "$gov" 'currentRewardRate()(uint128)'); open=$(p85_open_result 2>/dev/null || echo unreadable)
  jq -n --argjson id0 "$id0" --argjson id1 "$id1" --arg rate "$rate1" --arg open "$open" --argjson waited "$i" --argjson proposed "$(jq .rateProposed "$X4G_DIR/queued.json")" \
    --arg election "$(p85_call "$(p85_election)" 'thresholds()(uint256,uint256)' 2>&1 | tr '\n' ' ')" --arg clock "$(p85_call "$(x4g_roots)" 'progress()(uint64)' 2>&1 | awk 'NR==1{print $1}')" --argjson required "$([ "$want" = 1 ] && echo true || echo false)" \
    '{policyIdBefore: $id0, policyIdAfter: $id1, activated: ($id1 > $id0), rateAfter: $rate, rateProposed: $proposed, openResultAtEnd: $open, waitedSeconds: $waited, activationRequired: $required, thresholds: $election, registryProgress: $clock}' >"$X4G_DIR/outcome.json" || return 1
  if [ "$want" = 1 ]; then
    jq -e '.activated == true and (.rateAfter | tonumber) == (.rateProposed | tonumber)' "$X4G_DIR/outcome.json" >/dev/null || { echo "x4g: the queued rate was not activated in ${X4G_WAIT} s although no election result should be open: $(jq -c . "$X4G_DIR/outcome.json")" >&2; return 1; }
  fi
  echo "PASS: x4g: outcome recorded: $(jq -c . "$X4G_DIR/outcome.json")"
}
