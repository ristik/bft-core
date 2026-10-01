#!/bin/bash
# f6c-reth-backup-acceptance.sh - restored voting against actual reth, with an actual older shard-home
# backup, while the independent signing authority stays alive outside everything restored (#105).
#
# Every component is a real process: the pinned reth for each validator, one root node, one
# `ubft signing-authority run`, and two `ubft shard-node run --executor engine-api` validators. The
# subject validator (v1) signs through the authority; v2 signs with its local key. The shard quorum is
# 2 of 2, so every round certified after v1 returns needs v1's authority-signed request: a certified
# round is the root chain's acceptance of that request, not an inference from v1 following along.
#
# Arms, each on a fresh cluster:
#
#   ordinary-restart  v1 signs work on ordinary (non-genesis) blocks, is stopped and started again
#                     from its own current home with --evidence-recover.
#   backup-restore    v1 signs work on an ordinary block, its home is copied while it is frozen, the
#                     certified chain and the authority's record then advance with v1 still signing,
#                     v1 is stopped, its home is replaced by the older copy, and it is started again
#                     with --evidence-recover. The same authority process and its record run
#                     throughout; nothing of the authority is copied, reset or restored.
#
# In both arms v1's execution client (reth) keeps running with its datadir untouched, so the arm
# isolates the shard-side restart or rollback. Rolling back the execution datadir, and power-loss
# durability of any store, are NOT covered. Host, backup and snapshot isolation of the authority is a
# deployment premise, not something a same-host run can measure.
#
# The events are reported separately, in the order they must happen:
#   acquisition   the evidence requester finished with state=ready;
#   adoption      the applier committed the certified block, which must be the exact ordinary block
#                 both execution clients hold (not the genesis exception), with no transaction
#                 injected since the restart and no non-quiet round certified since the restart;
#   signing       v1 submits authority-signed requests again, none of them before the adoption line;
#   fresh work    only then one transaction is injected; the round that certifies its block needs
#                 v1's request, and both execution clients must agree on the block and the receipt.
#
# Observations fail closed, as in scripts/f6c-authority-acceptance.sh, whose helpers this lane uses in
# library mode (one copy). Evidence is sealed (manifest and digests, execution datadirs excluded)
# before the datadirs and secrets are removed.
#
# Usage: scripts/f6c-reth-backup-acceptance.sh [-s arm]... [-o evidence-dir]
#        scripts/f6c-reth-backup-acceptance.sh --self-test
#   -s  run only this arm (repeatable; default: ordinary-restart backup-restore)
#   -o  evidence directory (default: evidence-runs/f6c-reth-backup-<UTC time>)
#   URETH_BIN selects the fork client (default: the pinned commit, obtained and verified by
#   scripts/lib/reth-pin.sh). An explicitly supplied binary is still verified against the pin.

set -u -o pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

chainID=31337
# The f6b library supplies the execution-client helpers (rpc, blockAt, sendTx, waitForReceipt,
# receiptIdentity, countTransactions). The authority lane is sourced after it, so its fail-closed
# pass/fail and observation helpers are the ones in effect.
# shellcheck source=lib/f6b-acceptance-lib.sh
source scripts/lib/f6b-acceptance-lib.sh
# shellcheck source=f6c-authority-acceptance.sh
F6C_LANE_LIBRARY=1 source scripts/f6c-authority-acceptance.sh

partitionID=8
networkID=3
t2Millis=5000
validators=2
rootP2PPort=46662
rootRPCPort=46866
valP2PBase=46111
valRPCBase=46311
rethEngineBase=48551
rethEthBase=48545
rethP2PBase=40401
recoveryFlag="--evidence-recover"

arms=()
# --- lane helpers (tested offline by reth_lane_self_test) -----------------------------------------

# start_any <name> <log> <command...> starts a process from this checkout and records its pid, like
# start_bg, for commands other than build/ubft.
start_any() {
  local name=$1 log=$2 pid
  shift 2
  : >>"$log" || { artifact_error "could not create $log"; return 1; }
  logcmd "$@" || return 1
  "$@" >>"$log" 2>&1 </dev/null &
  pid=$!
  if ! { mkdir -p "$scen/pids" && echo "$pid" >"$scen/pids/$name"; }; then
    artifact_error "could not record pid $pid of $name; stopping it now"
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 1
  fi
  echo "$(stamp) started $name pid $pid: $(ps -o command= -p "$pid" 2>/dev/null)" >>"$scen/processes.txt" ||
    artifact_error "$scen/processes.txt"
  return 0
}

# count_between <file> <after line> <before line> <substring> [second substring]: matches strictly
# between two marks. 2, with nothing printed, when the file cannot be read to the later mark.
count_between() {
  local file=$1 from=$2 to=$3 out
  readable "$file" || return 2
  is_count "$from" && is_count "$to" || return 2
  [ "$to" -ge "$from" ] || return 2
  out=$(awk -v a="$from" -v b="$to" -v p="$4" -v q="${5:-}" '
    NR > a && NR < b && index($0, p) && (q == "" || index($0, q)) {c++}
    END {if (NR < b - 1) exit 3; print c + 0}' "$file") || return 2
  is_count "$out" || return 2
  echo "$out"
}

# adopted_block <log> <after line> prints "0x<blockHash> 0x<stateRoot>" from the first adoption line
# after the mark: 1 when there is none, 2 when the log cannot be read or the line is malformed.
adopted_block() {
  local line h r
  line=$(line_after "$1" "$2" "recovered from authenticated evidence: the certified block is committed")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  h=$(echo "$line" | grep -o 'blockHash=[0-9a-f]\{64\}' | head -1 | cut -d= -f2)
  r=$(echo "$line" | grep -o 'stateRoot=[0-9a-f]\{64\}' | head -1 | cut -d= -f2)
  [ -n "$h" ] && [ -n "$r" ] || return 2
  echo "0x$h 0x$r"
}

# same_block <a> <b>: two complete "<number> <hash> <stateRoot>" triples from blockAt, equal.
same_block() {
  [ -n "$1" ] && [ "$1" = "$2" ] && [ "$(echo "$1" | wc -w | tr -d ' ')" = 3 ]
}

# record_advanced <before.json> <after.json>: the authority's status has the same session generation,
# is not faulted, and holds a strictly higher reserved round. Unreadable snapshots are not advanced.
record_advanced() {
  [ "$(jq -n --slurpfile b "$1" --slurpfile a "$2" \
    '($b[0].reservedRound | type) == "number" and ($a[0].reservedRound | type) == "number"
     and $a[0].generation == $b[0].generation and ($a[0].faulted | not)
     and $a[0].reservedRound > $b[0].reservedRound' 2>/dev/null)" = true ]
}

# checkpoint_rolled_back <restored> <backup> <replaced>: the restored checkpoint is byte-identical to
# the backup and differs from the checkpoint it replaced.
checkpoint_rolled_back() {
  local r b p
  r=$({ shasum -a 256 <"$1" | cut -d' ' -f1; } 2>/dev/null) || return 1
  b=$({ shasum -a 256 <"$2" | cut -d' ' -f1; } 2>/dev/null) || return 1
  p=$({ shasum -a 256 <"$3" | cut -d' ' -f1; } 2>/dev/null) || return 1
  [ "${#r}" -eq 64 ] && [ "$r" = "$b" ] && [ "$r" != "$p" ]
}

# first_round_after <log> <after line>: the round of the first submission after the mark; 1 when none,
# 2 when unreadable or malformed.
first_round_after() {
  local line r
  line=$(line_after "$1" "$2" "submitting block certification request")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  r=$(echo "$line" | grep -o ' round=[0-9]*' | head -1 | grep -o '[0-9]*$')
  is_count "$r" || return 2
  echo "$r"
}

validator_home() { echo "$scen/v$1"; }
eth_url() { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }

validator_addr() {
  local i=$1 id
  id=$(ubft node-id --home "$(validator_home "$i")" | tail -n1) || return 1
  echo "/ip4/127.0.0.1/tcp/$((valP2PBase + i - 1))/p2p/$id"
}

# start_validator <index> [extra flags...]: v1 signs through the authority, v2 with its local key.
start_validator() {
  local i=$1 home other addr extra=()
  shift
  home=$(validator_home "$i")
  other=$((3 - i))
  addr=$(validator_addr "$other") || { fail "could not read validator $other's address"; return 1; }
  if [ "$i" -eq 1 ]; then
    extra=(--signing-authority-socket "$sockDir/client.sock" --signing-authority-credential "$scen/authority/client.cred")
  fi
  start_any "v$i" "$home/debug.log" build/ubft shard-node run --home "$home" --executor engine-api --registry-layout 1 \
    --address "/ip4/127.0.0.1/tcp/$((valP2PBase + i - 1))" --bootnodes "$rootBoot,$addr" \
    --trust-base "$scen/trust-base.json" --shard-conf "$scen/shard-conf-${partitionID}_0.json" \
    --rpc-server-address "127.0.0.1:$((valRPCBase + i - 1))" \
    --engine-url "http://127.0.0.1:$((rethEngineBase + i - 1))" --eth-url "$(eth_url "$i")" \
    --jwt-secret "$home/jwt.hex" --log-format text --log-level debug \
    ${extra[@]+"${extra[@]}"} "$@"
}

validator_health() { # <index> <name>
  curl -fsS "http://127.0.0.1:$((valRPCBase + $1 - 1))/api/v1/health" >"$scen/health-v$1-$2.json" 2>"$scen/health-v$1-$2.err"
}

teardown_arm() {
  local dir=$1
  stop_proc "$dir" v1 'ubft shard-node run'
  stop_proc "$dir" v2 'ubft shard-node run'
  stop_proc "$dir" authority 'ubft signing-authority run'
  stop_proc "$dir" root 'ubft root-node run'
  stop_proc "$dir" reth1 'reth node'
  stop_proc "$dir" reth2 'reth node'
}

# --- evidence and verdict (this lane's own: reth datadirs are excluded from the seal) ---------------

write_manifest() {
  {
    echo "f6c real-reth restart and shard-home backup acceptance run"
    echo "started:          $startedAt"
    echo "finished:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "reached:          $reached"
    echo "failed asserts:   $failures (at the time this manifest was written)"
    echo "evidence writes:  $artifactErrors failures before this manifest"
    echo "stopped early:    ${abortedScenarios[*]+${abortedScenarios[*]}}"
    echo "verdict:          the exit status and RESULT line, which also count failures to write this manifest and the digests"
    echo "invocation:       $invocation"
    echo "arms:             ${arms[*]+${arms[*]}}"
    echo "repository:       $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "worktree clean:   $([ -z "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo 'NO: this run is not reproducible from the recorded revision')"
    echo "ubft sha256:      $([ -x build/ubft ] && shasum -a 256 build/ubft | cut -d' ' -f1 || echo missing)"
    local rethDesc="not resolved"
    if [ -n "${URETH_BIN:-}" ]; then
      rethDesc="$URETH_BIN, commit $("$URETH_BIN" --version 2>/dev/null | sed -n 's/^Commit SHA: //p') (pinned ${URETH_PIN_COMMIT:-unknown}), sha256 $(shasum -a 256 "$URETH_BIN" 2>/dev/null | cut -d' ' -f1)"
    fi
    echo "reth:             $rethDesc"
    echo "go:               $(go version 2>/dev/null)"
    echo "host:             $(uname -srm)"
    echo "cluster:          network $networkID, partition $partitionID, T2 ${t2Millis}ms, one root node, $validators validators (quorum 2 of 2), v1 signs through the authority, v2 with its local key"
    echo "ports:            root $rootP2PPort/$rootRPCPort, validators p2p $valP2PBase+, rpc $valRPCBase+, reth engine $rethEngineBase+, eth $rethEthBase+, p2p $rethP2PBase+"
    echo "restart flags:    v1 restarted with $recoveryFlag; initial starts without it"
    echo "identities:       <arm>/identity.txt (node ids, authority key fingerprint, configuration hash, chain spec digest)"
    echo "not covered:      execution datadir rollback, power-loss durability, host/backup/snapshot isolation of the authority (a deployment premise)"
    echo "seal:             sha256sums.txt covers every file except reth datadirs, which are removed after sealing"
  } >"$runDir/manifest.txt"
}

write_digests() {
  local out
  out=$(cd "$runDir" && find . -type f ! -name sha256sums.txt ! -path '*/dd/*' -print0 | sort -z | xargs -0 shasum -a 256) || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" >"$runDir/sha256sums.txt"
}

remove_secrets() {
  local found f
  : >"$runDir/removed-secrets.txt" || { artifact_error "removed-secrets.txt"; return 1; }
  found=$(find "$runDir" \( -name '*.cred' -o -name 'keys.json' -o -name 'jwt.hex' \) -type f ! -path '*/dd/*') || {
    artifact_error "could not enumerate secrets under $runDir"
    return 1
  }
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if rm -f "$f" && [ ! -e "$f" ]; then
      echo "${f#"$runDir"/}" >>"$runDir/removed-secrets.txt" || artifact_error "removed-secrets.txt"
    else
      artifact_error "could not remove secret $f"
    fi
  done <<<"$found"
}

cleanup() {
  local rc=$? d reasons="" sealed=1
  trap - EXIT INT TERM
  for d in "$runDir"/*/; do
    [ -d "$d/pids" ] && teardown_arm "${d%/}"
  done
  for d in ${socketDirs[@]+"${socketDirs[@]}"}; do
    rm -rf "$d" || artifact_error "could not remove socket directory $d"
  done
  remove_secrets
  write_manifest || { artifact_error "could not write $runDir/manifest.txt"; sealed=0; }
  write_digests || { artifact_error "could not write $runDir/sha256sums.txt"; sealed=0; }
  # Preserve the stopped clients' datadirs if the evidence could not be sealed.
  if [ "$sealed" -eq 1 ]; then
    for d in "$runDir"/*/reth*/dd; do
      if [ -d "$d" ]; then
        rm -rf "$d" || artifact_error "could not remove sealed run datadir $d"
      fi
    done
  fi
  echo
  echo "evidence: $runDir"
  [ "$failures" -gt 0 ] && reasons="$reasons $failures failed assertions;"
  [ "$artifactErrors" -gt 0 ] && reasons="$reasons $artifactErrors evidence write failures;"
  [ ${#abortedScenarios[@]} -gt 0 ] && reasons="$reasons stopped early: ${abortedScenarios[*]};"
  [ "$reached" != "all arms" ] && reasons="$reasons reached: $reached;"
  if [ -n "$reasons" ]; then
    echo "RESULT: FAIL ($reasons )"
    [ "$rc" -eq 0 ] && rc=1
  else
    echo "RESULT: PASS"
  fi
  exit "$rc"
}

# --- the cluster ------------------------------------------------------------------------------------

setup_arm() {
  local p i out rc waited home genesisBlock
  for p in $rootP2PPort $rootRPCPort; do port_listening "$p" && { fail "port $p is in use; this run does not stop processes it did not start"; return 1; }; done
  for i in 1 2; do
    for p in $((valP2PBase + i - 1)) $((valRPCBase + i - 1)) $((rethEngineBase + i - 1)) $((rethEthBase + i - 1)) $((rethP2PBase + i - 1)); do
      port_listening "$p" && { fail "port $p is in use; this run does not stop processes it did not start"; return 1; }
    done
  done
  sockDir=$(mktemp -d /tmp/f6c-reth.XXXXXX) || { fail "could not create a socket directory"; return 1; }
  socketDirs+=("$sockDir")
  mkdir -p "$scen/authority" "$scen/root" "$scen/v1" "$scen/v2" "$scen/reth1" "$scen/reth2" && chmod 700 "$scen/authority" ||
    { artifact_error "could not create the arm directories"; return 1; }

  ubft root-node init --home "$scen/root" -g >>"$scen/setup.log" 2>&1 || { fail "root-node init"; return 1; }
  ubft trust-base generate --home "$scen" --epoch 1 --epoch-start 1 --network-id "$networkID" \
    --node-info "$scen/root/node-info.json" >>"$scen/setup.log" 2>&1 || { fail "trust-base generate"; return 1; }
  ubft trust-base sign --home "$scen/root" --trust-base "$scen/trust-base.json" >>"$scen/setup.log" 2>&1 || { fail "trust-base sign"; return 1; }
  for i in 1 2; do
    ubft shard-node init --home "$scen/v$i" -g >>"$scen/setup.log" 2>&1 || { fail "shard-node init v$i"; return 1; }
    openssl rand -hex 32 >"$scen/v$i/jwt.hex" || { artifact_error "could not write v$i's JWT secret"; return 1; }
  done
  v1ID=$(ubft node-id --home "$scen/v1" | tail -n1) && v2ID=$(ubft node-id --home "$scen/v2" | tail -n1) ||
    { fail "could not read the validators' node ids"; return 1; }

  ubft signing-authority credential --home "$scen/authority" --out "$scen/authority/operator.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "signing-authority credential"; return 1; }
  start_bg authority "$scen/authority/authority.log" signing-authority run --home "$scen/authority" \
    --client-socket "$sockDir/client.sock" --operator-socket "$sockDir/operator.sock" \
    --operator-credential "$scen/authority/operator.cred" --authority-id "f6c-reth-$scenario" \
    --node-id "$v1ID" --network-id "$networkID" --partition-id "$partitionID" --shard-id 0x80 \
    --shard-epoch 0 --root-epoch 1 --trust-base "$scen/trust-base.json" --log-format text --log-level debug ||
    { fail "could not start the authority process"; return 1; }
  wait_count "$scen/authority/authority.log" 0 1 20 "signing authority running"
  case $? in 0) ;; 1) fail "the authority process did not start"; return 1 ;; *) return 1 ;; esac
  # shellcheck disable=SC2046
  ubft signing-authority node-info $(opargs) --out "$scen/authority/node-info.json" >>"$scen/setup.log" 2>&1 ||
    { fail "signing-authority node-info"; return 1; }

  ubft shard-conf generate --home "$scen" --network-id "$networkID" --partition-id "$partitionID" --partition-type-id "$partitionID" \
    --shard-id 0x80 --epoch-start 1 --t2-timeout "$t2Millis" --partition-params "proof_type=exec,chain_id=$chainID" \
    --node-info "$scen/authority/node-info.json" --node-info "$scen/v2/node-info.json" >>"$scen/setup.log" 2>&1 ||
    { fail "shard-conf generate"; return 1; }
  conf_t2_ok "$scen/shard-conf-${partitionID}_0.json" && pass "the shard configuration's T2 is ${t2Millis}ms" ||
    { fail "the shard configuration's T2 is not ${t2Millis}ms"; return 1; }
  local confKey authorityKey localKey
  confKey=$(jq -r --arg id "$v1ID" '.validators[] | select(.nodeId == $id) | .sigKey' "$scen/shard-conf-${partitionID}_0.json")
  authorityKey=$(jq -r .sigKey "$scen/authority/node-info.json")
  localKey=$(jq -r .sigKey "$scen/v1/node-info.json")
  if [ -n "$confKey" ] && [ "$confKey" = "$authorityKey" ] && [ "$confKey" != "$localKey" ]; then
    pass "the shard configuration names v1 with the authority's key, not v1's local key"
  else
    fail "the shard configuration does not name v1 with the authority's key"
    return 1
  fi
  # shellcheck disable=SC2046
  ubft signing-authority complete-enrollment $(opargs) --shard-conf "$scen/shard-conf-${partitionID}_0.json" >>"$scen/setup.log" 2>&1 ||
    { fail "complete-enrollment"; return 1; }
  # shellcheck disable=SC2046
  ubft signing-authority replace-session $(opargs) --out "$scen/authority/client.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "replace-session"; return 1; }
  authority_status enrolled || { fail "status after enrollment"; return 1; }
  json_true "$scen/status-enrolled.json" '.enrollmentComplete and .generation == 1' &&
    pass "the authority is enrolled for the configuration naming its key, session generation 1" ||
    { fail "unexpected status after enrollment"; return 1; }

  ubft engine-api genesis --home "$scen" --shard-conf "$scen/shard-conf-${partitionID}_0.json" --out "$scen/evm-genesis.json" --registry-layout 1 >>"$scen/setup.log" 2>&1 ||
    { fail "engine-api genesis"; return 1; }
  python3 - "$scen/evm-genesis.json" "$scen/evm-genesis-funded.json" <<'PY' || { fail "could not fund the test genesis"; return 1; }
import json, subprocess, sys
g = json.load(open(sys.argv[1]))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open(sys.argv[2], "w"), indent=2)
PY
  {
    echo "arm:                  $scenario"
    echo "v1 node id:           $v1ID (signs through the authority)"
    echo "v2 node id:           $v2ID (local key)"
    echo "authority fingerprint: $(jq -r .signingKeyFingerprint "$scen/status-enrolled.json")"
    echo "shard conf hash:      $(jq -r .shardConfHash "$scen/status-enrolled.json")"
    echo "shard conf sha256:    $(shasum -a 256 "$scen/shard-conf-${partitionID}_0.json" | cut -d' ' -f1)"
    echo "chain spec sha256:    $(shasum -a 256 "$scen/evm-genesis-funded.json" | cut -d' ' -f1)"
  } >"$scen/identity.txt" || artifact_error "identity.txt"

  for i in 1 2; do
    start_any "reth$i" "$scen/reth$i/reth.log" "$URETH_BIN" node --chain "$scen/evm-genesis-funded.json" \
      --datadir "$scen/reth$i/dd" --authrpc.jwtsecret "$scen/v$i/jwt.hex" \
      --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
      --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,txpool \
      --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
      $(urethPinUnicityFlags) || { fail "could not start reth $i"; return 1; }
  done
  for i in 1 2; do
    waited=0
    until rpc "$(eth_url "$i")" eth_chainId '[]' 2>/dev/null | grep -q result; do
      [ "$waited" -ge 60 ] && { fail "reth $i did not answer within 60s"; return 1; }
      sleep 1
      waited=$((waited + 1))
    done
  done
  local enode
  enode=$(rpc "$(eth_url 1)" admin_nodeInfo '[]' | pyget "['result']['enode']")
  [ -n "$enode" ] && rpc "$(eth_url 2)" admin_addPeer "[\"$enode\"]" >/dev/null || { fail "could not peer the execution clients"; return 1; }
  genesisBlock=$(blockAt "$(eth_url 1)" 0x0) || { fail "could not read the execution genesis block"; return 1; }
  genesisHash=$(echo "$genesisBlock" | cut -d' ' -f2)
  pass "two pinned reth instances are up and peered on the funded chain spec (genesis ${genesisHash:0:18}...)"

  start_bg root "$scen/root/debug.log" root-node run --home "$scen/root" --address "/ip4/127.0.0.1/tcp/$rootP2PPort" \
    --trust-base "$scen/trust-base.json" --rpc-server-address "127.0.0.1:$rootRPCPort" --log-format text --log-level debug ||
    { fail "could not start the root node"; return 1; }
  waited=0
  until port_listening "$rootRPCPort"; do
    if ! alive "$(pid_of root)" || [ "$waited" -ge 30 ]; then fail "the root node did not start"; return 1; fi
    sleep 1
    waited=$((waited + 1))
  done
  logcmd curl -X PUT -H "Content-Type: application/json" -d "@$scen/shard-conf-${partitionID}_0.json" "http://127.0.0.1:$rootRPCPort/api/v1/configurations"
  curl -fsS -X PUT -H "Content-Type: application/json" -d "@$scen/shard-conf-${partitionID}_0.json" \
    "http://127.0.0.1:$rootRPCPort/api/v1/configurations" >>"$scen/setup.log" 2>&1 || { fail "registering the shard configuration"; return 1; }
  rootBoot="/ip4/127.0.0.1/tcp/$rootP2PPort/p2p/$(ubft node-id --home "$scen/root" | tail -n1)" ||
    { fail "could not read the root node identity"; return 1; }
  sleep 5 # wait_for_root_chain_settle in helper.sh explains this

  start_validator 2 || { fail "could not start v2"; return 1; }
  start_validator 1 || { fail "could not start v1"; return 1; }
  for i in 1 2; do
    wait_count "$(validator_home "$i")/debug.log" 0 3 180 "accepted certificate"
    case $? in 0) ;; 1) fail "v$i did not accept three certificates within 180s"; return 1 ;; *) return 1 ;; esac
  done
  if assert_count ge 1 "v1 started with the authority signer" "$scen/v1/debug.log" 0 'certificationSigning="signing authority at'; [ $? -eq 2 ]; then return 1; fi
  pass "the shard is certifying with both validators"
  rootControlMark=0
  return 0
}

# certify_transaction <label> <nonce> <submit to validator>: submits one transfer and waits until both
# execution clients hold its block. Sets txHash, txBlockHex, txBlock and txTriple.
certify_transaction() {
  local label=$1 nonce=$2 via=$3 i triple other
  txHash=$(sendTx "$(eth_url "$via")" "$nonce") || { fail "$label: could not submit the transaction"; return 1; }
  txBlockHex=$(waitForReceipt "$(eth_url "$via")" "$txHash" 90) || { fail "$label: the transaction was never executed"; return 1; }
  txBlock=$(dec "$txBlockHex")
  for i in 1 2; do
    waitForHead "$(eth_url "$i")" "$txBlock" 120 || { fail "$label: execution client $i never reached block $txBlock"; return 1; }
  done
  triple=$(blockAt "$(eth_url 1)" "$txBlockHex") || { fail "$label: could not read block $txBlock from client 1"; return 1; }
  other=$(blockAt "$(eth_url 2)" "$txBlockHex") || { fail "$label: could not read block $txBlock from client 2"; return 1; }
  if same_block "$triple" "$other"; then
    pass "$label: transaction in block $txBlock, identical on both execution clients (${triple#* })"
  else
    fail "$label: the execution clients disagree on block $txBlock: '$triple' vs '$other'"
    return 1
  fi
  txTriple=$triple
  return 0
}

# the signed work before the restart: an ordinary block certified with v1's authority-signed request.
establish_signed_work() {
  local label=$1 nonce=$2 mark rootMark
  mark=$(take_mark "$scen/v1/debug.log") || return 1
  rootMark=$(take_mark "$scen/root/debug.log") || return 1
  authority_status "$label-before" || { fail "$label: authority status"; return 1; }
  certify_transaction "$label" "$nonce" 2 || return 1
  if [ "$(echo "$txTriple" | cut -d' ' -f2)" = "$genesisHash" ] || [ "$txBlock" -lt 1 ]; then
    fail "$label: the block is the execution genesis"
    return 1
  fi
  if assert_count ge 1 "$label: v1 submitted a non-quiet authority-signed request for this work" "$scen/v1/debug.log" "$mark" "submitting block certification request" "quiet=false"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: v1 logged no signing refusal" "$scen/v1/debug.log" "$mark" "the certification request was not signed"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the root chain rejected no request as invalid" "$scen/root/debug.log" "$rootMark" "invalid block certification request"; [ $? -eq 2 ]; then return 1; fi
  authority_status "$label-after" || { fail "$label: authority status"; return 1; }
  if record_advanced "$scen/status-$label-before.json" "$scen/status-$label-after.json"; then
    pass "$label: the authority's record advanced from round $(jq -r .reservedRound "$scen/status-$label-before.json") to $(jq -r .reservedRound "$scen/status-$label-after.json") under generation $(jq -r .generation "$scen/status-$label-after.json")"
  else
    fail "$label: the authority's record did not advance under the same session"
  fi
  return 0
}

# restart_and_adopt <label> [restore]: stops v1 once the shard is quiet, optionally replaces its home with
# the backup, restarts it with evidence recovery, and asserts acquisition, exact adoption, P-id before
# signing, resumed signing and a non-decreasing authority record. Sets restartMark1/2, adoptLine.
restart_and_adopt() {
  local label=$1 restore=${2:-} tail head before after adopted certifiedHash certifiedRoot n first reserved
  tail=$(waitForQuietTail 4 180 "$scen/v1/debug.log" "$scen/v2/debug.log") ||
    { fail "$label: the shard never went quiet after the last transaction (tail $tail)"; return 1; }
  pass "$label: the shard is quiet ($tail quiet request entries since the last non-quiet one), so the newest certificate names no block"
  head=$(blockAt "$(eth_url 1)" latest) || { fail "$label: could not read v1's execution head"; return 1; }
  certifiedHash=$(echo "$head" | cut -d' ' -f2)
  certifiedRoot=$(echo "$head" | cut -d' ' -f3)
  same_block "$head" "$(blockAt "$(eth_url 2)" latest)" || { fail "$label: the execution clients disagree on the head before the restart"; return 1; }
  if [ "$certifiedHash" = "$genesisHash" ]; then fail "$label: the head before the restart is the execution genesis"; return 1; fi
  authority_status "$label-before-stop" || { fail "$label: authority status before the stop"; return 1; }

  note "stopping v1 (SIGTERM)"
  stop_proc "$scen" v1 'ubft shard-node run' TERM
  if [ "$restore" = restore ]; then
    mv "$scen/v1" "$scen/v1-replaced" || { artifact_error "could not move v1's current home aside"; return 1; }
    cp -Rp "$scen/v1-backup" "$scen/v1" || { artifact_error "could not restore v1's home from the backup"; return 1; }
    if checkpoint_rolled_back "$scen/v1/shard-node-luc.json" "$scen/v1-backup/shard-node-luc.json" "$scen/v1-replaced/shard-node-luc.json"; then
      pass "$label: v1's home is the older copy: its checkpoint is byte-identical to the backup and differs from the one it replaced"
    else
      fail "$label: the restored checkpoint is not the older backup"
      return 1
    fi
    : >>"$scen/v1/debug.log"
  fi
  local kept="v1's execution client kept running with its datadir untouched, still at block $(dec "$(echo "$head" | cut -d' ' -f1)")"
  [ "$restore" = restore ] && kept="$kept, certified work that the restored older shard home has not recorded"
  same_block "$head" "$(blockAt "$(eth_url 1)" latest)" &&
    pass "$label: $kept" ||
    { fail "$label: v1's execution head moved while the shard node was stopped"; return 1; }

  restartMark1=$(take_mark "$scen/v1/debug.log") || return 1
  restartMark2=$(take_mark "$scen/v2/debug.log") || return 1
  local rootMark
  rootMark=$(take_mark "$scen/root/debug.log") || return 1
  note "starting v1 again with $recoveryFlag"
  start_validator 1 "$recoveryFlag" || { fail "$label: could not restart v1"; return 1; }

  wait_count "$scen/v1/debug.log" "$restartMark1" 1 30 "resumed from persisted certificate"
  case $? in
  0) pass "$label: v1 resumed from its checkpoint at partition round $(line_after "$scen/v1/debug.log" "$restartMark1" "resumed from persisted certificate" | grep -o ' round=[0-9]*' | grep -o '[0-9]*$'), while the authority held round $(jq -r .reservedRound "$scen/status-$label-before-stop.json")" ;;
  1) fail "$label: v1 did not resume from its checkpoint"; return 1 ;;
  *) return 1 ;;
  esac
  wait_count "$scen/v1/debug.log" "$restartMark1" 1 240 "anchor recovery finished" "state=ready"
  case $? in
  0) pass "$label: ACQUISITION: $(line_after "$scen/v1/debug.log" "$restartMark1" "anchor recovery finished" | grep -o 'state=[a-z]* .*attempts=[0-9]* restarts=[0-9]*')" ;;
  1) fail "$label: evidence was not acquired within 240s"; return 1 ;;
  *) return 1 ;;
  esac
  wait_count "$scen/v1/debug.log" "$restartMark1" 1 120 "recovered from authenticated evidence: the certified block is committed"
  case $? in 0) ;; 1) fail "$label: no anchor was adopted within 120s"; return 1 ;; *) return 1 ;; esac
  adoptLine=$(first_after "$scen/v1/debug.log" "$restartMark1" "recovered from authenticated evidence: the certified block is committed") ||
    { fail "$label: could not locate the adoption line"; return 1; }
  adopted=$(adopted_block "$scen/v1/debug.log" "$restartMark1") || { fail "$label: the adoption line could not be read"; return 1; }
  if [ "$adopted" = "$certifiedHash $certifiedRoot" ]; then
    pass "$label: ADOPTION of the exact ordinary block ${certifiedHash:0:18}... at state ${certifiedRoot:0:18}..., which both execution clients hold and which is not the execution genesis"
  else
    fail "$label: adopted '$adopted', the certified head is '$certifiedHash $certifiedRoot'"
    return 1
  fi
  n=$(count_between "$scen/v1/debug.log" "$restartMark1" "$adoptLine" "submitting block certification request") ||
    { fail "$label: could not observe v1's submissions before the adoption"; return 1; }
  [ "$n" -eq 0 ] && pass "$label: P-id BEFORE SIGNING: v1 submitted nothing between the restart and the adoption" ||
    { fail "$label: v1 submitted $n requests before it adopted its anchor"; return 1; }
  n=$(count_between "$scen/v1/debug.log" "$restartMark1" "$adoptLine" "abstaining from the vote")
  [ $? -eq 0 ] && info "$label: v1 abstained on $n round(s) between the restart and the adoption (refusal diagnostics in $label-refusals.txt)"
  awk -v a="$restartMark1" -v b="$adoptLine" 'NR > a && NR < b && (index($0, "abstaining") || index($0, "declining to lead") || index($0, "cannot prove"))' \
    "$scen/v1/debug.log" >"$scen/$label-refusals.txt" || artifact_error "$label-refusals.txt"

  wait_count "$scen/v1/debug.log" "$adoptLine" 2 180 "submitting block certification request"
  case $? in 0) ;; 1) fail "$label: v1 did not resume signing within 180s after the adoption"; return 1 ;; *) return 1 ;; esac
  if assert_count ge 1 "$label: SIGNING resumed after adoption through the authority's record" "$scen/v1/debug.log" "$adoptLine" "signing only what the signing authority's record admits"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: no signing refusal since the restart" "$scen/v1/debug.log" "$restartMark1" "the certification request was not signed"; [ $? -eq 2 ]; then return 1; fi
  first=$(first_round_after "$scen/v1/debug.log" "$restartMark1") || { fail "$label: could not read v1's first request after the restart"; return 1; }
  reserved=$(jq -r .reservedRound "$scen/status-$label-before-stop.json")
  if is_count "$reserved" && [ "$first" -gt "$reserved" ]; then
    pass "$label: v1's first request after the restart is for round $first, above the round $reserved the authority held before the stop"
  else
    fail "$label: v1's first request after the restart is for round $first, not above the authority's round '$reserved'"
  fi
  wait_count "$scen/root/debug.log" "$rootMark" 1 60 "reached consensus, new InputHash"
  case $? in 0) ;; 1) fail "$label: no round was certified after v1 resumed"; return 1 ;; *) return 1 ;; esac
  if assert_count ge 1 "$label: the root chain certified rounds after the restart, each needing v1's request (quorum 2 of 2)" "$scen/root/debug.log" "$rootMark" "reached consensus, new InputHash"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the root chain rejected no request as invalid after the restart" "$scen/root/debug.log" "$rootMark" "invalid block certification request"; [ $? -eq 2 ]; then return 1; fi
  authority_status "$label-after-resume" || { fail "$label: authority status after resuming"; return 1; }
  if record_advanced "$scen/status-$label-before-stop.json" "$scen/status-$label-after-resume.json"; then
    pass "$label: the authority's record was not lowered by the restart: round $(jq -r .reservedRound "$scen/status-$label-before-stop.json") before the stop, $(jq -r .reservedRound "$scen/status-$label-after-resume.json") now, same session and process"
  else
    fail "$label: the authority's record did not move forward from the round it held before the stop"
  fi
  return 0
}

# fresh_work <label> <nonce>: after adoption, one transaction; its block is certified with v1's request,
# and both clients agree on the block and the receipt.
fresh_work() {
  local label=$1 nonce=$2 inject1 inject2 rootMark n mine theirs i
  inject1=$(take_mark "$scen/v1/debug.log") || return 1
  inject2=$(take_mark "$scen/v2/debug.log") || return 1
  rootMark=$(take_mark "$scen/root/debug.log") || return 1
  for i in 1 2; do
    local from to
    if [ "$i" -eq 1 ]; then from=$restartMark1; to=$inject1; else from=$restartMark2; to=$inject2; fi
    n=$(count_between "$scen/v$i/debug.log" "$from" "$((to + 1))" "submitting block certification request" "quiet=false") ||
      { fail "$label: could not observe v$i's requests between the restart and the injection"; return 1; }
    [ "$n" -eq 0 ] || { fail "$label: v$i logged $n non-quiet request(s) between the restart and the injection"; return 1; }
  done
  pass "$label: ordering: no non-quiet request by either validator between the restart and the injection, and the adoption (v1 log line $adoptLine) precedes it"
  authority_status "$label-before" || { fail "$label: authority status"; return 1; }
  certify_transaction "$label" "$nonce" 2 || return 1
  if assert_count ge 1 "$label: FRESH WORK: v1 submitted a non-quiet authority-signed request after the injection" "$scen/v1/debug.log" "$inject1" "submitting block certification request" "quiet=false"; [ $? -eq 2 ]; then return 1; fi
  if assert_count ge 1 "$label: the root chain certified a round after the injection (quorum 2 of 2 includes v1)" "$scen/root/debug.log" "$rootMark" "reached consensus, new InputHash"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the root chain rejected no request as invalid" "$scen/root/debug.log" "$rootMark" "invalid block certification request"; [ $? -eq 2 ]; then return 1; fi
  mine=$(receiptIdentity "$(eth_url 1)" "$txHash") || { fail "$label: v1's client has no receipt"; return 1; }
  theirs=$(receiptIdentity "$(eth_url 2)" "$txHash") || { fail "$label: v2's client has no receipt"; return 1; }
  [ "$mine" = "$theirs" ] && pass "$label: both execution clients hold the receipt in the same block: $mine" ||
    { fail "$label: receipts differ: '$mine' vs '$theirs'"; return 1; }
  for i in 1 2; do
    assertTransactionCount "$label: execution client $i" "$(eth_url "$i")" "$((nonce + 1))" "every transaction this arm submitted, and nothing else"
  done
  authority_status "$label-after" || { fail "$label: authority status"; return 1; }
  record_advanced "$scen/status-$label-before.json" "$scen/status-$label-after.json" &&
    pass "$label: the authority's record advanced to round $(jq -r .reservedRound "$scen/status-$label-after.json") for the fresh work" ||
    fail "$label: the authority's record did not advance for the fresh work"
  if validator_health 1 end && json_true "$scen/health-v1-end.json" '.voting == true'; then
    pass "$label: v1 reports voting=true after its request was certified"
  else
    fail "$label: v1's health does not report voting"
  fi
  return 0
}

arm_ordinary_restart() {
  local authorityPid
  setup_arm || return 1
  authorityPid=$(pid_of authority)
  establish_signed_work "ordinary-signed-work" 0 || return 1
  establish_signed_work "ordinary-advance" 1 || return 1
  restart_and_adopt "ordinary-restart" || return 1
  fresh_work "ordinary-fresh-work" 2 || return 1
  [ "$(pid_of authority)" = "$authorityPid" ] && alive "$authorityPid" &&
    pass "ordinary-restart: the same authority process (pid $authorityPid) ran throughout" || fail "ordinary-restart: the authority process changed"
  return 0
}

arm_backup_restore() {
  local authorityPid
  setup_arm || return 1
  authorityPid=$(pid_of authority)
  establish_signed_work "backup-signed-work" 0 || return 1

  # The backup: v1 is frozen so that its home is copied between writes, and resumed at once.
  signal_owned v1 'ubft shard-node run' STOP || { fail "could not freeze v1 for the backup"; return 1; }
  if cp -Rp "$scen/v1" "$scen/v1-backup"; then
    signal_owned v1 'ubft shard-node run' CONT
    pass "backup: v1's home copied while frozen (checkpoint sha256 $(shasum -a 256 <"$scen/v1-backup/shard-node-luc.json" | cut -d' ' -f1))"
  else
    signal_owned v1 'ubft shard-node run' CONT
    artifact_error "could not copy v1's home"
    return 1
  fi
  authority_status backup-at-copy || { fail "authority status at the backup"; return 1; }

  # The certified chain and the authority's record move past the backup with v1 still signing.
  establish_signed_work "backup-advance" 1 || return 1
  record_advanced "$scen/status-backup-at-copy.json" "$scen/status-backup-advance-after.json" &&
    pass "backup: after the copy, the authority's record advanced from round $(jq -r .reservedRound "$scen/status-backup-at-copy.json") to $(jq -r .reservedRound "$scen/status-backup-advance-after.json")" ||
    fail "backup: the authority's record did not advance after the copy"

  restart_and_adopt "backup-restore" restore || return 1
  fresh_work "backup-fresh-work" 2 || return 1
  [ "$(pid_of authority)" = "$authorityPid" ] && alive "$authorityPid" &&
    pass "backup-restore: the same authority process (pid $authorityPid) ran throughout, and nothing of it was copied or restored" ||
    fail "backup-restore: the authority process changed"
  return 0
}

run_arms() {
  local rc
  for scenario in "${arms[@]}"; do
    scen="$runDir/$scenario"
    mkdir -p "$scen" || { artifact_error "could not create $scen"; abortedScenarios+=("$scenario"); continue; }
    scenarioFailures=0
    echo
    echo "=== arm: $scenario ==="
    case "$scenario" in
    ordinary-restart) arm_ordinary_restart ;;
    backup-restore) arm_backup_restore ;;
    *) false ;;
    esac
    rc=$?
    if [ "$rc" -ne 0 ]; then
      abortedScenarios+=("$scenario")
      fail "arm $scenario stopped early"
    fi
    teardown_arm "$scen"
    echo "arm $scenario: $scenarioFailures failed assertions$([ "$rc" -ne 0 ] && echo ', stopped early')" | tee -a "$scen/summary.txt" ||
      artifact_error "$scen/summary.txt"
    reached="$scenario"
  done
  reached="all arms"
}

# --- self-test ----------------------------------------------------------------------------------------

reth_lane_self_test() {
  local selfFailures=0 scratch out rc a b
  st() { if [ "$2" -eq 0 ]; then echo "  PASS: $1"; else echo "  FAIL: $1"; selfFailures=$((selfFailures + 1)); fi; }
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/f6c-reth-selftest.XXXXXX") || return 1
  runDir="$scratch/run"
  mkdir -p "$runDir" && : >"$runDir/run.log" && : >"$runDir/commands.log" || return 1
  scen=""
  echo "=== self-test: f6c real-reth lane assertions ==="

  {
    echo 'time=1 msg="resumed from persisted certificate: ..."'
    echo 'time=2 msg="abstaining from the vote: this node cannot prove its executor is on the certified block"'
    echo "time=3 msg=\"recovered from authenticated evidence: the certified block is committed\" blockHash=$(printf 'a%.0s' $(seq 1 64)) stateRoot=$(printf 'b%.0s' $(seq 1 64)) anchorRound=9"
    echo 'time=4 msg="submitting block certification request" round=12 quiet=true leader=true'
  } >"$scratch/ordered.log"
  {
    echo 'time=1 msg="resumed from persisted certificate: ..."'
    echo 'time=2 msg="submitting block certification request" round=11 quiet=true leader=true'
    echo "time=3 msg=\"recovered from authenticated evidence: the certified block is committed\" blockHash=$(printf 'a%.0s' $(seq 1 64)) stateRoot=$(printf 'b%.0s' $(seq 1 64)) anchorRound=9"
  } >"$scratch/early.log"

  out=$(count_between "$scratch/ordered.log" 0 3 "submitting block certification request")
  st "no submission before the adoption line is counted as zero" "$([ $? -eq 0 ] && [ "$out" = 0 ] && echo 0 || echo 1)"
  out=$(count_between "$scratch/early.log" 0 3 "submitting block certification request")
  st "a submission before the adoption line is counted" "$([ $? -eq 0 ] && [ "$out" = 1 ] && echo 0 || echo 1)"
  count_between "$scratch/missing.log" 0 3 "submitting" >/dev/null 2>&1
  st "a missing log is not zero submissions before adoption" "$([ $? -eq 2 ] && echo 0 || echo 1)"
  count_between "$scratch/ordered.log" 0 40 "submitting" >/dev/null 2>&1
  st "a window past the end of a truncated log is not observed" "$([ $? -eq 2 ] && echo 0 || echo 1)"
  count_between "$scratch/ordered.log" 3 1 "submitting" >/dev/null 2>&1
  st "an inverted window is not observed" "$([ $? -eq 2 ] && echo 0 || echo 1)"

  out=$(adopted_block "$scratch/ordered.log" 0)
  st "the adopted block and state are read from the applier's line" "$([ $? -eq 0 ] && [ "$out" = "0x$(printf 'a%.0s' $(seq 1 64)) 0x$(printf 'b%.0s' $(seq 1 64))" ] && echo 0 || echo 1)"
  adopted_block "$scratch/ordered.log" 3 >/dev/null 2>&1
  st "no adoption after the mark is not an adoption" "$([ $? -eq 1 ] && echo 0 || echo 1)"
  adopted_block "$scratch/missing.log" 0 >/dev/null 2>&1
  st "an unreadable log is not an adoption" "$([ $? -eq 2 ] && echo 0 || echo 1)"
  echo 'time=5 msg="recovered from authenticated evidence: the certified block is committed" blockHash=abc stateRoot=def' >"$scratch/short.log"
  adopted_block "$scratch/short.log" 0 >/dev/null 2>&1
  st "a truncated block hash is not an adoption" "$([ $? -eq 2 ] && echo 0 || echo 1)"

  a="0x5 0x$(printf 'c%.0s' $(seq 1 64)) 0x$(printf 'd%.0s' $(seq 1 64))"
  same_block "$a" "$a"
  st "positive control: identical block triples are the same block" "$([ $? -eq 0 ] && echo 0 || echo 1)"
  same_block "" ""
  st "two unreadable blocks are not the same block" "$([ $? -ne 0 ] && echo 0 || echo 1)"
  same_block "0x5 0x$(printf 'c%.0s' $(seq 1 64))" "0x5 0x$(printf 'c%.0s' $(seq 1 64))"
  st "an incomplete block triple is not a block" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  echo '{"generation":1,"reservedRound":7,"faulted":false}' >"$scratch/s7.json"
  echo '{"generation":1,"reservedRound":9,"faulted":false}' >"$scratch/s9.json"
  echo '{"generation":2,"reservedRound":9,"faulted":false}' >"$scratch/g2.json"
  echo '{"generation":1,"reservedRound":9,"faulted":true}' >"$scratch/f9.json"
  record_advanced "$scratch/s7.json" "$scratch/s9.json"
  st "positive control: a higher round under the same session is an advance" "$([ $? -eq 0 ] && echo 0 || echo 1)"
  record_advanced "$scratch/s9.json" "$scratch/s7.json"
  st "a lower reserved round is not an advance" "$([ $? -ne 0 ] && echo 0 || echo 1)"
  record_advanced "$scratch/s9.json" "$scratch/s9.json"
  st "an unchanged reserved round is not an advance" "$([ $? -ne 0 ] && echo 0 || echo 1)"
  record_advanced "$scratch/s7.json" "$scratch/g2.json"
  st "a changed session generation is not the same record advancing" "$([ $? -ne 0 ] && echo 0 || echo 1)"
  record_advanced "$scratch/s7.json" "$scratch/f9.json"
  st "a faulted authority is not an advance" "$([ $? -ne 0 ] && echo 0 || echo 1)"
  record_advanced "$scratch/missing.json" "$scratch/s9.json"
  st "an unreadable status is not an advance" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  echo older >"$scratch/backup.luc" && cp "$scratch/backup.luc" "$scratch/restored.luc" && echo newer >"$scratch/replaced.luc"
  checkpoint_rolled_back "$scratch/restored.luc" "$scratch/backup.luc" "$scratch/replaced.luc"
  st "positive control: the restored checkpoint is the backup and not the replaced one" "$([ $? -eq 0 ] && echo 0 || echo 1)"
  checkpoint_rolled_back "$scratch/replaced.luc" "$scratch/backup.luc" "$scratch/replaced.luc"
  st "a checkpoint that was not replaced is not a rollback" "$([ $? -ne 0 ] && echo 0 || echo 1)"
  checkpoint_rolled_back "$scratch/missing.luc" "$scratch/backup.luc" "$scratch/replaced.luc"
  st "a missing restored checkpoint is not a rollback" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  out=$(first_round_after "$scratch/ordered.log" 0)
  st "the first request round after the mark is read" "$([ $? -eq 0 ] && [ "$out" = 12 ] && echo 0 || echo 1)"
  first_round_after "$scratch/ordered.log" 4 >/dev/null 2>&1
  st "no request after the mark has no round" "$([ $? -eq 1 ] && echo 0 || echo 1)"
  first_round_after "$scratch/missing.log" 0 >/dev/null 2>&1
  st "an unreadable log has no first round" "$([ $? -eq 2 ] && echo 0 || echo 1)"

  # The seal excludes execution datadirs and fails the verdict when it cannot be written.
  local d="$scratch/verdict"
  mkdir -p "$d/arm/reth1/dd" && : >"$d/run.log" && : >"$d/commands.log" && echo big >"$d/arm/reth1/dd/mdbx.dat" && echo log >"$d/arm/reth1/reth.log"
  (runDir=$d; write_digests) >/dev/null 2>&1
  st "the digests cover the reth log and exclude the datadir" "$(grep -q 'reth1/reth.log' "$d/sha256sums.txt" && ! grep -q 'dd/mdbx.dat' "$d/sha256sums.txt" && echo 0 || echo 1)"
  mkdir -p "$scratch/v2/arm/v1" "$scratch/v2/arm/reth1/dd" && echo retained >"$scratch/v2/arm/reth1/dd/sentinel" && : >"$scratch/v2/run.log" && : >"$scratch/v2/commands.log" && echo s >"$scratch/v2/arm/v1/jwt.hex" && mkdir "$scratch/v2/sha256sums.txt"
  out=$(
    (
      runDir="$scratch/v2" scen="" scenario="" socketDirs=() arms=(backup-restore) failures=0 artifactErrors=0
      abortedScenarios=() reached="all arms" startedAt=self-test invocation=self-test
      cleanup
    ) 2>&1
    echo "exit=$?"
  )
  st "a digest list that cannot be written fails the verdict" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"
  st "a failed seal preserves the stopped execution datadir" "$([ -f "$scratch/v2/arm/reth1/dd/sentinel" ] && echo 0 || echo 1)"
  st "a JWT secret is removed and listed before sealing" "$([ ! -e "$scratch/v2/arm/v1/jwt.hex" ] && grep -q 'arm/v1/jwt.hex' "$scratch/v2/removed-secrets.txt" && echo 0 || echo 1)"

  chmod -R u+rwx "$scratch" 2>/dev/null
  rm -rf "$scratch"
  echo "self-test: $selfFailures failed"
  [ "$selfFailures" -eq 0 ]
}

# --- main ---------------------------------------------------------------------------------------------

if [ "${1:-}" = "--self-test" ]; then
  reth_lane_self_test
  exit $?
fi

while getopts "hs:o:" o; do
  case "$o" in
  s) arms+=("$OPTARG") ;;
  o) runDir=$OPTARG ;;
  *)
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  esac
done
[ ${#arms[@]} -eq 0 ] && arms=(ordinary-restart backup-restore)
for a in "${arms[@]}"; do
  case "$a" in ordinary-restart | backup-restore) ;; *) echo "unknown arm: $a" >&2; exit 2 ;; esac
done
# The fork client. This lane drives shard nodes with `--executor engine-api`, and the node refuses
# a client without the three engine_*WithSealV1 methods, so resolve and verify the pinned fork. The
# old RETH_BIN indirection is folded into the resolver's URETH_BIN, which is verified too: an
# operator pointing at stock reth is refused rather than silently measured.
urethPinResolve || exit 2
# This lane seeds and runs the layout-1 SealRegistry explicitly (it has its own scenario directory, not test-nodes/),
# so it must run a pre-#47 ureth (the built-in pin).
case "$URETH_PIN_COMMIT" in
  39d7e59d* | ae6e6be9*) ;;
  *) echo "f6c-reth-backup: layout-1 lane refuses ureth $URETH_PIN_COMMIT (pre-#47 pins only)" >&2; exit 2 ;;
esac

startedAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
invocation="$0 $*"
[ -n "$runDir" ] || runDir="evidence-runs/f6c-reth-backup-$(date -u +%Y%m%dT%H%M%SZ)"
if ! prepare_run_dir; then
  echo "could not create the evidence directory $runDir; nothing was started" >&2
  exit 2
fi
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "=== f6c-reth-backup-acceptance: evidence in $runDir ==="
logcmd make build
if ! make build >"$runDir/build.log" 2>&1; then
  cat "$runDir/build.log"
  fail "make build"
  exit 1
fi

run_arms
