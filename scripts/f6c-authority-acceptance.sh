#!/bin/bash
# f6c-authority-acceptance.sh - process acceptance for the F6c signing authority deployment (#105).
#
# Every component here is a separate operating-system process of build/ubft, started the way an
# operator starts it: one root node, one `signing-authority run`, and one `shard-node run` with the
# fake executor. The operator commands are separate `build/ubft` invocations too. This is different
# evidence from cli/ubft/cmd/signing_authority_test.go, which runs the authority's `run` command in a
# goroutine of the test binary and builds the shard-side signer by calling buildCertificationSigning
# directly; that test never starts `shard-node run`. PIDs and command lines are recorded per scenario.
#
# Each scenario gets a fresh cluster, because fencing, authority loss and a shard restart each end
# this node's voting for the life of the process (a restored node is non-voting, and a new authority
# lifetime has a key no configuration names), so none can follow another in one cluster.
#
#   fencing            positive control, then `replace-session`: the node holds a fenced credential
#                      and abstains; nothing is signed locally and the root chain certifies nothing.
#   authority-loss     positive control, then the authority process is killed: the node abstains
#                      with signing-authority-unavailable; nothing is signed locally.
#   restart            positive control over several quiet rounds, then the shard node is stopped
#                      and started again from its retained checkpoint. It is non-voting and requests
#                      no signature. In this lane the P-id check refuses first (no-anchor: the fake
#                      executor produces no non-quiet round after genesis, so the restarted process
#                      observes no certificate naming a block), so the restored gate is not reached.
#   restart-at-anchor  the shard node is frozen (SIGSTOP) right after its first authority-signed
#                      request is sent, so the root certifies that round while the node's checkpoint
#                      is still the round before it, and then killed. The restarted process observes
#                      the non-quiet certificate, holds an anchor, passes P-id, and is stopped by the
#                      restored gate itself.
#
# In both restart scenarios the authority's enrollment, session generation and record are compared
# before and after the restart, and the same authority process runs throughout.
#
# Every scenario's setup: the enrollment is two-phase (the authority starts pending; a configuration
# generated from the shard's own node info is refused; the one generated from `signing-authority
# node-info` completes it), the configuration names the authority's key and not the local key, and a
# control run of `shard-node run` WITHOUT the authority flags (the local key, its own checkpoint file)
# has its request rejected by the root chain with a signature verification error. The shard is the
# only validator, so a consensus line in the root log afterwards can only come from a request that
# passed the same check against the key the configuration names.
#
# Usage: scripts/f6c-authority-acceptance.sh [-s scenario]... [-o evidence-dir]
#   -s  run only this scenario (repeatable; default: all four, in the order above)
#   -o  evidence directory (default: evidence-runs/f6c-authority-<UTC time>)
#
# Evidence is kept under the evidence directory; credential files and key configurations are removed
# at the end, after every process of the run has stopped. Cleanup stops only processes whose pid this
# run recorded, and only after checking that each is alive, runs the expected command, and has this
# checkout as its working directory (helper.sh owned_pid). There is no name-based sweep.

set -u -o pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=../helper.sh
source helper.sh

partitionID=8
networkID=3
t2Millis=3000
rootP2PPort=36662
rootRPCPort=36866
shardP2PPort=36111
shardRPCPort=36311

scenarios=()
runDir=""
while getopts "hs:o:" o; do
  case "$o" in
  s) scenarios+=("$OPTARG") ;;
  o) runDir=$OPTARG ;;
  *)
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  esac
done
[ ${#scenarios[@]} -eq 0 ] && scenarios=(fencing authority-loss restart restart-at-anchor)
for s in "${scenarios[@]}"; do
  case "$s" in
  fencing | authority-loss | restart | restart-at-anchor) ;;
  *)
    echo "unknown scenario: $s" >&2
    exit 2
    ;;
  esac
done

startedAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[ -n "$runDir" ] || runDir="evidence-runs/f6c-authority-$(date -u +%Y%m%dT%H%M%SZ)"
if [ -e "$runDir" ]; then
  echo "evidence directory already exists: $runDir" >&2
  exit 2
fi
mkdir -p "$runDir"
runDir=$(cd "$runDir" && pwd -P)
invocation="$0 $*"

failures=0
scenarioFailures=0
scenario=""
scen=""
socketDirs=()
reached="startup"

stamp() { date -u +%H:%M:%S; }
note() { echo "$(stamp) [$scenario] $*" | tee -a "$runDir/run.log"; }
pass() {
  echo "  PASS: $1" | tee -a "$runDir/run.log"
  [ -n "$scen" ] && echo "PASS: $1" >>"$scen/summary.txt"
  return 0
}
fail() {
  echo "  FAIL: $1" | tee -a "$runDir/run.log" >&2
  [ -n "$scen" ] && echo "FAIL: $1" >>"$scen/summary.txt"
  failures=$((failures + 1))
  scenarioFailures=$((scenarioFailures + 1))
  return 0
}

# logcmd records a command exactly as it is run, shell-quoted, before running it.
logcmd() {
  {
    printf '%s [%s] ' "$(stamp)" "${scenario:-run}"
    printf '%q ' "$@"
    echo
  } >>"$runDir/commands.log"
}
ubft() {
  logcmd build/ubft "$@"
  build/ubft "$@"
}

# alive reports whether a pid is a live, non-zombie process (a stopped process counts). kill -0
# succeeds on a zombie, and the processes of this run are this shell's children, so they are
# zombies until reaped.
alive() {
  local st
  st=$(ps -o stat= -p "$1" 2>/dev/null) || return 1
  case "$st" in *Z*) return 1 ;; esac
  return 0
}

# start_bg <name> <log> <ubft args...> starts one ubft process in the background from this checkout,
# records its pid under the scenario and its command line in processes.txt.
start_bg() {
  local name=$1 log=$2 pid
  shift 2
  logcmd build/ubft "$@"
  build/ubft "$@" >>"$log" 2>&1 </dev/null &
  pid=$!
  mkdir -p "$scen/pids"
  echo "$pid" >"$scen/pids/$name"
  echo "$(stamp) started $name pid $pid: $(ps -o command= -p "$pid" 2>/dev/null)" >>"$scen/processes.txt"
}

pid_of() { cat "$scen/pids/$1" 2>/dev/null; }

# signal_owned <name> <pattern> <signal> signals a recorded process of this scenario only if it is
# this checkout's.
signal_owned() {
  local pid
  pid=$(pid_of "$1")
  if alive "$pid" && owned_pid "$pid" "$2"; then
    kill "-$3" "$pid" && echo "$(stamp) sent SIG$3 to $1 pid $pid" >>"$scen/processes.txt"
  else
    echo "$(stamp) did not send SIG$3 to $1 pid $pid: not alive, or not a '$2' of this checkout" >>"$scen/processes.txt"
    return 1
  fi
}

# stop_proc <scenario dir> <name> <command pattern> [signal] stops a recorded process of this run
# only if it is this checkout's (owned_pid), waits at most 20 seconds, and reaps it. SIGCONT follows
# the signal so that a frozen process receives it.
stop_proc() {
  local dir=$1 name=$2 pattern=$3 sig=${4:-TERM} pidfile pid waited=0
  pidfile="$dir/pids/$name"
  [ -f "$pidfile" ] || return 0
  pid=$(cat "$pidfile")
  if alive "$pid" && owned_pid "$pid" "$pattern"; then
    kill "-$sig" "$pid" 2>/dev/null
    kill -CONT "$pid" 2>/dev/null
    while alive "$pid"; do
      [ "$waited" -eq 15 ] && kill -KILL "$pid" 2>/dev/null
      if [ "$waited" -ge 20 ]; then
        echo "$(stamp) $name pid $pid did not exit after SIG$sig and SIGKILL" >>"$dir/processes.txt"
        break
      fi
      sleep 1
      waited=$((waited + 1))
    done
    echo "$(stamp) stopped $name pid $pid with SIG$sig after ${waited}s" >>"$dir/processes.txt"
  else
    echo "$(stamp) $name pid $pid was not signalled: not alive, or not a '$pattern' of this checkout" >>"$dir/processes.txt"
  fi
  wait "$pid" 2>/dev/null
  mv "$pidfile" "$pidfile.stopped"
}

teardown_scenario() {
  local dir=$1
  stop_proc "$dir" shard 'ubft shard-node run'
  stop_proc "$dir" local-control 'ubft shard-node run'
  stop_proc "$dir" authority 'ubft signing-authority run'
  stop_proc "$dir" root 'ubft root-node run'
}

cleanup() {
  local rc=$? d f
  trap - EXIT INT TERM
  for d in "$runDir"/*/; do
    [ -d "$d/pids" ] && teardown_scenario "${d%/}"
  done
  for d in ${socketDirs[@]+"${socketDirs[@]}"}; do
    rm -rf "$d"
  done
  # Secrets of this run: operator and client credentials, and the root's and shard's key
  # configurations. Removed only now, after every process has stopped.
  : >"$runDir/removed-secrets.txt"
  while IFS= read -r f; do
    rm -f "$f" && echo "${f#"$runDir"/}" >>"$runDir/removed-secrets.txt"
  done < <(find "$runDir" \( -name '*.cred' -o -name 'keys.json' \) -type f)
  write_manifest
  echo
  echo "evidence: $runDir"
  if [ "$failures" -gt 0 ] || [ "$reached" != "all scenarios" ]; then
    echo "RESULT: FAIL ($failures failed assertions, reached: $reached)"
    [ "$rc" -eq 0 ] && rc=1
  else
    echo "RESULT: PASS"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

write_manifest() {
  {
    echo "f6c signing authority process acceptance run"
    echo "started:          $startedAt"
    echo "finished:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "reached:          $reached"
    echo "failed asserts:   $failures"
    echo "invocation:       $invocation"
    echo "scenarios:        ${scenarios[*]}"
    echo "repository:       $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "worktree clean:   $([ -z "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo 'NO: this run is not reproducible from the recorded revision')"
    echo "ubft sha256:      $([ -x build/ubft ] && shasum -a 256 build/ubft | cut -d' ' -f1 || echo missing)"
    echo "go:               $(go version 2>/dev/null)"
    echo "host:             $(uname -srm)"
    echo "cluster:          network $networkID, partition $partitionID, shard 0x80, T2 ${t2Millis}ms, one root node, one shard validator, fake executor"
    echo "ports:            root p2p $rootP2PPort, root rpc $rootRPCPort, shard p2p $shardP2PPort, shard rpc $shardRPCPort"
    echo "process model:    every root node, authority and shard node is a separate build/ubft process; see <scenario>/processes.txt"
    echo "commands:         commands.log"
  } >"$runDir/manifest.txt"
  (cd "$runDir" && find . -type f ! -name sha256sums.txt ! -name manifest.txt -print0 | sort -z | xargs -0 shasum -a 256 >sha256sums.txt)
}

lines() { if [ -f "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi; }

# count_after <file> <after line> <substring> [second substring]
count_after() {
  awk -v n="$2" -v p="$3" -v q="${4:-}" 'NR > n && index($0, p) && (q == "" || index($0, q)) {c++} END {print c + 0}' "$1" 2>/dev/null || echo 0
}

# first_after <file> <after line> <substring> [second substring] prints the first matching line number.
first_after() {
  awk -v n="$2" -v p="$3" -v q="${4:-}" 'NR > n && index($0, p) && (q == "" || index($0, q)) {print NR; exit}' "$1" 2>/dev/null
}

# line_after <file> <after line> <substring> prints the first matching line.
line_after() {
  awk -v n="$2" -v p="$3" 'NR > n && index($0, p) {print; exit}' "$1" 2>/dev/null
}

# wait_count <file> <after line> <n> <timeout seconds> <substring> [second substring]
wait_count() {
  local file=$1 after=$2 n=$3 timeout=$4 waited=0
  shift 4
  while [ "$(count_after "$file" "$after" "$@")" -lt "$n" ]; do
    [ "$waited" -ge "$timeout" ] && return 1
    sleep 1
    waited=$((waited + 1))
  done
  return 0
}

port_listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

wait_port_free() { # <port> <timeout seconds>
  local waited=0
  while port_listening "$1"; do
    [ "$waited" -ge "$2" ] && return 1
    sleep 1
    waited=$((waited + 1))
  done
}

opargs() { echo --home "$scen/authority" --operator-socket "$sockDir/operator.sock" --operator-credential "$scen/authority/operator.cred"; }

authority_status() { # <name>: writes status-<name>.json, fails if the authority does not answer
  # shellcheck disable=SC2046
  ubft signing-authority status $(opargs) >"$scen/status-$1.json" 2>"$scen/status-$1.err"
}

health() { # <name>
  curl -fsS "http://127.0.0.1:$shardRPCPort/api/v1/health" >"$scen/health-$1.json" 2>"$scen/health-$1.err"
}

submitted_round() { # <round>: the shard log has a submission for this round
  grep -q "msg=\"submitting block certification request\" round=$1 " "$scen/shard/debug.log"
}

start_shard() {
  start_bg shard "$scen/shard/debug.log" shard-node run --home "$scen/shard" --executor fake \
    --address "/ip4/127.0.0.1/tcp/$shardP2PPort" --bootnodes "$rootBoot" \
    --trust-base "$scen/trust-base.json" --shard-conf "$scen/shard-conf-${partitionID}_0.json" \
    --rpc-server-address "127.0.0.1:$shardRPCPort" --log-format text --log-level debug \
    --signing-authority-socket "$sockDir/client.sock" \
    --signing-authority-credential "$scen/authority/client.cred"
}

# setup_cluster builds a fresh cluster, runs the two-phase enrollment with real processes, and runs
# the local-key control against the root verifier. The caller starts the authority-backed shard node.
setup_cluster() {
  local p out rc
  for p in $rootP2PPort $rootRPCPort $shardP2PPort $shardRPCPort; do
    if port_listening "$p"; then
      fail "port $p is already in use by another process; this run does not stop processes it did not start"
      return 1
    fi
  done
  sockDir=$(mktemp -d /tmp/f6c-sa.XXXXXX) || return 1
  socketDirs+=("$sockDir")
  mkdir -p "$scen/authority" "$scen/control" && chmod 700 "$scen/authority"

  ubft root-node init --home "$scen/root" -g >>"$scen/setup.log" 2>&1 || { fail "root-node init"; return 1; }
  ubft trust-base generate --home "$scen" --epoch 1 --epoch-start 1 --network-id "$networkID" \
    --node-info "$scen/root/node-info.json" >>"$scen/setup.log" 2>&1 || { fail "trust-base generate"; return 1; }
  ubft trust-base sign --home "$scen/root" --trust-base "$scen/trust-base.json" >>"$scen/setup.log" 2>&1 || { fail "trust-base sign"; return 1; }
  ubft shard-node init --home "$scen/shard" -g >>"$scen/setup.log" 2>&1 || { fail "shard-node init"; return 1; }
  nodeID=$(ubft node-id --home "$scen/shard" | tail -n1)
  localSigKey=$(jq -r .sigKey "$scen/shard/node-info.json" | sed 's/^0x//')

  ubft signing-authority credential --home "$scen/authority" --out "$scen/authority/operator.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "signing-authority credential"; return 1; }
  start_bg authority "$scen/authority/authority.log" signing-authority run --home "$scen/authority" \
    --client-socket "$sockDir/client.sock" --operator-socket "$sockDir/operator.sock" \
    --operator-credential "$scen/authority/operator.cred" --authority-id "f6c-acceptance-$scenario" \
    --node-id "$nodeID" --network-id "$networkID" --partition-id "$partitionID" --shard-id 0x80 \
    --shard-epoch 0 --root-epoch 1 --trust-base "$scen/trust-base.json" --log-format text --log-level debug
  if ! wait_count "$scen/authority/authority.log" 0 1 20 "signing authority running"; then
    fail "the authority process did not start: $(tail -3 "$scen/authority/authority.log")"
    return 1
  fi
  authorityKey=$(sed -n 's/.* signingKey=\([0-9a-f]*\).*/\1/p' "$scen/authority/authority.log" | head -1)
  authorityFingerprint=$(sed -n 's/.* signingKeyFingerprint=\([0-9a-f]*\).*/\1/p' "$scen/authority/authority.log" | head -1)

  authority_status pending || { fail "status of the pending authority: $(cat "$scen/status-pending.err")"; return 1; }
  if [ "$(jq -r .enrollmentComplete "$scen/status-pending.json")" = false ]; then
    pass "the authority process starts pending (enrollmentComplete=false)"
  else
    fail "the authority process did not start pending"
  fi

  # shellcheck disable=SC2046
  out=$(ubft signing-authority replace-session $(opargs) --out "$scen/authority/client.cred" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ] && echo "$out" | grep -q signing-enrollment-incomplete && [ ! -e "$scen/authority/client.cred" ]; then
    pass "replace-session is refused while pending (signing-enrollment-incomplete), and no client credential exists"
  else
    fail "replace-session while pending: rc=$rc, $out"
  fi

  # shellcheck disable=SC2046
  ubft signing-authority node-info $(opargs) --out "$scen/authority/node-info.json" >>"$scen/setup.log" 2>&1 ||
    { fail "signing-authority node-info"; return 1; }
  local confArgs=(--network-id "$networkID" --partition-id "$partitionID" --partition-type-id "$partitionID"
    --shard-id 0x80 --epoch-start 1 --t2-timeout "$t2Millis" --partition-params "proof_type=exec,chain_id=31337")

  # Control: the configuration generated from `shard-node init`'s own node info names the local key.
  ubft shard-conf generate --home "$scen/control" "${confArgs[@]}" --node-info "$scen/shard/node-info.json" >>"$scen/setup.log" 2>&1 ||
    { fail "shard-conf generate (local control)"; return 1; }
  # shellcheck disable=SC2046
  out=$(ubft signing-authority complete-enrollment $(opargs) --shard-conf "$scen/control/shard-conf-${partitionID}_0.json" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ] && echo "$out" | grep -q signing-context-mismatch; then
    pass "a configuration generated from the shard's local node info is refused by the authority process (signing-context-mismatch)"
  else
    fail "complete-enrollment with the local-key configuration: rc=$rc, $out"
  fi

  ubft shard-conf generate --home "$scen" "${confArgs[@]}" --node-info "$scen/authority/node-info.json" >>"$scen/setup.log" 2>&1 ||
    { fail "shard-conf generate"; return 1; }
  confSigKey=$(jq -r --arg id "$nodeID" '.validators[] | select(.nodeId == $id) | .sigKey' "$scen/shard-conf-${partitionID}_0.json" | sed 's/^0x//')
  local confFingerprint
  confFingerprint=$(printf '%s' "$confSigKey" | xxd -r -p | shasum -a 256 | cut -d' ' -f1)
  if [ -n "$authorityKey" ] && [ "$confSigKey" = "$authorityKey" ] && [ "$confSigKey" != "$localSigKey" ] &&
    [ "$confFingerprint" = "$authorityFingerprint" ]; then
    pass "the shard configuration names node $nodeID with the authority process's key (fingerprint $authorityFingerprint), not the local key"
  else
    fail "configuration key $confSigKey, authority key $authorityKey (fingerprint $authorityFingerprint, computed $confFingerprint), local key $localSigKey"
  fi

  # shellcheck disable=SC2046
  ubft signing-authority complete-enrollment $(opargs) --shard-conf "$scen/shard-conf-${partitionID}_0.json" >>"$scen/setup.log" 2>&1 ||
    { fail "complete-enrollment with the authority configuration"; return 1; }
  # shellcheck disable=SC2046
  ubft signing-authority replace-session $(opargs) --out "$scen/authority/client.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "replace-session after completion"; return 1; }
  authority_status enrolled || { fail "status after enrollment"; return 1; }
  if [ "$(jq -r '.enrollmentComplete and .generation == 1 and (.faulted | not) and (.keyLost | not)' "$scen/status-enrolled.json")" = true ]; then
    pass "complete-enrollment and replace-session succeed: enrolled, session generation 1"
  else
    fail "unexpected status after enrollment: $(cat "$scen/status-enrolled.json")"
  fi

  start_bg root "$scen/root/debug.log" root-node run --home "$scen/root" --address "/ip4/127.0.0.1/tcp/$rootP2PPort" \
    --trust-base "$scen/trust-base.json" --rpc-server-address "127.0.0.1:$rootRPCPort" --log-format text --log-level debug
  local waited=0
  until port_listening "$rootRPCPort"; do
    if ! alive "$(pid_of root)" || [ "$waited" -ge 30 ]; then
      fail "the root node did not start: $(tail -3 "$scen/root/debug.log")"
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  logcmd curl -X PUT -H "Content-Type: application/json" -d "@$scen/shard-conf-${partitionID}_0.json" "http://127.0.0.1:$rootRPCPort/api/v1/configurations"
  curl -fsS -X PUT -H "Content-Type: application/json" -d "@$scen/shard-conf-${partitionID}_0.json" \
    "http://127.0.0.1:$rootRPCPort/api/v1/configurations" >>"$scen/setup.log" 2>&1 || { fail "registering the shard configuration"; return 1; }
  rootBoot="/ip4/127.0.0.1/tcp/$rootP2PPort/p2p/$(ubft node-id --home "$scen/root" | tail -n1)"
  sleep 5 # wait_for_root_chain_settle in helper.sh explains this

  # Control against the root verifier: the same node, started without the authority flags, signs
  # with the key configuration's key. Its own checkpoint file keeps it from touching the checkpoint
  # the authority-backed node uses.
  local rootLog="$scen/root/debug.log" controlLog="$scen/control/shard-local.log"
  start_bg local-control "$controlLog" shard-node run --home "$scen/shard" --executor fake \
    --address "/ip4/127.0.0.1/tcp/$shardP2PPort" --bootnodes "$rootBoot" \
    --trust-base "$scen/trust-base.json" --shard-conf "$scen/shard-conf-${partitionID}_0.json" \
    --luc-store "$scen/control/local-luc.json" --log-format text --log-level debug
  if wait_count "$rootLog" 0 1 90 "invalid block certification request" "signature verification"; then
    pass "control: the same node signing with its local key (certificationSigning=\"local key\": $(grep -c 'certificationSigning="local key"' "$controlLog")) has its request rejected by the root chain: $(line_after "$rootLog" 0 "invalid block certification request" | grep -o 'invalid block certification request[^"]*' | cut -c1-160)"
  else
    fail "control: the root chain did not reject the local-key request within 90s"
  fi
  local n
  n=$(count_after "$rootLog" 0 "reached consensus, new InputHash")
  [ "$n" -eq 0 ] && pass "control: the root chain reached no consensus on the local-key request" ||
    fail "control: the root chain reached consensus $n times during the local-key control"
  stop_proc "$scen" local-control 'ubft shard-node run'
  wait_port_free "$shardP2PPort" 20 || { fail "the control node's port $shardP2PPort was not released"; return 1; }
  rootControlMark=$(lines "$rootLog")
  return 0
}

start_authority_shard() {
  start_shard
  sleep 2
  check_shard_started
}

# check_shard_started: the authority-backed node is running and pinned the configured key.
check_shard_started() {
  if ! alive "$(pid_of shard)"; then
    fail "shard-node run exited at startup: $(tail -5 "$scen/shard/debug.log")"
    return 1
  fi
  if grep -q "certificationSigning=\"signing authority at $sockDir/client.sock, key fingerprint $authorityFingerprint\"" "$scen/shard/debug.log"; then
    pass "shard-node run started with the authority signer pinned to fingerprint $authorityFingerprint"
  else
    fail "shard-node run did not report the authority signer: $(grep -o 'certificationSigning=[^=]*' "$scen/shard/debug.log" | head -1)"
  fi
  ps -o pid,ppid,stat,command -p "$(pid_of root),$(pid_of authority),$(pid_of shard)" >"$scen/process-table.txt"
  return 0
}

# positive_control: the running node's requests are signed by the authority and certified.
positive_control() {
  local log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" n reserved i ok=0
  if wait_count "$log" 0 3 120 "submitting block certification request"; then
    pass "the node signed and submitted $(count_after "$log" 0 "submitting block certification request") certification requests through the authority"
  else
    fail "the node did not submit three certification requests within 120s"
    return 1
  fi
  if wait_count "$rootLog" "$rootControlMark" 3 30 "reached consensus, new InputHash"; then
    pass "the root chain reached consensus $(count_after "$rootLog" "$rootControlMark" "reached consensus, new InputHash") times on the only validator's requests"
  else
    fail "the root chain did not reach consensus on the node's requests"
  fi
  if wait_count "$log" 0 3 30 "accepted certificate" "class=valid"; then
    pass "the node accepted $(count_after "$log" 0 "accepted certificate" "class=valid") valid certificates"
  else
    fail "the node accepted no valid certificates"
  fi
  n=$(count_after "$rootLog" "$rootControlMark" "invalid block certification request")
  [ "$n" -eq 0 ] && pass "the root chain rejected no certification request as invalid after the control" ||
    fail "the root chain rejected $n certification requests as invalid after the control"
  authority_status positive || fail "status after the positive control"
  if [ "$(jq -r '.generation == 1 and .hasReservation and .reservedRound > 0 and (.faulted | not)' "$scen/status-positive.json")" = true ]; then
    reserved=$(jq -r .reservedRound "$scen/status-positive.json")
    for i in 1 2 3 4 5 6 7 8 9 10; do
      submitted_round "$reserved" && { ok=1; break; }
      sleep 1
    done
    [ "$ok" -eq 1 ] && pass "the authority's record holds round $reserved under session generation 1, and the node logged submitting a request for round $reserved" ||
      fail "the authority reserved round $reserved, for which the node logged no submission"
  else
    fail "unexpected authority status after the positive control: $(cat "$scen/status-positive.json")"
  fi
  if health positive && [ "$(jq -r .voting "$scen/health-positive.json")" = true ]; then
    pass "the node's health reports voting=true"
  else
    fail "health after the positive control: $(cat "$scen/health-positive.json" "$scen/health-positive.err" 2>/dev/null)"
  fi
}

# assert_abstains <refusal> <shard mark> <label>: the node abstains naming the refusal, signs and
# submits nothing, keeps following certificates, and the root chain certifies nothing it sent.
assert_abstains() {
  local refusal=$1 mark=$2 label=$3 log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" first rootMark n
  if ! wait_count "$log" "$mark" 1 60 "the certification request was not signed" "$refusal"; then
    fail "$label: the node did not abstain naming $refusal within 60s"
    return 1
  fi
  first=$(first_after "$log" "$mark" "the certification request was not signed" "$refusal")
  # Taken now: a consensus on a request sent before the first abstention is logged by the root
  # before the certificate that led to that abstention reached the node.
  rootMark=$(lines "$rootLog")
  wait_count "$log" "$first" 3 60 "the certification request was not signed" "$refusal"
  wait_count "$log" "$first" 3 60 "accepted certificate"
  n=$(count_after "$log" "$((first - 1))" "the certification request was not signed" "$refusal")
  [ "$n" -ge 4 ] && pass "$label: the node abstained on $n rounds, each naming $refusal (first at shard log line $first)" ||
    fail "$label: only $n abstentions naming $refusal after line $first"
  n=$(count_after "$log" "$mark" "the certification request was not signed")
  local named
  named=$(count_after "$log" "$mark" "the certification request was not signed" "$refusal")
  [ "$n" -eq "$named" ] && pass "$label: every signing refusal since the change names $refusal ($n)" ||
    fail "$label: $((n - named)) of $n signing refusals name something other than $refusal"
  n=$(count_after "$log" "$first" "submitting block certification request")
  [ "$n" -eq 0 ] && pass "$label: no certification request was submitted after the first abstention (no local fallback)" ||
    fail "$label: $n certification requests were submitted after the first abstention"
  n=$(count_after "$log" "$first" "accepted certificate")
  [ "$n" -ge 3 ] && pass "$label: the node kept following the shard, accepting $n certificates after the first abstention" ||
    fail "$label: the node accepted only $n certificates after the first abstention"
  n=$(count_after "$rootLog" "$rootMark" "reached consensus, new InputHash")
  [ "$n" -eq 0 ] && pass "$label: the root chain reached no consensus after the first abstention (root log after line $rootMark)" ||
    fail "$label: the root chain reached consensus $n times after the first abstention"
  n=$(count_after "$rootLog" "$rootControlMark" "invalid block certification request")
  [ "$n" -eq 0 ] && pass "$label: the root chain rejected no certification request as invalid after the control, so no request under another key reached it" ||
    fail "$label: the root chain rejected $n certification requests as invalid"
  if health "$label" && [ "$(jq -r .voting "$scen/health-$label.json")" = false ] &&
    jq -r .nonVotingReason "$scen/health-$label.json" | grep -q "$refusal"; then
    pass "$label: health reports voting=false: $(jq -r .nonVotingReason "$scen/health-$label.json")"
  else
    fail "$label: health does not report the abstention: $(cat "$scen/health-$label.json" 2>/dev/null)"
  fi
  alive "$(pid_of shard)" && pass "$label: the shard-node process is still running" || fail "$label: the shard-node process exited"
}

scenario_fencing() {
  setup_cluster || return 1
  start_authority_shard || return 1
  positive_control || return 1
  local mark authMark n
  mark=$(lines "$scen/shard/debug.log")
  authMark=$(lines "$scen/authority/authority.log")
  note "replacing the session; the node keeps the credential it loaded"
  # shellcheck disable=SC2046
  ubft signing-authority replace-session $(opargs) --out "$scen/authority/client.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "replace-session"; return 1; }
  authority_status fenced
  [ "$(jq -r '.generation == 2 and (.faulted | not) and (.keyLost | not)' "$scen/status-fenced.json")" = true ] &&
    pass "replace-session moved the authority to session generation 2 without a fault" ||
    fail "unexpected status after replace-session: $(cat "$scen/status-fenced.json")"
  assert_abstains signing-session-fenced "$mark" fenced || return 1
  n=$(count_after "$scen/authority/authority.log" "$authMark" "refusing an operation" "refusal=signing-session-fenced")
  [ "$n" -ge 1 ] && pass "fenced: the authority process logged $n refused client operations as signing-session-fenced" ||
    fail "fenced: the authority process logged no fenced refusal"
  authority_status fenced-after
  [ "$(jq -r '.generation == 2 and (.faulted | not)' "$scen/status-fenced-after.json")" = true ] &&
    pass "fenced: the authority remains at generation 2 and unfaulted after the refused operations" ||
    fail "fenced: unexpected status: $(cat "$scen/status-fenced-after.json")"
}

scenario_authority_loss() {
  setup_cluster || return 1
  start_authority_shard || return 1
  positive_control || return 1
  local mark out rc
  mark=$(lines "$scen/shard/debug.log")
  note "killing the authority process (SIGKILL)"
  stop_proc "$scen" authority 'ubft signing-authority run' KILL
  alive "$(cat "$scen/pids/authority.stopped")" && fail "the authority process is still alive" ||
    pass "the authority process $(cat "$scen/pids/authority.stopped") is gone"
  # shellcheck disable=SC2046
  out=$(ubft signing-authority status $(opargs) 2>&1)
  rc=$?
  [ "$rc" -ne 0 ] && echo "$out" | grep -q signing-authority-unavailable &&
    pass "the operator status command reports signing-authority-unavailable" ||
    fail "operator status after the loss: rc=$rc, $out"
  assert_abstains signing-authority-unavailable "$mark" loss || return 1
}

# assert_restored <mark> <root mark> <authority mark> <authority pid> <label>: what a restarted node
# and its authority must show, whichever check stops the vote.
assert_restored() {
  local mark=$1 rootMark=$2 authMark=$3 authorityPid=$4 label=$5 n
  local log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" authLog="$scen/authority/authority.log"
  wait_count "$log" "$mark" 4 120 "accepted certificate"
  n=$(count_after "$log" "$mark" "accepted certificate")
  [ "$n" -ge 4 ] && pass "$label: the restored node accepted $n certificates" || fail "$label: the restored node accepted only $n certificates"
  n=$(count_after "$log" "$mark" "submitting block certification request")
  [ "$n" -eq 0 ] && pass "$label: the restored node submitted no certification request (non-voting)" ||
    fail "$label: the restored node submitted $n certification requests"
  n=$(count_after "$log" "$mark" "the certification request was not signed")
  [ "$n" -eq 0 ] && pass "$label: the restored node never called the signer (no signing refusal logged)" ||
    fail "$label: the restored node logged $n signing refusals, so it called the signer"
  n=$(count_after "$rootLog" "$rootMark" "reached consensus, new InputHash")
  [ "$n" -eq 0 ] && pass "$label: the root chain reached no consensus after the restart" ||
    fail "$label: the root chain reached consensus $n times after the restart"
  authority_status "$label-after-restart" || { fail "$label: status after the restart"; return 1; }
  if [ "$(jq -S . "$scen/status-$label-after-stop.json")" = "$(jq -S . "$scen/status-$label-after-restart.json")" ]; then
    pass "$label: the authority status is identical before and after the restart (generation $(jq -r .generation "$scen/status-$label-after-restart.json"), reserved round $(jq -r .reservedRound "$scen/status-$label-after-restart.json"), retained $(jq -r .responseRetained "$scen/status-$label-after-restart.json"))"
  else
    fail "$label: the authority status changed across the restart: $(diff "$scen/status-$label-after-stop.json" "$scen/status-$label-after-restart.json")"
  fi
  [ "$(jq -r .shardConfHash "$scen/status-$label-after-restart.json")" = "$(jq -r .shardConfHash "$scen/status-enrolled.json")" ] &&
    pass "$label: the enrollment's configuration hash is unchanged" || fail "$label: the configuration hash changed"
  n=$(count_after "$authLog" "$authMark" "refusing an operation")
  [ "$n" -eq 0 ] && pass "$label: the authority process refused no operation after the restart" ||
    fail "$label: the authority process refused $n operations after the restart"
  [ "$(pid_of authority)" = "$authorityPid" ] && alive "$authorityPid" &&
    pass "$label: the same authority process (pid $authorityPid) ran throughout" || fail "$label: the authority process changed or exited"
}

scenario_restart() {
  setup_cluster || return 1
  start_authority_shard || return 1
  positive_control || return 1
  local log="$scen/shard/debug.log" authorityPid mark rootMark authMark n
  authorityPid=$(pid_of authority)
  note "stopping the shard node (SIGTERM)"
  stop_proc "$scen" shard 'ubft shard-node run' TERM
  authority_status restart-after-stop || { fail "status after stopping the shard node"; return 1; }
  if [ -s "$scen/shard/shard-node-luc.json" ]; then
    cp "$scen/shard/shard-node-luc.json" "$scen/checkpoint-at-restart.json"
    pass "the shard node retained a checkpoint ($(wc -c <"$scen/shard/shard-node-luc.json" | tr -d ' ') bytes)"
  else
    fail "the shard node left no checkpoint to restart from"
    return 1
  fi
  mark=$(lines "$log")
  rootMark=$(lines "$scen/root/debug.log")
  authMark=$(lines "$scen/authority/authority.log")
  note "starting the shard node again with the same flags and credential"
  start_shard
  if wait_count "$log" "$mark" 1 30 "resumed from persisted certificate"; then
    pass "restart: the node resumed from its checkpoint: $(line_after "$log" "$mark" "resumed from persisted certificate" | grep -o 'msg=.*' | sed 's/ go_id=.*//')"
  else
    fail "restart: the node did not resume from its checkpoint"
    return 1
  fi
  assert_restored "$mark" "$rootMark" "$authMark" "$authorityPid" restart
  # Which check stopped the vote, stated rather than assumed.
  n=$(count_after "$log" "$mark" "cannot prove" "no-anchor")
  [ "$n" -ge 1 ] && pass "restart: P-id refused first on $n rounds (no-anchor: the restarted process observed no certificate naming a block)" ||
    fail "restart: expected the P-id no-anchor refusal in this lane, found none"
  n=$(count_after "$log" "$mark" "will NOT vote until the monotonic signing record")
  [ "$n" -eq 0 ] && pass "restart: the restored gate was not reached in this scenario (see restart-at-anchor)" ||
    fail "restart: the restored gate was reached although P-id refused; this scenario's description is wrong"
  if health restored && [ "$(jq -r .voting "$scen/health-restored.json")" = false ] &&
    jq -r .nonVotingReason "$scen/health-restored.json" | grep -q "^restored from a persisted certificate"; then
    pass "restart: health reports voting=false: $(jq -r .nonVotingReason "$scen/health-restored.json")"
  else
    fail "restart: health does not report the restored state: $(cat "$scen/health-restored.json" 2>/dev/null)"
  fi
}

scenario_restart_at_anchor() {
  setup_cluster || return 1
  local log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" authorityPid mark rootMark authMark n i round resumed
  authorityPid=$(pid_of authority)
  # Watched from the moment the process starts: the first round is certified within about two
  # seconds of startup. Freeze once the first request has been sent AND the certificate it followed
  # has been saved (persistingDriver saves after the round handler, which sends): the checkpoint then
  # predates the certificate the root is about to issue for that request.
  start_shard
  i=0
  until [ "$(count_after "$log" 0 "submitting block certification request")" -ge 1 ] && [ -s "$scen/shard/shard-node-luc.json" ]; do
    if [ "$i" -ge 2400 ]; then
      fail "restart-at-anchor: no submission and checkpoint within 120s"
      return 1
    fi
    sleep 0.05
    i=$((i + 1))
  done
  signal_owned shard 'ubft shard-node run' STOP || { fail "restart-at-anchor: could not freeze the shard node"; return 1; }
  note "froze the shard node after its first submission"
  round=$(grep -o 'msg="submitting block certification request" round=[0-9]*' "$log" | head -1 | grep -o '[0-9]*$')
  n=$(count_after "$log" 0 "accepted certificate" "partitionRound=$round ")
  if [ "$n" -ne 0 ]; then
    fail "restart-at-anchor: the node had already accepted the certificate for round $round when it was frozen (race lost; rerun)"
    return 1
  fi
  pass "restart-at-anchor: the node was frozen after submitting round $round through the authority and before accepting its certificate"
  check_shard_started || return 1
  if wait_count "$rootLog" "$rootControlMark" 1 30 "reached consensus, new InputHash"; then
    pass "restart-at-anchor: the root chain reached consensus on the authority-signed request for round $round, whose certificate the frozen node had not accepted"
  else
    fail "restart-at-anchor: the root chain reached no consensus on round $round"
    return 1
  fi
  n=$(count_after "$rootLog" "$rootControlMark" "invalid block certification request")
  [ "$n" -eq 0 ] && pass "restart-at-anchor: the root chain rejected no certification request as invalid after the control" ||
    fail "restart-at-anchor: the root chain rejected $n requests as invalid"
  note "killing the frozen shard node (SIGKILL)"
  stop_proc "$scen" shard 'ubft shard-node run' KILL
  authority_status anchor-after-stop || { fail "status after stopping the shard node"; return 1; }
  if [ "$(jq -r --argjson r "$round" '.generation == 1 and .reservedRound == $r and .responseRetained and (.faulted | not)' "$scen/status-anchor-after-stop.json")" = true ]; then
    pass "restart-at-anchor: the authority's record holds round $round with its response retained, under generation 1"
  else
    fail "restart-at-anchor: unexpected status: $(cat "$scen/status-anchor-after-stop.json")"
  fi
  cp "$scen/shard/shard-node-luc.json" "$scen/checkpoint-at-restart.json"
  mark=$(lines "$log")
  rootMark=$(lines "$rootLog")
  authMark=$(lines "$scen/authority/authority.log")
  note "starting the shard node again with the same flags and credential"
  start_shard
  if ! wait_count "$log" "$mark" 1 30 "resumed from persisted certificate"; then
    fail "restart-at-anchor: the node did not resume from its checkpoint"
    return 1
  fi
  resumed=$(line_after "$log" "$mark" "resumed from persisted certificate" | grep -o ' round=[0-9]*' | grep -o '[0-9]*$')
  [ -n "$resumed" ] && [ "$resumed" -lt "$round" ] &&
    pass "restart-at-anchor: the node resumed from its checkpoint at round $resumed, older than the certified round $round" ||
    fail "restart-at-anchor: the node resumed at round '$resumed', not older than round $round"
  if wait_count "$log" "$mark" 1 60 "will NOT vote until the monotonic signing record"; then
    pass "restart-at-anchor: the restored gate withheld the vote: $(line_after "$log" "$mark" "will NOT vote until the monotonic signing record" | grep -o 'restoredFromRound=[0-9]* round=[0-9]*')"
  else
    fail "restart-at-anchor: the restored gate was not reached within 60s"
  fi
  n=$(count_after "$log" "$mark" "transition=installed")
  [ "$n" -ge 1 ] && pass "restart-at-anchor: the restarted process installed an anchor from the non-quiet certificate" ||
    fail "restart-at-anchor: the restarted process installed no anchor"
  assert_restored "$mark" "$rootMark" "$authMark" "$authorityPid" anchor
  n=$(count_after "$log" "$mark" "cannot prove")
  [ "$n" -eq 0 ] && pass "restart-at-anchor: P-id refused nothing after the restart, so the restored gate alone withheld the vote" ||
    fail "restart-at-anchor: P-id refused $n times after the restart"
  if health restored && [ "$(jq -r .voting "$scen/health-restored.json")" = false ] &&
    [ "$(jq -r .nonVotingReason "$scen/health-restored.json")" = "restored from a persisted certificate: non-voting until the monotonic signing contract (#105) exists" ]; then
    pass "restart-at-anchor: health reports voting=false with the restored reason alone: $(jq -r .nonVotingReason "$scen/health-restored.json")"
  else
    fail "restart-at-anchor: unexpected health: $(cat "$scen/health-restored.json" 2>/dev/null)"
  fi
}

echo "=== f6c-authority-acceptance: evidence in $runDir ==="
logcmd make build
if ! make build >"$runDir/build.log" 2>&1; then
  cat "$runDir/build.log"
  exit 1
fi

for scenario in "${scenarios[@]}"; do
  scen="$runDir/$scenario"
  mkdir -p "$scen"
  scenarioFailures=0
  rootControlMark=0
  echo
  echo "=== scenario: $scenario ==="
  case "$scenario" in
  fencing) scenario_fencing ;;
  authority-loss) scenario_authority_loss ;;
  restart) scenario_restart ;;
  restart-at-anchor) scenario_restart_at_anchor ;;
  esac
  [ $? -ne 0 ] && [ "$scenarioFailures" -eq 0 ] && fail "scenario $scenario stopped early"
  teardown_scenario "$scen"
  echo "scenario $scenario: $scenarioFailures failed assertions" | tee -a "$scen/summary.txt"
  reached="$scenario"
done
reached="all scenarios"
