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
#                      and started again from its retained checkpoint. It is non-voting and submits
#                      nothing. In this lane the P-id check refuses first (no-anchor: the fake
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
# OBSERVATIONS FAIL CLOSED. A log that is missing, unreadable, or shorter than the mark a window was
# measured from is a failed observation, never a count of zero, and a negative assertion ("nothing
# happened after line N") also requires the window to contain at least one line. Failing to write
# evidence (the run directory, pid files, the command log, the manifest, the digests, the list of
# removed secrets) fails the run's verdict, and a scenario that stops early fails it too. The exit
# status and the final RESULT line are the verdict. `--self-test` exercises these failure paths with
# the real functions and no processes.
#
# Usage: scripts/f6c-authority-acceptance.sh [-s scenario]... [-o evidence-dir]
#        scripts/f6c-authority-acceptance.sh --self-test
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
# The owner's test floor is 5000ms. Production T2 must be sized well above normal round timing.
t2Millis=5000
rootP2PPort=36662
rootRPCPort=36866
shardP2PPort=36111
shardRPCPort=36311
# How long a negative window may take to acquire its first line. Every log it is used on is written
# continuously while the cluster runs.
windowTimeout=60

scenarios=()
runDir=""
failures=0
artifactErrors=0
abortedScenarios=()
scenarioFailures=0
scenario=""
scen=""
socketDirs=()
reached="startup"
rootControlMark=0
startedAt=""
invocation=""

stamp() { date -u +%H:%M:%S; }

# artifact_error records a failure to write evidence. It fails the verdict.
artifact_error() {
  echo "  EVIDENCE WRITE FAILURE: $*" >&2
  artifactErrors=$((artifactErrors + 1))
}

note() { echo "$(stamp) [$scenario] $*" | tee -a "$runDir/run.log" || artifact_error "run.log (note)"; }
pass() {
  echo "  PASS: $1" | tee -a "$runDir/run.log" || artifact_error "run.log (pass)"
  if [ -n "$scen" ]; then echo "PASS: $1" >>"$scen/summary.txt" || artifact_error "$scen/summary.txt"; fi
  return 0
}
fail() {
  echo "  FAIL: $1" | tee -a "$runDir/run.log" >&2 || artifact_error "run.log (fail)"
  if [ -n "$scen" ]; then echo "FAIL: $1" >>"$scen/summary.txt" || artifact_error "$scen/summary.txt"; fi
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
  } >>"$runDir/commands.log" || { artifact_error "commands.log"; return 1; }
}
ubft() {
  # A counter changed inside $(ubft ...) is lost; return the failure to the caller instead.
  logcmd build/ubft "$@" || return 1
  build/ubft "$@"
}

# --- observations ---------------------------------------------------------------------------------
#
# Each returns 2, and prints nothing on stdout, when it could not observe: the file is missing or
# unreadable, the mark is not a number, or the file is shorter than the mark (a truncated log must not
# look like an empty suffix). A caller must treat 2 as a failure of the assertion it was making.

readable() { [ -f "$1" ] && [ -r "$1" ]; }
is_count() { case "$1" in '' | *[!0-9]*) return 1 ;; esac; }

# lines <file> prints the number of lines.
lines() {
  local n
  readable "$1" || { echo "lines: cannot read $1" >&2; return 2; }
  n=$(wc -l <"$1") || return 2
  n=$(echo $n)
  is_count "$n" || return 2
  echo "$n"
}

# count_after <file> <after line> <substring> [second substring]
count_after() {
  local file=$1 after=$2 out
  readable "$file" || { echo "count_after: cannot read $file" >&2; return 2; }
  is_count "$after" || { echo "count_after: malformed mark '$after' for $file" >&2; return 2; }
  out=$(awk -v n="$after" -v p="$3" -v q="${4:-}" '
    NR > n && index($0, p) && (q == "" || index($0, q)) {c++}
    END {if (NR < n) exit 3; print c + 0}' "$file") || {
    echo "count_after: $file could not be read to line $after (missing, unreadable or truncated)" >&2
    return 2
  }
  is_count "$out" || return 2
  echo "$out"
}

# first_after <file> <after line> <substring> [second substring] prints the first matching line
# number; returns 1 when there is none.
first_after() {
  local file=$1 after=$2 out
  readable "$file" || return 2
  is_count "$after" || return 2
  out=$(awk -v n="$after" -v p="$3" -v q="${4:-}" '
    NR > n && index($0, p) && (q == "" || index($0, q)) && !found {found = NR}
    END {if (NR < n) exit 3; if (found) print found}' "$file") || return 2
  [ -n "$out" ] || return 1
  echo "$out"
}

# line_after <file> <after line> <substring> prints the first matching line; returns 1 when there is none.
line_after() {
  local file=$1 after=$2 out
  readable "$file" || return 2
  is_count "$after" || return 2
  out=$(awk -v n="$after" -v p="$3" '
    NR > n && index($0, p) && !done {line = $0; done = 1}
    END {if (NR < n) exit 3; if (done) print line}' "$file") || return 2
  [ -n "$out" ] || return 1
  echo "$out"
}

# wait_count <file> <after line> <n> <timeout seconds> <substring> [second substring]: 0 when reached,
# 1 on timeout, 2 (after recording a failure) when the file could not be observed.
wait_count() {
  local file=$1 after=$2 want=$3 timeout=$4 waited=0 n
  shift 4
  while :; do
    if ! n=$(count_after "$file" "$after" "$@"); then
      fail "could not observe $file after line $after while waiting for '$1'"
      return 2
    fi
    [ "$n" -ge "$want" ] && return 0
    [ "$waited" -ge "$timeout" ] && return 1
    sleep 1
    waited=$((waited + 1))
  done
}

# take_mark <file>: prints the current line count, recording a failure when it cannot.
take_mark() {
  local m
  if ! m=$(lines "$1"); then
    fail "could not take a mark on $1"
    return 2
  fi
  echo "$m"
}

# assert_count <eq|ge> <want> <message> <file> <after> <substring> [second substring]
# 0 pass, 1 counted mismatch, 2 not observed. Both 1 and 2 record a failure.
assert_count() {
  local op=$1 want=$2 msg=$3 file=$4 after=$5 n
  shift 3
  if ! n=$(count_after "$@"); then
    fail "$msg: could not observe $file after line $after (missing, unreadable, or shorter than the mark)"
    return 2
  fi
  if [ "$n" "-$op" "$want" ]; then
    pass "$msg (observed $n)"
    return 0
  fi
  fail "$msg (observed $n, expected $op $want)"
  return 1
}

# assert_none <message> <file> <after> <substring> [second substring]: zero matches in a window that
# holds at least one line. The window is given windowTimeout seconds to acquire one.
assert_none() {
  local msg=$1 file=$2 after=$3 total waited=0
  while :; do
    if ! total=$(lines "$file"); then
      fail "$msg: $file could not be observed"
      return 2
    fi
    [ "$total" -gt "$after" ] && break
    if [ "$waited" -ge "$windowTimeout" ]; then
      fail "$msg: the window after line $after of $file holds no line ($total lines), so nothing was observed"
      return 2
    fi
    sleep 1
    waited=$((waited + 1))
  done
  assert_count eq 0 "$msg" "$file" "$after" "${@:4}"
}

# json_true <file> <jq expression>
json_true() { [ "$(jq -r "$2" "$1" 2>/dev/null)" = true ]; }

# conf_t2_ok <shard conf>: the configuration's T2 (t2timeout, in nanoseconds) equals t2Millis and is at
# least the 5000ms floor. An unreadable configuration or a missing field is not OK.
conf_t2_ok() {
  local ns
  ns=$(jq -r .t2timeout "$1" 2>/dev/null) || return 1
  is_count "$ns" || return 1
  [ "$ns" -eq $((t2Millis * 1000000)) ] && [ "$ns" -ge 5000000000 ]
}

# json_same <a> <b>: both parse to the same non-empty value. Two unreadable files are not equal.
json_same() {
  local x y
  x=$(jq -S . "$1" 2>/dev/null) && y=$(jq -S . "$2" 2>/dev/null) && [ -n "$x" ] && [ "$x" = "$y" ]
}

# --- processes ------------------------------------------------------------------------------------

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
# records its pid under the scenario and its command line in processes.txt. A process whose pid could
# not be recorded is stopped at once, because cleanup could not find it.
start_bg() {
  local name=$1 log=$2 pid
  shift 2
  : >>"$log" || { artifact_error "could not create $log"; return 1; }
  logcmd build/ubft "$@"
  build/ubft "$@" >>"$log" 2>&1 </dev/null &
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

pid_of() { cat "$scen/pids/$1" 2>/dev/null; }

# signal_owned <name> <pattern> <signal> signals a recorded process of this scenario only if it is
# this checkout's.
signal_owned() {
  local pid
  pid=$(pid_of "$1")
  if alive "$pid" && owned_pid "$pid" "$2"; then
    kill "-$3" "$pid" || return 1
    echo "$(stamp) sent SIG$3 to $1 pid $pid" >>"$scen/processes.txt" || artifact_error "$scen/processes.txt"
    return 0
  fi
  echo "$(stamp) did not send SIG$3 to $1 pid $pid: not alive, or not a '$2' of this checkout" >>"$scen/processes.txt" ||
    artifact_error "$scen/processes.txt"
  return 1
}

# stop_proc <scenario dir> <name> <command pattern> [signal] stops a recorded process of this run
# only if it is this checkout's (owned_pid), waits at most 20 seconds, and reaps it. SIGCONT follows
# the signal so that a frozen process receives it.
stop_proc() {
  local dir=$1 name=$2 pattern=$3 sig=${4:-TERM} pidfile pid waited=0 record
  pidfile="$dir/pids/$name"
  [ -f "$pidfile" ] || return 0
  pid=$(cat "$pidfile") || { artifact_error "could not read $pidfile"; return 1; }
  if alive "$pid" && owned_pid "$pid" "$pattern"; then
    kill "-$sig" "$pid" 2>/dev/null
    kill -CONT "$pid" 2>/dev/null
    while alive "$pid"; do
      [ "$waited" -eq 15 ] && kill -KILL "$pid" 2>/dev/null
      [ "$waited" -ge 20 ] && break
      sleep 1
      waited=$((waited + 1))
    done
    if alive "$pid"; then
      record="$(stamp) $name pid $pid did not exit after SIG$sig and SIGKILL"
      fail "$record"
    else
      record="$(stamp) stopped $name pid $pid with SIG$sig after ${waited}s"
    fi
  else
    record="$(stamp) $name pid $pid was not signalled: not alive, or not a '$pattern' of this checkout"
  fi
  echo "$record" >>"$dir/processes.txt" || artifact_error "$dir/processes.txt"
  wait "$pid" 2>/dev/null
  mv "$pidfile" "$pidfile.stopped" || artifact_error "could not mark $pidfile stopped"
  return 0
}

teardown_scenario() {
  local dir=$1
  stop_proc "$dir" shard 'ubft shard-node run'
  stop_proc "$dir" local-control 'ubft shard-node run'
  stop_proc "$dir" authority 'ubft signing-authority run'
  stop_proc "$dir" root 'ubft root-node run'
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

# --- evidence and verdict ---------------------------------------------------------------------------

# prepare_run_dir creates a new, empty evidence directory and resolves runDir to its absolute path.
prepare_run_dir() {
  if [ -e "$runDir" ]; then
    echo "evidence directory already exists: $runDir" >&2
    return 1
  fi
  mkdir -p "$runDir" || return 1
  runDir=$(cd "$runDir" && pwd -P) || return 1
  { : >"$runDir/run.log" && : >"$runDir/commands.log"; } || return 1
}

write_manifest() {
  {
    echo "f6c signing authority process acceptance run"
    echo "started:          $startedAt"
    echo "finished:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "reached:          $reached"
    echo "failed asserts:   $failures (at the time this manifest was written)"
    echo "evidence writes:  $artifactErrors failures before this manifest"
    echo "stopped early:    ${abortedScenarios[*]+${abortedScenarios[*]}}"
    echo "verdict:          the exit status and RESULT line, which also count failures to write this manifest and the digests"
    echo "invocation:       $invocation"
    echo "scenarios:        ${scenarios[*]+${scenarios[*]}}"
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
}

# write_digests hashes every evidence file, the manifest included, into sha256sums.txt.
write_digests() {
  local out
  out=$(cd "$runDir" && find . -type f ! -name sha256sums.txt -print0 | sort -z | xargs -0 shasum -a 256) || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" >"$runDir/sha256sums.txt"
}

# remove_secrets deletes credentials and key configurations and lists what it deleted. A secret it
# could not delete, or could not list, is an evidence failure.
remove_secrets() {
  local found f
  : >"$runDir/removed-secrets.txt" || { artifact_error "removed-secrets.txt"; return 1; }
  found=$(find "$runDir" \( -name '*.cred' -o -name 'keys.json' \) -type f) || {
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
  local rc=$? d reasons=""
  trap - EXIT INT TERM
  for d in "$runDir"/*/; do
    [ -d "$d/pids" ] && teardown_scenario "${d%/}"
  done
  for d in ${socketDirs[@]+"${socketDirs[@]}"}; do
    rm -rf "$d" || artifact_error "could not remove socket directory $d"
  done
  remove_secrets
  write_manifest || artifact_error "could not write $runDir/manifest.txt"
  write_digests || artifact_error "could not write $runDir/sha256sums.txt"
  echo
  echo "evidence: $runDir"
  [ "$failures" -gt 0 ] && reasons="$reasons $failures failed assertions;"
  [ "$artifactErrors" -gt 0 ] && reasons="$reasons $artifactErrors evidence write failures;"
  [ ${#abortedScenarios[@]} -gt 0 ] && reasons="$reasons stopped early: ${abortedScenarios[*]};"
  [ "$reached" != "all scenarios" ] && reasons="$reasons reached: $reached;"
  if [ -n "$reasons" ]; then
    echo "RESULT: FAIL ($reasons )"
    [ "$rc" -eq 0 ] && rc=1
  else
    echo "RESULT: PASS"
  fi
  exit "$rc"
}

# --- the cluster ----------------------------------------------------------------------------------

opargs() { echo --home "$scen/authority" --operator-socket "$sockDir/operator.sock" --operator-credential "$scen/authority/operator.cred"; }

authority_status() { # <name>: writes status-<name>.json, fails if the authority does not answer
  # shellcheck disable=SC2046
  ubft signing-authority status $(opargs) >"$scen/status-$1.json" 2>"$scen/status-$1.err"
}

health() { # <name>
  curl -fsS "http://127.0.0.1:$shardRPCPort/api/v1/health" >"$scen/health-$1.json" 2>"$scen/health-$1.err"
}

submitted_round() { # <round>: the shard log has a submission for this round
  readable "$scen/shard/debug.log" && grep -q "msg=\"submitting block certification request\" round=$1 " "$scen/shard/debug.log"
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
  local p out rc rootLog="$scen/root/debug.log" controlLog="$scen/control/shard-local.log" line
  for p in $rootP2PPort $rootRPCPort $shardP2PPort $shardRPCPort; do
    if port_listening "$p"; then
      fail "port $p is already in use by another process; this run does not stop processes it did not start"
      return 1
    fi
  done
  sockDir=$(mktemp -d /tmp/f6c-sa.XXXXXX) || { fail "could not create a socket directory"; return 1; }
  socketDirs+=("$sockDir")
  mkdir -p "$scen/authority" "$scen/control" "$scen/root" "$scen/shard" && chmod 700 "$scen/authority" ||
    { artifact_error "could not create the scenario directories"; return 1; }

  ubft root-node init --home "$scen/root" -g >>"$scen/setup.log" 2>&1 || { fail "root-node init"; return 1; }
  ubft trust-base generate --home "$scen" --epoch 1 --epoch-start 1 --network-id "$networkID" \
    --node-info "$scen/root/node-info.json" >>"$scen/setup.log" 2>&1 || { fail "trust-base generate"; return 1; }
  ubft trust-base sign --home "$scen/root" --trust-base "$scen/trust-base.json" >>"$scen/setup.log" 2>&1 || { fail "trust-base sign"; return 1; }
  ubft shard-node init --home "$scen/shard" -g >>"$scen/setup.log" 2>&1 || { fail "shard-node init"; return 1; }
  nodeID=$(ubft node-id --home "$scen/shard" | tail -n1) ||
    { fail "could not record or read the shard node identity"; return 1; }
  localSigKey=$(jq -r .sigKey "$scen/shard/node-info.json" | sed 's/^0x//')
  [ -n "$nodeID" ] && [ -n "$localSigKey" ] || { fail "could not read the shard node's identity"; return 1; }

  ubft signing-authority credential --home "$scen/authority" --out "$scen/authority/operator.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "signing-authority credential"; return 1; }
  start_bg authority "$scen/authority/authority.log" signing-authority run --home "$scen/authority" \
    --client-socket "$sockDir/client.sock" --operator-socket "$sockDir/operator.sock" \
    --operator-credential "$scen/authority/operator.cred" --authority-id "f6c-acceptance-$scenario" \
    --node-id "$nodeID" --network-id "$networkID" --partition-id "$partitionID" --shard-id 0x80 \
    --shard-epoch 0 --root-epoch 1 --trust-base "$scen/trust-base.json" --log-format text --log-level debug ||
    { fail "could not start the authority process"; return 1; }
  if ! wait_count "$scen/authority/authority.log" 0 1 20 "signing authority running"; then
    fail "the authority process did not start: $(tail -3 "$scen/authority/authority.log" 2>/dev/null)"
    return 1
  fi
  authorityKey=$(sed -n 's/.* signingKey=\([0-9a-f]*\).*/\1/p' "$scen/authority/authority.log" | head -1)
  authorityFingerprint=$(sed -n 's/.* signingKeyFingerprint=\([0-9a-f]*\).*/\1/p' "$scen/authority/authority.log" | head -1)
  [ -n "$authorityKey" ] && [ -n "$authorityFingerprint" ] || { fail "could not read the authority's key from its log"; return 1; }

  authority_status pending || { fail "status of the pending authority: $(cat "$scen/status-pending.err" 2>/dev/null)"; return 1; }
  if json_true "$scen/status-pending.json" '.enrollmentComplete == false'; then
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
  if conf_t2_ok "$scen/shard-conf-${partitionID}_0.json"; then
    pass "the shard configuration's T2 is ${t2Millis}ms, at least the 5000ms floor for test lanes"
  else
    fail "the shard configuration's T2 is not ${t2Millis}ms at or above the 5000ms floor: t2timeout=$(jq -c .t2timeout "$scen/shard-conf-${partitionID}_0.json" 2>/dev/null)"
    return 1
  fi
  confSigKey=$(jq -r --arg id "$nodeID" '.validators[] | select(.nodeId == $id) | .sigKey' "$scen/shard-conf-${partitionID}_0.json" | sed 's/^0x//')
  local confFingerprint
  confFingerprint=$(printf '%s' "$confSigKey" | xxd -r -p | shasum -a 256 | cut -d' ' -f1)
  if [ -n "$confSigKey" ] && [ "$confSigKey" = "$authorityKey" ] && [ "$confSigKey" != "$localSigKey" ] &&
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
  if json_true "$scen/status-enrolled.json" '.enrollmentComplete and .generation == 1 and (.faulted | not) and (.keyLost | not)'; then
    pass "complete-enrollment and replace-session succeed: enrolled, session generation 1"
  else
    fail "unexpected status after enrollment: $(cat "$scen/status-enrolled.json" 2>/dev/null)"
  fi

  start_bg root "$rootLog" root-node run --home "$scen/root" --address "/ip4/127.0.0.1/tcp/$rootP2PPort" \
    --trust-base "$scen/trust-base.json" --rpc-server-address "127.0.0.1:$rootRPCPort" --log-format text --log-level debug ||
    { fail "could not start the root node"; return 1; }
  local waited=0
  until port_listening "$rootRPCPort"; do
    if ! alive "$(pid_of root)" || [ "$waited" -ge 30 ]; then
      fail "the root node did not start: $(tail -3 "$rootLog" 2>/dev/null)"
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  logcmd curl -X PUT -H "Content-Type: application/json" -d "@$scen/shard-conf-${partitionID}_0.json" "http://127.0.0.1:$rootRPCPort/api/v1/configurations"
  curl -fsS -X PUT -H "Content-Type: application/json" -d "@$scen/shard-conf-${partitionID}_0.json" \
    "http://127.0.0.1:$rootRPCPort/api/v1/configurations" >>"$scen/setup.log" 2>&1 || { fail "registering the shard configuration"; return 1; }
  rootBoot="/ip4/127.0.0.1/tcp/$rootP2PPort/p2p/$(ubft node-id --home "$scen/root" | tail -n1)" ||
    { fail "could not record or read the root node identity"; return 1; }
  sleep 5 # wait_for_root_chain_settle in helper.sh explains this

  # Control against the root verifier: the same node, started without the authority flags, signs
  # with the key configuration's key. Its own checkpoint file keeps it from touching the checkpoint
  # the authority-backed node uses.
  start_bg local-control "$controlLog" shard-node run --home "$scen/shard" --executor fake \
    --address "/ip4/127.0.0.1/tcp/$shardP2PPort" --bootnodes "$rootBoot" \
    --trust-base "$scen/trust-base.json" --shard-conf "$scen/shard-conf-${partitionID}_0.json" \
    --luc-store "$scen/control/local-luc.json" --log-format text --log-level debug ||
    { fail "could not start the local-key control node"; return 1; }
  wait_count "$rootLog" 0 1 90 "invalid block certification request" "signature verification"
  case $? in
  0)
    line=$(line_after "$rootLog" 0 "invalid block certification request")
    pass "control: the same node signing with its local key has its request rejected by the root chain: $(echo "$line" | grep -o 'invalid block certification request[^"]*' | cut -c1-160)"
    ;;
  1) fail "control: the root chain did not reject the local-key request within 90s" ;;
  *) return 1 ;;
  esac
  if assert_count ge 1 "control: the control node reported signing with the local key" "$controlLog" 0 'certificationSigning="local key"'; [ $? -eq 2 ]; then return 1; fi
  if assert_none "control: the root chain reached no consensus during the local-key control" "$rootLog" 0 "reached consensus, new InputHash"; [ $? -eq 2 ]; then return 1; fi
  stop_proc "$scen" local-control 'ubft shard-node run'
  wait_port_free "$shardP2PPort" 20 || { fail "the control node's port $shardP2PPort was not released"; return 1; }
  rootControlMark=$(take_mark "$rootLog") || return 1
  return 0
}

start_authority_shard() {
  start_shard || { fail "could not start the shard node"; return 1; }
  sleep 2
  check_shard_started
}

# check_shard_started: the authority-backed node is running and pinned the configured key.
check_shard_started() {
  if ! alive "$(pid_of shard)"; then
    fail "shard-node run exited at startup: $(tail -5 "$scen/shard/debug.log" 2>/dev/null)"
    return 1
  fi
  if assert_count ge 1 "shard-node run started with the authority signer pinned to fingerprint $authorityFingerprint" \
    "$scen/shard/debug.log" 0 "certificationSigning=\"signing authority at $sockDir/client.sock, key fingerprint $authorityFingerprint\""; [ $? -eq 2 ]; then
    return 1
  fi
  ps -o pid,ppid,stat,command -p "$(pid_of root),$(pid_of authority),$(pid_of shard)" >"$scen/process-table.txt" ||
    artifact_error "$scen/process-table.txt"
  return 0
}

# positive_control: the running node's requests are signed by the authority and certified.
positive_control() {
  local log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" reserved i ok=0
  wait_count "$log" 0 3 120 "submitting block certification request"
  case $? in 1) fail "the node did not submit three certification requests within 120s"; return 1 ;; 2) return 1 ;; esac
  if assert_count ge 3 "the node signed and submitted certification requests through the authority" "$log" 0 "submitting block certification request"; [ $? -eq 2 ]; then return 1; fi
  wait_count "$rootLog" "$rootControlMark" 3 30 "reached consensus, new InputHash"
  [ $? -eq 2 ] && return 1
  if assert_count ge 3 "the root chain reached consensus on the only validator's requests" "$rootLog" "$rootControlMark" "reached consensus, new InputHash"; [ $? -eq 2 ]; then return 1; fi
  wait_count "$log" 0 3 30 "accepted certificate" "class=valid"
  [ $? -eq 2 ] && return 1
  if assert_count ge 3 "the node accepted valid certificates" "$log" 0 "accepted certificate" "class=valid"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "the root chain rejected no certification request as invalid after the control" "$rootLog" "$rootControlMark" "invalid block certification request"; [ $? -eq 2 ]; then return 1; fi
  authority_status positive || fail "status after the positive control"
  if json_true "$scen/status-positive.json" '.generation == 1 and .hasReservation and .reservedRound > 0 and (.faulted | not)'; then
    reserved=$(jq -r .reservedRound "$scen/status-positive.json")
    for i in 1 2 3 4 5 6 7 8 9 10; do
      submitted_round "$reserved" && { ok=1; break; }
      sleep 1
    done
    if [ "$ok" -eq 1 ]; then
      pass "the authority's record holds round $reserved under session generation 1, and the node logged submitting a request for round $reserved"
    else
      fail "the authority reserved round $reserved, for which the node's log shows no submission"
    fi
  else
    fail "unexpected authority status after the positive control: $(cat "$scen/status-positive.json" 2>/dev/null)"
  fi
  if health positive && json_true "$scen/health-positive.json" '.voting == true'; then
    pass "the node's health reports voting=true"
  else
    fail "health after the positive control: $(cat "$scen/health-positive.json" "$scen/health-positive.err" 2>/dev/null)"
  fi
  return 0
}

# assert_abstains <refusal> <shard mark> <label>: the node abstains naming the refusal, signs and
# submits nothing, keeps following certificates, and the root chain certifies nothing it sent.
assert_abstains() {
  local refusal=$1 mark=$2 label=$3 log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" first rootMark all named
  wait_count "$log" "$mark" 1 60 "the certification request was not signed" "$refusal"
  case $? in 1) fail "$label: the node did not abstain naming $refusal within 60s"; return 1 ;; 2) return 1 ;; esac
  first=$(first_after "$log" "$mark" "the certification request was not signed" "$refusal") ||
    { fail "$label: could not locate the first abstention in $log"; return 1; }
  # Taken now: a consensus on a request sent before the first abstention is logged by the root
  # before the certificate that led to that abstention reached the node.
  rootMark=$(take_mark "$rootLog") || return 1
  wait_count "$log" "$first" 3 60 "the certification request was not signed" "$refusal"
  [ $? -eq 2 ] && return 1
  wait_count "$log" "$first" 3 60 "accepted certificate"
  [ $? -eq 2 ] && return 1
  if assert_count ge 4 "$label: the node abstained naming $refusal on every round from shard log line $first" "$log" "$((first - 1))" "the certification request was not signed" "$refusal"; [ $? -eq 2 ]; then return 1; fi
  all=$(count_after "$log" "$mark" "the certification request was not signed") &&
    named=$(count_after "$log" "$mark" "the certification request was not signed" "$refusal") ||
    { fail "$label: could not observe the signing refusals in $log"; return 1; }
  if [ "$all" -eq "$named" ]; then
    pass "$label: every signing refusal since the change names $refusal ($all)"
  else
    fail "$label: $((all - named)) of $all signing refusals name something other than $refusal"
  fi
  if assert_none "$label: no certification request was submitted after the first abstention (no local fallback)" "$log" "$first" "submitting block certification request"; [ $? -eq 2 ]; then return 1; fi
  if assert_count ge 3 "$label: the node kept following the shard, accepting certificates after the first abstention" "$log" "$first" "accepted certificate"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the root chain reached no consensus after the first abstention (root log after line $rootMark)" "$rootLog" "$rootMark" "reached consensus, new InputHash"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the root chain rejected no certification request as invalid after the control, so no request under another key reached it" "$rootLog" "$rootControlMark" "invalid block certification request"; [ $? -eq 2 ]; then return 1; fi
  if health "$label" && json_true "$scen/health-$label.json" '.voting == false' &&
    jq -r .nonVotingReason "$scen/health-$label.json" 2>/dev/null | grep -q "$refusal"; then
    pass "$label: health reports voting=false: $(jq -r .nonVotingReason "$scen/health-$label.json")"
  else
    fail "$label: health does not report the abstention: $(cat "$scen/health-$label.json" 2>/dev/null)"
  fi
  if alive "$(pid_of shard)"; then pass "$label: the shard-node process is still running"; else fail "$label: the shard-node process exited"; fi
  return 0
}

scenario_fencing() {
  setup_cluster || return 1
  start_authority_shard || return 1
  positive_control || return 1
  local mark authMark
  mark=$(take_mark "$scen/shard/debug.log") || return 1
  authMark=$(take_mark "$scen/authority/authority.log") || return 1
  note "replacing the session; the node keeps the credential it loaded"
  # shellcheck disable=SC2046
  ubft signing-authority replace-session $(opargs) --out "$scen/authority/client.cred" >>"$scen/setup.log" 2>&1 ||
    { fail "replace-session"; return 1; }
  authority_status fenced
  if json_true "$scen/status-fenced.json" '.generation == 2 and (.faulted | not) and (.keyLost | not)'; then
    pass "replace-session moved the authority to session generation 2 without a fault"
  else
    fail "unexpected status after replace-session: $(cat "$scen/status-fenced.json" 2>/dev/null)"
  fi
  assert_abstains signing-session-fenced "$mark" fenced || return 1
  if assert_count ge 1 "fenced: the authority process logged refused client operations as signing-session-fenced" "$scen/authority/authority.log" "$authMark" "refusing an operation" "refusal=signing-session-fenced"; [ $? -eq 2 ]; then return 1; fi
  authority_status fenced-after
  if json_true "$scen/status-fenced-after.json" '.generation == 2 and (.faulted | not)'; then
    pass "fenced: the authority remains at generation 2 and unfaulted after the refused operations"
  else
    fail "fenced: unexpected status: $(cat "$scen/status-fenced-after.json" 2>/dev/null)"
  fi
  return 0
}

scenario_authority_loss() {
  setup_cluster || return 1
  start_authority_shard || return 1
  positive_control || return 1
  local mark out rc gone
  mark=$(take_mark "$scen/shard/debug.log") || return 1
  note "killing the authority process (SIGKILL)"
  stop_proc "$scen" authority 'ubft signing-authority run' KILL
  gone=$(cat "$scen/pids/authority.stopped" 2>/dev/null)
  if [ -n "$gone" ] && ! alive "$gone"; then
    pass "the authority process $gone is gone"
  else
    fail "the authority process '$gone' is still alive or was not recorded"
  fi
  # shellcheck disable=SC2046
  out=$(ubft signing-authority status $(opargs) 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ] && echo "$out" | grep -q signing-authority-unavailable; then
    pass "the operator status command reports signing-authority-unavailable"
  else
    fail "operator status after the loss: rc=$rc, $out"
  fi
  assert_abstains signing-authority-unavailable "$mark" loss || return 1
  return 0
}

# assert_restored <mark> <root mark> <authority mark> <authority pid> <label>: what a restarted node
# and its authority must show, whichever check stops the vote.
#
# What is measured is the node's log (no submission, no signing refusal) and the authority's status
# (unchanged). That the signer was not called at all is an inference from the code path (P-id and the
# restored gate both return before CertificationSigner.Sign), not an observation: a successful
# identical retry would also leave both unchanged.
assert_restored() {
  local mark=$1 rootMark=$2 authMark=$3 authorityPid=$4 label=$5
  local log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" authLog="$scen/authority/authority.log"
  wait_count "$log" "$mark" 4 120 "accepted certificate"
  [ $? -eq 2 ] && return 1
  if assert_count ge 4 "$label: the restored node accepted certificates" "$log" "$mark" "accepted certificate"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the restored node submitted no certification request (non-voting)" "$log" "$mark" "submitting block certification request"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the restored node logged no signing refusal" "$log" "$mark" "the certification request was not signed"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "$label: the root chain reached no consensus after the restart" "$rootLog" "$rootMark" "reached consensus, new InputHash"; [ $? -eq 2 ]; then return 1; fi
  authority_status "$label-after-restart" || { fail "$label: the authority did not answer status after the restart"; return 1; }
  if json_same "$scen/status-$label-after-stop.json" "$scen/status-$label-after-restart.json"; then
    pass "$label: the authority status is identical before and after the restart (generation $(jq -r .generation "$scen/status-$label-after-restart.json"), reserved round $(jq -r .reservedRound "$scen/status-$label-after-restart.json"), retained $(jq -r .responseRetained "$scen/status-$label-after-restart.json"))"
  else
    fail "$label: the authority status before and after the restart is not the same readable value"
  fi
  local before after
  before=$(jq -r .shardConfHash "$scen/status-enrolled.json" 2>/dev/null)
  after=$(jq -r .shardConfHash "$scen/status-$label-after-restart.json" 2>/dev/null)
  if [ -n "$before" ] && [ "$before" != null ] && [ "$before" = "$after" ]; then
    pass "$label: the enrollment's configuration hash is unchanged"
  else
    fail "$label: the configuration hash is unreadable or changed ('$before' then '$after')"
  fi
  # The authority logs nothing for an operation it accepts, so this window may legitimately be
  # empty; only a missing or truncated log is a failed observation here.
  if assert_count eq 0 "$label: the authority process refused no operation after the restart" "$authLog" "$authMark" "refusing an operation"; [ $? -eq 2 ]; then return 1; fi
  if [ "$(pid_of authority)" = "$authorityPid" ] && alive "$authorityPid"; then
    pass "$label: the same authority process (pid $authorityPid) ran throughout"
  else
    fail "$label: the authority process changed or exited"
  fi
  return 0
}

scenario_restart() {
  setup_cluster || return 1
  start_authority_shard || return 1
  positive_control || return 1
  local log="$scen/shard/debug.log" authorityPid mark rootMark authMark line
  authorityPid=$(pid_of authority)
  note "stopping the shard node (SIGTERM)"
  stop_proc "$scen" shard 'ubft shard-node run' TERM
  authority_status restart-after-stop || { fail "status after stopping the shard node"; return 1; }
  if [ -s "$scen/shard/shard-node-luc.json" ] && cp "$scen/shard/shard-node-luc.json" "$scen/checkpoint-at-restart.json"; then
    pass "the shard node retained a checkpoint ($(wc -c <"$scen/shard/shard-node-luc.json" | tr -d ' ') bytes)"
  else
    fail "the shard node left no checkpoint to restart from, or it could not be preserved"
    return 1
  fi
  mark=$(take_mark "$log") || return 1
  rootMark=$(take_mark "$scen/root/debug.log") || return 1
  authMark=$(take_mark "$scen/authority/authority.log") || return 1
  note "starting the shard node again with the same flags and credential"
  start_shard || { fail "could not restart the shard node"; return 1; }
  wait_count "$log" "$mark" 1 30 "resumed from persisted certificate"
  case $? in 1) fail "restart: the node did not resume from its checkpoint"; return 1 ;; 2) return 1 ;; esac
  line=$(line_after "$log" "$mark" "resumed from persisted certificate") || { fail "restart: could not read the resume line"; return 1; }
  pass "restart: the node resumed from its checkpoint: $(echo "$line" | grep -o 'msg=.*' | sed 's/ go_id=.*//')"
  assert_restored "$mark" "$rootMark" "$authMark" "$authorityPid" restart || return 1
  # Which check stopped the vote, stated rather than assumed.
  if assert_count ge 1 "restart: P-id refused first (no-anchor: the restarted process observed no certificate naming a block)" "$log" "$mark" "cannot prove" "no-anchor"; [ $? -eq 2 ]; then return 1; fi
  if assert_none "restart: the restored gate was not reached in this scenario (see restart-at-anchor)" "$log" "$mark" "will NOT vote until the monotonic signing record"; [ $? -eq 2 ]; then return 1; fi
  if health restored && json_true "$scen/health-restored.json" '.voting == false' &&
    jq -r .nonVotingReason "$scen/health-restored.json" 2>/dev/null | grep -q "^restored from a persisted certificate"; then
    pass "restart: health reports voting=false: $(jq -r .nonVotingReason "$scen/health-restored.json")"
  else
    fail "restart: health does not report the restored state: $(cat "$scen/health-restored.json" 2>/dev/null)"
  fi
  return 0
}

# freeze_in_time <log> <round>: the node's log shows it had NOT accepted the certificate for <round>.
# 0 in time, 1 late, 2 not observed (a missing log or a round that is not a number is not "in time").
freeze_in_time() {
  local n
  is_count "$2" || return 2
  n=$(count_after "$1" 0 "accepted certificate" "partitionRound=$2 ") || return 2
  [ "$n" -eq 0 ]
}

scenario_restart_at_anchor() {
  setup_cluster || return 1
  local log="$scen/shard/debug.log" rootLog="$scen/root/debug.log" authorityPid mark rootMark authMark n i round resumed line
  authorityPid=$(pid_of authority)
  # Watched from the moment the process starts: the first round is certified within about two
  # seconds of startup. Freeze once the first request has been sent AND the certificate it followed
  # has been saved (persistingDriver saves after the round handler, which sends): the checkpoint then
  # predates the certificate the root is about to issue for that request.
  start_shard || { fail "could not start the shard node"; return 1; }
  i=0
  while :; do
    if n=$(count_after "$log" 0 "submitting block certification request"); then
      [ "$n" -ge 1 ] && [ -s "$scen/shard/shard-node-luc.json" ] && break
    elif [ "$i" -ge 20 ]; then
      # The log is created before the process starts, so a second of it being unreadable is a failure.
      fail "restart-at-anchor: the shard log could not be observed while waiting to freeze"
      return 1
    fi
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
  freeze_in_time "$log" "$round"
  case $? in
  0) pass "restart-at-anchor: the node was frozen after submitting round $round through the authority and before accepting its certificate" ;;
  1)
    fail "restart-at-anchor: the node had already accepted the certificate for round $round when it was frozen (late freeze; rerun)"
    return 1
    ;;
  *)
    fail "restart-at-anchor: could not establish whether the freeze was in time (round '$round', log $log)"
    return 1
    ;;
  esac
  check_shard_started || return 1
  wait_count "$rootLog" "$rootControlMark" 1 30 "reached consensus, new InputHash"
  case $? in
  0) pass "restart-at-anchor: the root chain reached consensus on the authority-signed request for round $round, whose certificate the frozen node had not accepted" ;;
  1)
    fail "restart-at-anchor: the root chain reached no consensus on round $round"
    return 1
    ;;
  *) return 1 ;;
  esac
  if assert_none "restart-at-anchor: the root chain rejected no certification request as invalid after the control" "$rootLog" "$rootControlMark" "invalid block certification request"; [ $? -eq 2 ]; then return 1; fi
  note "killing the frozen shard node (SIGKILL)"
  stop_proc "$scen" shard 'ubft shard-node run' KILL
  authority_status anchor-after-stop || { fail "status after stopping the shard node"; return 1; }
  if json_true "$scen/status-anchor-after-stop.json" ".generation == 1 and .reservedRound == $round and .responseRetained and (.faulted | not)"; then
    pass "restart-at-anchor: the authority's record holds round $round with its response retained, under generation 1"
  else
    fail "restart-at-anchor: unexpected status: $(cat "$scen/status-anchor-after-stop.json" 2>/dev/null)"
  fi
  cp "$scen/shard/shard-node-luc.json" "$scen/checkpoint-at-restart.json" || artifact_error "could not preserve the checkpoint"
  mark=$(take_mark "$log") || return 1
  rootMark=$(take_mark "$rootLog") || return 1
  authMark=$(take_mark "$scen/authority/authority.log") || return 1
  note "starting the shard node again with the same flags and credential"
  start_shard || { fail "could not restart the shard node"; return 1; }
  wait_count "$log" "$mark" 1 30 "resumed from persisted certificate"
  case $? in 1) fail "restart-at-anchor: the node did not resume from its checkpoint"; return 1 ;; 2) return 1 ;; esac
  resumed=$(line_after "$log" "$mark" "resumed from persisted certificate" | grep -o ' round=[0-9]*' | grep -o '[0-9]*$')
  if is_count "$resumed" && [ "$resumed" -lt "$round" ]; then
    pass "restart-at-anchor: the node resumed from its checkpoint at round $resumed, older than the certified round $round"
  else
    fail "restart-at-anchor: the node resumed at round '$resumed', not older than round $round"
  fi
  wait_count "$log" "$mark" 1 60 "will NOT vote until the monotonic signing record"
  case $? in
  0)
    line=$(line_after "$log" "$mark" "will NOT vote until the monotonic signing record")
    pass "restart-at-anchor: the restored gate withheld the vote: $(echo "$line" | grep -o 'restoredFromRound=[0-9]* round=[0-9]*')"
    ;;
  1) fail "restart-at-anchor: the restored gate was not reached within 60s" ;;
  *) return 1 ;;
  esac
  if assert_count ge 1 "restart-at-anchor: the restarted process installed an anchor from the non-quiet certificate" "$log" "$mark" "transition=installed"; [ $? -eq 2 ]; then return 1; fi
  assert_restored "$mark" "$rootMark" "$authMark" "$authorityPid" anchor || return 1
  if assert_none "restart-at-anchor: P-id refused nothing after the restart, so the restored gate alone withheld the vote" "$log" "$mark" "cannot prove"; [ $? -eq 2 ]; then return 1; fi
  if health restored && json_true "$scen/health-restored.json" '.voting == false and .nonVotingReason == "restored from a persisted certificate: non-voting until the monotonic signing contract (#105) exists"'; then
    pass "restart-at-anchor: health reports voting=false with the restored reason alone: $(jq -r .nonVotingReason "$scen/health-restored.json")"
  else
    fail "restart-at-anchor: unexpected health: $(cat "$scen/health-restored.json" 2>/dev/null)"
  fi
  return 0
}

# run_scenarios runs each selected scenario, tears it down, and records a scenario whose function
# returned early as stopped, which fails the verdict whatever it had counted.
run_scenarios() {
  local rc
  for scenario in "${scenarios[@]}"; do
    scen="$runDir/$scenario"
    mkdir -p "$scen" || { artifact_error "could not create $scen"; abortedScenarios+=("$scenario"); continue; }
    scenarioFailures=0
    rootControlMark=0
    echo
    echo "=== scenario: $scenario ==="
    case "$scenario" in
    fencing) scenario_fencing ;;
    authority-loss) scenario_authority_loss ;;
    restart) scenario_restart ;;
    restart-at-anchor) scenario_restart_at_anchor ;;
    *) false ;;
    esac
    rc=$?
    if [ "$rc" -ne 0 ]; then
      abortedScenarios+=("$scenario")
      fail "scenario $scenario stopped early"
    fi
    teardown_scenario "$scen"
    echo "scenario $scenario: $scenarioFailures failed assertions$([ "$rc" -ne 0 ] && echo ', stopped early')" | tee -a "$scen/summary.txt" ||
      artifact_error "$scen/summary.txt"
    reached="$scenario"
  done
  reached="all scenarios"
}

# --- self-test: the harness's failure paths, with the real functions and no processes ---------------
#
# A passing acceptance run never executes these paths, because they only run when an observation or
# an evidence write has already failed. Each case below asserts that such a failure FAILS: it counts a
# failure, returns non-zero, or changes the verdict to FAIL with a non-zero exit status. Two cases are
# positive controls, so that a harness failing everything cannot pass this self-test.
f6c_self_test() {
  local selfFailures=0 scratch desc before out rc
  st() { # st <desc> <0 to pass>
    if [ "$2" -eq 0 ]; then echo "  PASS: $1"; else
      echo "  FAIL: $1"
      selfFailures=$((selfFailures + 1))
    fi
  }
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/f6c-selftest.XXXXXX") || return 1
  runDir="$scratch/run"
  mkdir -p "$runDir" && : >"$runDir/run.log" && : >"$runDir/commands.log" || return 1
  scen=""
  windowTimeout=2
  echo "=== self-test: f6c acceptance harness failure paths ==="

  printf 'one\nreached consensus, new InputHash\nthree\n' >"$scratch/three.log"

  desc="a missing log is not a count of zero"
  out=$(count_after "$scratch/missing.log" 0 "reached consensus" 2>/dev/null)
  rc=$?
  st "$desc" "$([ "$rc" -ne 0 ] && [ -z "$out" ] && echo 0 || echo 1)"

  desc="a mark beyond the end of a log (a truncated log) is not an empty suffix"
  out=$(count_after "$scratch/three.log" 7 "reached consensus" 2>/dev/null)
  rc=$?
  st "$desc" "$([ "$rc" -ne 0 ] && [ -z "$out" ] && echo 0 || echo 1)"

  desc="a malformed mark is not a window"
  count_after "$scratch/three.log" "x" "reached consensus" >/dev/null 2>&1
  st "$desc" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  if [ "$(id -u)" -ne 0 ]; then
    desc="an unreadable log is not a count of zero"
    cp "$scratch/three.log" "$scratch/unreadable.log" && chmod 000 "$scratch/unreadable.log"
    out=$(count_after "$scratch/unreadable.log" 0 "reached consensus" 2>/dev/null)
    rc=$?
    st "$desc" "$([ "$rc" -ne 0 ] && [ -z "$out" ] && echo 0 || echo 1)"
    chmod 600 "$scratch/unreadable.log"
  else
    echo "  skip: unreadable-file case (running as root)"
  fi

  desc="a missing log has no line count"
  lines "$scratch/missing.log" >/dev/null 2>&1
  st "$desc" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  desc="positive control: a readable log is counted exactly, and zero matches is zero"
  st "$desc" "$([ "$(count_after "$scratch/three.log" 0 "reached consensus")" = 1 ] &&
    [ "$(count_after "$scratch/three.log" 2 "reached consensus")" = 0 ] && echo 0 || echo 1)"

  desc="waiting on a missing log fails as not observed, at once"
  before=$failures
  wait_count "$scratch/missing.log" 0 1 30 "anything" >/dev/null 2>&1
  rc=$?
  st "$desc" "$([ "$rc" -eq 2 ] && [ "$failures" -gt "$before" ] && echo 0 || echo 1)"

  desc="a negative assertion on a missing log fails and does not pass"
  before=$failures
  out=$(assert_none "no consensus" "$scratch/missing.log" 0 "reached consensus" 2>&1; echo "rc=$?")
  st "$desc" "$(echo "$out" | grep -q 'rc=2' && ! echo "$out" | grep -q 'PASS' && echo 0 || echo 1)"

  desc="a negative assertion on an empty window fails as not observed"
  out=$(assert_none "no consensus" "$scratch/three.log" 3 "reached consensus" 2>&1; echo "rc=$?")
  st "$desc" "$(echo "$out" | grep -q 'rc=2' && echo "$out" | grep -q 'holds no line' && echo 0 || echo 1)"

  desc="two unreadable status files are not an unchanged status"
  json_same "$scratch/missing-a.json" "$scratch/missing-b.json"
  st "$desc" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  desc="a missing log or a malformed round does not make a freeze in time"
  freeze_in_time "$scratch/missing.log" 2 2>/dev/null
  a=$?
  freeze_in_time "$scratch/three.log" "" 2>/dev/null
  b=$?
  echo 'msg="accepted certificate" class=valid partitionRound=2 rootRound=9' >"$scratch/late.log"
  freeze_in_time "$scratch/late.log" 2 2>/dev/null
  c=$?
  freeze_in_time "$scratch/three.log" 2 2>/dev/null
  d=$?
  st "$desc (missing $a, malformed $b, late $c, in time $d)" "$([ "$a" -eq 2 ] && [ "$b" -eq 2 ] && [ "$c" -eq 1 ] && [ "$d" -eq 0 ] && echo 0 || echo 1)"

  # A synthetic abstaining node, driven through the real assert_abstains. Process and HTTP probes are
  # replaced inside a subshell; the observation and assertion functions are the real ones.
  make_abstain_logs() { # <dir>
    mkdir -p "$1/shard" "$1/root" "$1/authority"
    {
      echo 'msg="accepted certificate" class=valid partitionRound=4'
      echo 'msg="submitting block certification request" round=5 '
      for r in 5 6 7 8 9; do
        echo "msg=\"abstaining from the vote: the certification request was not signed\" round=$r err=\"reserving the round with the signing authority: signing-session-fenced\""
        echo "msg=\"accepted certificate\" class=repeat partitionRound=4"
      done
    } >"$1/shard/debug.log"
    for r in 1 2 3 4 5 6; do echo "root round $r"; done >"$1/root/debug.log"
  }
  abstain_probe() { # <dir> <prepare command> : prints the probe's output and "rc=N failures=M"
    (
      scen=$1
      rootControlMark=1
      health() { echo '{"voting":false,"nonVotingReason":"the certification request was not signed: signing-session-fenced"}' >"$scen/health-$1.json"; }
      alive() { return 0; }
      pid_of() { echo 1; }
      eval "$2"
      failures=0
      assert_abstains signing-session-fenced 1 probe
      echo "rc=$? failures=$failures"
    ) 2>&1
  }

  desc="positive control: assert_abstains passes on a complete synthetic record"
  make_abstain_logs "$scratch/good"
  out=$(abstain_probe "$scratch/good" '(sleep 1; echo "root round 7" >>"$scen/root/debug.log") &')
  st "$desc" "$(echo "$out" | grep -q 'rc=0 failures=0$' && echo 0 || { echo "$out" | sed 's/^/      /' >&2; echo 1; })"

  desc="a root log that disappears after the positive control fails assert_abstains"
  make_abstain_logs "$scratch/gone"
  out=$(abstain_probe "$scratch/gone" 'rm -f "$scen/root/debug.log"')
  st "$desc" "$(echo "$out" | grep -q 'rc=1' && ! echo "$out" | grep -q 'PASS: probe: the root chain reached no consensus' && echo 0 || echo 1)"

  desc="a root log truncated while its window is open fails assert_abstains"
  make_abstain_logs "$scratch/truncated"
  out=$(abstain_probe "$scratch/truncated" '(sleep 1; : >"$scen/root/debug.log") &')
  st "$desc" "$(echo "$out" | grep -Eq 'rc=1|failures=[1-9]' && ! echo "$out" | grep -q 'PASS: probe: the root chain reached no consensus' && echo 0 || echo 1)"

  desc="a shard log that disappears fails assert_abstains"
  make_abstain_logs "$scratch/shardgone"
  out=$(abstain_probe "$scratch/shardgone" 'rm -f "$scen/shard/debug.log"')
  st "$desc" "$(echo "$out" | grep -q 'rc=1' && ! echo "$out" | grep -q 'PASS: probe: no certification request was submitted' && echo 0 || echo 1)"

  desc="missing status snapshots and a missing root log fail assert_restored"
  mkdir -p "$scratch/restored/shard" "$scratch/restored/authority"
  for r in 1 2 3 4; do echo 'msg="accepted certificate" class=repeat partitionRound=4'; done >"$scratch/restored/shard/debug.log"
  : >"$scratch/restored/authority/authority.log"
  out=$(
    (
      scen="$scratch/restored"
      ubft() { return 1; }
      alive() { return 0; }
      pid_of() { echo 1; }
      failures=0
      assert_restored 0 0 0 1 probe
      echo "rc=$? failures=$failures"
    ) 2>&1
  )
  st "$desc" "$(echo "$out" | grep -q 'rc=1' && ! echo "$out" | grep -q 'PASS: probe: the root chain reached no consensus' && ! echo "$out" | grep -q 'identical before and after' && echo 0 || echo 1)"

  # The real cleanup and verdict, in a subshell each (cleanup exits). No scenario directory holds
  # pids, so teardown signals nothing.
  verdict_probe() { # <name> <prepare command>: prints cleanup's output and "exit=N"
    local d="$scratch/verdict-$1"
    mkdir -p "$d" && : >"$d/run.log" && : >"$d/commands.log"
    (
      runDir=$d
      scen=""
      scenario=""
      socketDirs=()
      scenarios=(fencing)
      failures=0
      artifactErrors=0
      abortedScenarios=()
      reached="all scenarios"
      startedAt=self-test
      invocation=self-test
      eval "$2"
      cleanup
    ) >"$d.out" 2>&1
    echo "exit=$?" >>"$d.out"
    cat "$d.out"
  }

  desc="positive control: a clean synthetic run is RESULT: PASS with exit 0"
  out=$(verdict_probe clean ':')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: PASS' && echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="a manifest that cannot be written fails the verdict"
  out=$(verdict_probe manifest 'mkdir "$runDir/manifest.txt"')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="digests that cannot be written fail the verdict"
  out=$(verdict_probe digests 'mkdir "$runDir/sha256sums.txt"')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="a list of removed secrets that cannot be written fails the verdict"
  out=$(verdict_probe secrets-list 'mkdir "$runDir/removed-secrets.txt"')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  if [ "$(id -u)" -ne 0 ]; then
    desc="a secret that cannot be removed fails the verdict"
    out=$(verdict_probe secret-stuck 'mkdir -p "$runDir/s/authority" && : >"$runDir/s/authority/client.cred" && chmod 500 "$runDir/s/authority"')
    chmod 700 "$scratch/verdict-secret-stuck/s/authority" 2>/dev/null
    st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"
  fi

  desc="a run log that cannot be written fails the verdict"
  out=$(verdict_probe runlog 'rm -f "$runDir/run.log" && mkdir "$runDir/run.log" && pass "an assertion whose record was lost"')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="a command-log failure inside a captured ubft call reaches the parent verdict"
  out=$(verdict_probe captured-command 'rm -f "$runDir/commands.log" && mkdir "$runDir/commands.log"; build/ubft() { echo node-id; }; nodeID=$(ubft node-id) || fail "captured command could not be recorded"; rmdir "$runDir/commands.log"; : >"$runDir/commands.log"')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="a counted assertion failure fails the verdict"
  out=$(verdict_probe failed 'failures=1')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="a scenario that stops early after only passing assertions fails the verdict"
  out=$(verdict_probe aborted 'scenario_fencing() { pass "a stub assertion"; return 1; }; run_scenarios >/dev/null 2>&1')
  st "$desc" "$(echo "$out" | grep -q '^RESULT: FAIL (.*stopped early: fencing' && ! echo "$out" | grep -q '^exit=0$' && echo 0 || echo 1)"

  desc="an evidence directory that cannot be created is refused"
  : >"$scratch/a-file"
  (runDir="$scratch/a-file/run" && prepare_run_dir) >/dev/null 2>&1
  st "$desc" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  desc="an existing evidence directory is refused"
  (runDir="$scratch/run" && prepare_run_dir) >/dev/null 2>&1
  st "$desc" "$([ $? -ne 0 ] && echo 0 || echo 1)"

  desc="T2 is at least the owner's 5000ms floor"
  st "$desc (t2Millis=$t2Millis)" "$([ "$t2Millis" -ge 5000 ] && echo 0 || echo 1)"

  desc="a shard configuration with T2 3000ms, or with no T2 field, is refused"
  echo '{"t2timeout":3000000000}' >"$scratch/conf-3s.json"
  echo '{"epoch":0}' >"$scratch/conf-none.json"
  a=0 b=0
  (t2Millis=3000 && conf_t2_ok "$scratch/conf-3s.json") && a=1
  conf_t2_ok "$scratch/conf-none.json" && b=1
  conf_t2_ok "$scratch/missing-conf.json" && b=1
  st "$desc" "$([ "$a" -eq 0 ] && [ "$b" -eq 0 ] && echo 0 || echo 1)"

  desc="positive control: a shard configuration with T2 ${t2Millis}ms is accepted"
  echo "{\"t2timeout\":$((t2Millis * 1000000))}" >"$scratch/conf-ok.json"
  conf_t2_ok "$scratch/conf-ok.json"
  st "$desc" "$([ $? -eq 0 ] && echo 0 || echo 1)"

  chmod -R u+rwx "$scratch" 2>/dev/null
  rm -rf "$scratch"
  echo "self-test: $selfFailures failed"
  [ "$selfFailures" -eq 0 ]
}

# --- main -----------------------------------------------------------------------------------------

if [ "${1:-}" = "--self-test" ]; then
  f6c_self_test
  exit $?
fi

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
invocation="$0 $*"
[ -n "$runDir" ] || runDir="evidence-runs/f6c-authority-$(date -u +%Y%m%dT%H%M%SZ)"
if ! prepare_run_dir; then
  echo "could not create the evidence directory $runDir; nothing was started" >&2
  exit 2
fi
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "=== f6c-authority-acceptance: evidence in $runDir ==="
logcmd make build
if ! make build >"$runDir/build.log" 2>&1; then
  cat "$runDir/build.log"
  fail "make build"
  exit 1
fi

run_scenarios
