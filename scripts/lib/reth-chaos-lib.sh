#!/bin/bash
# reth-chaos-lib.sh - DEFINITIONS ONLY for scripts/reth-chaos.sh.
#
# Sourcing this file must have NO side effects: it changes no directory, parses no options, starts
# no process, installs no trap and checks no prerequisite. That is the entire reason it exists.
#
# scripts/reth-chaos-selftest.sh used to source a PREFIX of reth-chaos.sh, which dragged `cd`,
# `getopts`, the reth prerequisite check and the INT/TERM trap along with the definitions. On a
# machine without reth the prerequisite check exited each case before a single assertion ran and
# the suite reported "0 ok, 6 bad" — a suite that tested nothing while looking as though it had
# failed honestly. Its `cd` also escaped the temporary work directory. Separating definitions from
# initialisation is what makes the assertion oracle testable with no reth, no devnet, no side
# effects and nothing written outside a temporary directory.
#
# Every tunable below is `: "${name:=default}"`, so a caller may set it before sourcing.

: "${validators:=4}"
: "${workloadTxs:=3}"
: "${keep:=false}"
: "${injectFailure:=false}"
: "${scenarios:=}"   # empty = run them all; see wantScenario

# --- where the evidence lives -----------------------------------------------------------------
#
# NOT under test-nodes/. setup-evm-nodes.sh runs `make clean`, which deletes that directory whole,
# and this harness now rebuilds a cluster per scenario — so anything kept there is destroyed at
# every scenario boundary, before it can be collected. Earlier revisions stashed test-nodes/evidence
# across the reset and lost everything else with it: the full shard, root and reth logs, the trust
# base, the identities and the chain configuration, which are exactly what a continuity-gap or a
# "Too deep reorg" needs to be explained from. The summaries that survived cannot reconstruct a
# certificate history.
#
# So the run writes to its own directory, outside the blast radius, one per invocation. A previous
# run's artefacts can therefore never be inherited by this one either.
: "${runID:=$(date -u +%Y%m%dT%H%M%SZ)-$$}"
: "${runDir:=${F1_CHAOS_RUN_DIR:-evidence-runs/$runID}}"
evidenceDir=$runDir

# Scan inputs (scripts/lib/reth-pin.sh, "scan inputs"): every cluster's secrets are recorded before
# use into a private file beside the run's archive, so publication can search the whole run's
# evidence for secrets of clusters that no longer exist. Derived from runDir, never cached, so a
# caller that sets runDir after sourcing still gets the matching file.
# shellcheck source=scripts/lib/reth-pin.sh
. "$(dirname "${BASH_SOURCE[0]}")/reth-pin.sh"
chaosScanFile() { rethScanInputsPath "$runDir.tar.gz"; }

# knownScenarios is the authority for -s. A name not in it is a mistake, not a filter.
knownScenarios="baseline follower-restart leader-kill reth-only-restart pair-restart multi-leader quiet-restart"

# currentScenario names the cluster that is up, so it can be sealed under the right label before the
# next reset destroys it. Empty means no cluster has been built yet.
: "${currentScenario:=}"
# scenariosRun counts scenarios that actually executed. A run that executed none is not a pass.
: "${scenariosRun:=0}"

: "${partitionID:=8}"
: "${chainID:=31337}"
: "${pinnedRethCommit:=$URETH_PIN_COMMIT}"   # the fork client the seal-capable shard node requires

: "${rethEngineBase:=18551}"
: "${rethEthBase:=18545}"
: "${rethP2PBase:=30401}"

: "${failures:=0}"
pass() { echo "  PASS: $1"; }
# Everything goes to stdout. Splitting pass/fail across stdout and stderr scrambles the order in
# a redirected log — stderr is unbuffered, stdout is block-buffered — which made an early run look
# as though cleanup had torn the devnet down mid-scenario when it had not. The exit code carries
# the failure signal; the log needs to read in the order things happened.
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  ..   $1"; }

ethURL()    { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }
engineURL() { echo "http://127.0.0.1:$((rethEngineBase + $1 - 1))"; }

# --- RPC, strictly validated -------------------------------------------------------------------
#
# Every observation used in an assertion goes through rpcField. A transport failure, a JSON-RPC
# error object, a missing result or a missing field is a FAILED OBSERVATION and returns nonzero;
# it never yields a value an assertion can accidentally agree on.
#
# This matters more than it sounds. The first version returned "" on failure and compared the
# strings: with every block and receipt call erroring, all four nodes produced the same empty
# observation, so "all clients agree on the canonical head", "...on the sender nonce" and
# "...on every receipt" all PASSED with zero failures. A harness that reports agreement because
# nothing answered is worse than no harness. Reproduced by the reviewer and now pinned by
# scripts/reth-chaos-selftest.sh.
rpc() {
  curl -sS --max-time 15 -X POST "$1" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" 2>/dev/null
}

# rpcField <url> <method> <params> <json-array-of-keys>
#
# The fourth argument is a JSON ARRAY of keys — '["result","blockHash"]' — not a Python index
# expression, whatever the older wording suggested. Passing the wrong shape makes every call fail
# and every caller take its "could not observe" branch, which is silent by design; that is exactly
# what happened to the first version of the leader correlation below.
# Prints the field on success. Returns 1 on transport failure, JSON-RPC error, null result, or a
# missing/null field, printing nothing.
rpcField() {
  local url=$1 method=$2 params=$3 expr=$4 body
  body=$(rpc "$url" "$method" "$params") || return 1
  [ -n "$body" ] || return 1
  python3 - "$body" "$expr" <<'PYEOF' 2>/dev/null || return 1
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
if not isinstance(d, dict) or d.get("error") is not None:
    sys.exit(1)
if "result" not in d or d["result"] is None:
    sys.exit(1)
cur = d
try:
    for key in json.loads(sys.argv[2]):
        cur = cur[key]
except Exception:
    sys.exit(1)
if cur is None:
    sys.exit(1)
print(cur)
PYEOF
}

pyget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
hexToDec() { python3 -c "print(int('${1:-0x0}',16))" 2>/dev/null || echo 0; }

# --- process lifecycle ------------------------------------------------------------------------
startReth() {
  local i=$1
  mkdir -p "test-nodes/reth$i"
  declare -F registry_layout_require >/dev/null || source helper.sh # first cluster starts reth before the lane sources helper.sh
  registry_layout_require || return 1
  "$URETH_BIN" node --chain test-nodes/evm-genesis-funded.json --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    $(urethPinUnicityFlags) \
    >>"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
}

# stopReth - stop a client and WAIT for it to actually exit before returning. Dropping the pid
# file immediately let a restart race the dying process for its datadir and ports.
stopReth() {
  local i=$1 pid waited=0
  [ -f "test-nodes/reth$i/pid" ] || return 0
  pid=$(cat "test-nodes/reth$i/pid")
  rm -f "test-nodes/reth$i/pid"
  # Only a pid that is still a `reth node` running from this checkout (helper.sh, "ownership"): the
  # integer in a stale pid file may by now belong to anything.
  declare -F owned_pid >/dev/null || source helper.sh
  owned_pid "$pid" 'reth node' || return 0
  kill "$pid" 2>/dev/null || return 0
  while ps -p "$pid" >/dev/null 2>&1; do
    if [ "$waited" -ge 30 ]; then
      kill -9 "$pid" 2>/dev/null
      break
    fi
    sleep 1; waited=$((waited + 1))
  done
  return 0
}

# waitReth - bounded, condition-driven: poll until the client answers, never a fixed sleep.
waitReth() {
  local i=$1 budget=${2:-60} waited=0
  while ! rpc "$(ethURL "$i")" eth_chainId '[]' | grep -q result; do
    [ "$waited" -ge "$budget" ] && return 1
    sleep 1; waited=$((waited + 1))
  done
  return 0
}

peerReths() {
  local i j enode
  for i in $(seq 1 "$validators"); do
    enode=$(rpc "$(ethURL "$i")" admin_nodeInfo '[]' | pyget "['result']['enode']")
    [ -z "$enode" ] && continue
    for j in $(seq 1 "$validators"); do
      [ "$i" = "$j" ] && continue
      rpc "$(ethURL "$j")" admin_addPeer "[\"$enode\"]" >/dev/null
    done
  done
}

# Teardown is NOT on an EXIT trap, deliberately.
#
# helper.sh's start_one_evm_validator backgrounds the node, and that forked child ran this
# script's EXIT trap with a call stack of "cleanup start_one_evm_validator main" — confirmed by
# instrumenting it. Cleanup then killed every node in the middle of a scenario while the parent
# carried on, so every later assertion failed against an already-dead devnet. It looked exactly
# like a protocol fault and was not one.
#
# No PID test fixes this portably: bash keeps the parent's $$ in a forked child, macOS's
# /bin/bash 3.2 has no BASHPID, and `$(sh -c "echo \$PPID")` reports the substitution subshell
# rather than the caller. So teardown is called explicitly instead — at the end, and on an
# interrupt. If the script dies some other way the nodes are left running, which is recoverable
# with `./stop-evm.sh -a` and is the more useful outcome anyway: #88 wants the evidence kept.
cleanup() {
  local i
  if [ "$keep" = true ]; then
    echo "=== leaving everything running (-k) ==="
    return
  fi
  echo "=== stopping everything ==="
  ./stop-evm.sh -a >/dev/null 2>&1
  for i in $(seq 1 "$validators"); do stopReth "$i"; done
  stopReth "wrongchain" 2>/dev/null
  wait 2>/dev/null
}
# finish - collect evidence, then tear down. Runs on success, on assertion failure, and on
# cancellation, so a run never ends without its evidence. Idempotent: an interrupt during the
# normal end-of-run path must not collect or tear down twice.
: "${finished:=}"
finish() {
  [ -z "$finished" ] || return 0
  finished=yes
  # The cluster still standing belongs to whichever scenario was running when the run ended,
  # however it ended. Everything before it was sealed at its own boundary, so the archive below
  # contains every scenario's full evidence and not just the last one's.
  # The supervisor is a different process from the child that ran the scenarios, so it cannot know
  # from a variable which one was live. The child records it; without that the last scenario's
  # evidence is filed under a name that says nothing about what it contains.
  local last=$currentScenario
  [ -n "$last" ] || last=$(cat "$runDir/.scenario" 2>/dev/null)
  collectEvidence "${last:-final}" || true
  # The cluster still standing was recorded at its bring-up; recording it again costs nothing and
  # covers a secret written after that. Sealed only if no capture failed — unsealed scan inputs mean
  # the workflow's selection will not publish this archive.
  if rethScanInputsCapture test-nodes "$(chaosScanFile)" >/dev/null && rethScanInputsSeal "$(chaosScanFile)" >/dev/null; then
    pass "scan inputs recorded for every cluster and sealed, outside the archive: $(chaosScanFile)"
  else
    rethScanInputsFail "$(chaosScanFile)" "final capture"
    fail "scan inputs not sealed — this archive's secrets cannot all be searched for, and it will not be published"
  fi
  archiveEvidence
  cleanup
}

# superviseResult <childStatus> <failuresFile> - the supervisor's verdict, as one function so it
# can be executed by scripts/reth-chaos-selftest.sh rather than only read.
#
# It collects evidence (finish), then combines TWO INDEPENDENT failure counts and prints the
# summary. Returns 0 only if both are zero.
#
# The two counts must stay separate, and conflating them was a real defect (#91 review 5144079322).
# finish -> collectEvidence reports through the same fail() the scenarios use, so it increments
# `failures` in THIS process: a failed copy, an archive tar could not write, or a secret file found
# in the archive. The supervisor then used to do `failures=$(cat "$failuresFile")`, overwriting its
# own count with the child's. A successful child plus a failed archive therefore printed the FAIL
# line and exited 0 with "evidence complete" — silently defeating the evidence-failure gate #88
# asks for, in the one direction that matters, since the evidence is the deliverable.
#
# Order is forced: finish must run before the child's count can be trusted anyway (it is what
# retains the evidence), so the fix is to snapshot the supervisor's own count immediately after it
# and add, never assign.
superviseResult() {
  local childStatus=$1 file=$2 childFailures supervisorFailures

  failures=0
  finish
  supervisorFailures=$failures

  if [ -s "$file" ]; then
    childFailures=$(cat "$file")
  else
    # The child never got far enough to record a count. That is itself a failure: the run did not
    # complete, and reporting 0 would read as success.
    echo "  FAIL: the scenario process ended without recording a result (exit $childStatus) — the run did not complete"
    childFailures=1
  fi
  # A result file that is not a number is not a result. Without this the arithmetic below fails at
  # runtime and the verdict is decided by whatever the shell does next, which is not a verdict.
  case "$childFailures" in
    "" | *[!0-9]*)
      echo "  FAIL: the scenario process recorded an unreadable result ('$childFailures') — the run did not complete"
      childFailures=1
      ;;
  esac
  if [ "$childStatus" -ne 0 ] && [ "$childFailures" -eq 0 ]; then
    echo "  FAIL: the scenario process exited $childStatus with no assertion failure recorded — treating as a harness failure"
    childFailures=1
  fi

  failures=$((childFailures + supervisorFailures))
  if [ "$failures" -gt 0 ]; then
    echo "=== reth-chaos.sh: $failures failure(s) — $childFailures from the run, $supervisorFailures from evidence collection — evidence retained ==="
    return 1
  fi
  echo "=== reth-chaos.sh: real-reth workload and fault evidence complete ==="
  return 0
}

# --- cluster lifecycle (#88 stage 2: "independent scenarios from clean fixtures") --------------
#
# Every fault scenario gets its OWN devnet: fresh keys, fresh reth datadirs, fresh chain, fresh
# certified history. Two separate reasons, and both were learned the hard way here:
#
#   Evidence. Scenarios used to share one long-lived cluster, so a node that failed to recover in
#   scenario 2 was still broken in scenarios 3-5 and every later assertion measured that instead of
#   the fault it named. The harness compensated by refusing to run them at all (skipIfUnrecovered),
#   which is honest but produces no evidence for four of the six scenarios.
#
#   Quorum. Since F6b stage 3 a shard node resumed from a persisted certificate is NON-VOTING for
#   the rest of its process (#105 owns the contract that lifts it). Shard quorum is n/2+1, so on a
#   shared cluster each restart permanently spends part of the fault budget and the run stalls after
#   the second one — not because the fault under test broke anything, but because of the fault
#   before it. A fresh cluster per scenario restores the full budget to each.
#
# The cost is one devnet bring-up per scenario. That is the price of a per-scenario result.
# bringUpCluster <label> - destroy the current cluster and build a clean one for <label>.
#
# The label is an argument because OWNERSHIP MUST TRANSFER AT THE RESET, not after the new cluster
# turns out to be healthy. An earlier revision took ownership after bring-up succeeded, so a startup
# failure — a reth that would not come up, a shard that never certified — left the PREVIOUS
# scenario's name attached to a cluster that no longer existed, and the final collection then wrote
# the broken cluster's artefacts over that scenario's sealed evidence. The failure destroyed the
# record of the thing that had worked.
bringUpCluster() {
  local label=${1:-} i waited=0

  ./stop-evm.sh -a >/dev/null 2>&1
  for i in $(seq 1 "$validators"); do stopReth "$i"; done

  # SEAL BEFORE DESTROYING. setup-evm-nodes.sh runs `make clean`, which deletes test-nodes whole:
  # every shard, root and reth log, the trust base, the identities and the chain configuration. If
  # the outgoing scenario is not sealed first, the run ends holding detailed evidence for only its
  # LAST cluster — which is what happened, and why an earlier continuity-gap could not be explained
  # from the archive. The reset is ABORTED when sealing fails: losing the evidence is worse than
  # not running the next scenario.
  if [ -n "$currentScenario" ]; then
    if ! collectEvidence "$currentScenario"; then
      fail "refusing to reset the cluster: '$currentScenario' evidence was not sealed and the reset would destroy it"
      return 1
    fi
  fi

  # The outgoing scenario's evidence is safely sealed, so this cluster is now the incoming one's —
  # whatever happens to it from here. Everything below can fail; none of it may be filed under the
  # scenario that just ended.
  currentScenario=$label
  mkdir -p "$runDir"
  echo "$label" >"$runDir/.scenario"

  # T2 is the inactivity timeout before the root chain tells the shard to retry, not the round
  # interval, and it must leave room above both. 5000ms matches scripts/chaos-evm.sh so the two
  # lanes are comparable, and the follower await budget is derived from it (AwaitTimeoutForT2).
  ./setup-evm-nodes.sh -r 3 -v "$validators" -t 5000 >/dev/null || { echo "setup failed" >&2; return 1; }

  python3 - <<'PY'
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY

  for i in $(seq 1 "$validators"); do
    openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  done
  # RECORD BEFORE USE. The next reset destroys this cluster's JWTs and keys while its logs stay in the
  # evidence; publication can only search that evidence for secrets recorded here. Nothing has used
  # them yet, so a failure to record means the cluster is not started at all.
  if ! rethScanInputsCapture test-nodes "$(chaosScanFile)" >/dev/null; then
    rethScanInputsFail "$(chaosScanFile)" "cluster '$label'"
    fail "could not record cluster '$label''s secrets as scan inputs; not starting it — its logs could carry secrets no scan would know"
    return 1
  fi
  for i in $(seq 1 "$validators"); do
    startReth "$i"
  done
  for i in $(seq 1 "$validators"); do
    waitReth "$i" 90 || { fail "reth$i did not start"; return 1; }
  done
  peerReths
  pass "$validators pinned reth instances up and statically peered"

  # shellcheck source=/dev/null
  source helper.sh
  for i in $(seq 1 "$validators"); do
    export "EVM_ENGINE_URL_$i=$(engineURL "$i")"
    export "EVM_ETH_URL_$i=$(ethURL "$i")"
  done
  # Debug, not info: evidence for #88 depends on it. "continuity: observed certificate" is the only
  # line that carries a partition round and the certified EVM block hash together, and correlating a
  # leader with an executed block is impossible without it (see assertMultiLeaderExecution, which
  # fails loudly rather than quietly finding nothing if the level is wrong).
  export EVM_VALIDATOR_LOG_LEVEL="${EVM_VALIDATOR_LOG_LEVEL:-debug}"
  ./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1
  rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")

  until grep -q 'accepted certificate' "$(log 1)" 2>/dev/null; do
    [ "$waited" -ge 180 ] && { fail "shard never certified"; return 1; }
    sleep 2; waited=$((waited + 2))
  done
  pass "shard certifying on --executor engine-api against real reth"

  # Per-cluster state. txHashes MUST be reset: the receipts it names live on the chain that was
  # just discarded, so carrying them into the next cluster would fail every convergence assertion
  # for a reason that has nothing to do with the scenario.
  txHashes=()
  recoveryFailed=""
  return 0
}

# validateScenarios - check every name given to -s against knownScenarios BEFORE anything is started
# or stopped. An unknown name used to select nothing: the run then executed no scenario, wrote no
# failures, archived an empty directory and exited 0 saying the evidence was complete. A selection
# that matches nothing is a mistake in the invocation, not a filter.
validateScenarios() {
  local name known found bad=""
  [ -n "$scenarios" ] || return 0
  # An empty token — "-s a,,b" or "-s ," — is not a name either.
  case ",$scenarios," in
    *,,*) echo "empty scenario name in -s '$scenarios'" >&2; return 1 ;;
  esac
  # Commas to spaces rather than IFS surgery: setting IFS=, would also split knownScenarios, which
  # is space-separated, and every valid name would then be reported as unknown.
  for name in $(echo "$scenarios" | tr ',' ' '); do
    found=no
    for known in $knownScenarios; do
      [ "$name" = "$known" ] && { found=yes; break; }
    done
    [ "$found" = yes ] || bad="$bad $name"
  done
  if [ -n "$bad" ]; then
    echo "unknown scenario(s):$bad" >&2
    echo "known scenarios: $knownScenarios" >&2
    return 1
  fi
  return 0
}

# writeRunManifest - the one artefact that says what this run measured, written unconditionally
# before any scenario is selected. A subset run used to record only per-cluster genesis hashes, so
# its archive could not establish the revisions it ran against; and because the evidence directory
# was reused, it could inherit a PREVIOUS run's pins and appear to.
writeRunManifest() {
  local rethVersion="not resolved"
  [ -n "${URETH_BIN:-}" ] && rethVersion=$("$URETH_BIN" --version 2>/dev/null | tr '\n' ' ')
  mkdir -p "$runDir"
  {
    echo "runID=$runID"
    echo "startedUTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "invocation=$0 $*"
    echo "bft=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "bftDirty=$([ -n "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo no)"
    echo "reth=$rethVersion"
    echo "rethPinned=$pinnedRethCommit"
    echo "validators=$validators workloadTxs=$workloadTxs partitionID=$partitionID chainID=$chainID"
    echo "t2Timeout=5000ms (generated by bringUpCluster)"
    echo "scenariosSelected=${scenarios:-all}"
    echo "logLevel=${EVM_VALIDATOR_LOG_LEVEL:-debug}"
  } >"$runDir/manifest.txt"
  cat "$runDir/manifest.txt"
}

# wantScenario <name> - true unless -s named a set this scenario is not in. Selection is by name
# rather than by number so a subset stays meaningful when scenarios are added or reordered.
wantScenario() {
  [ -n "$scenarios" ] || return 0
  case ",$scenarios," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

# freshCluster <label> - tear the previous cluster down and bring a new one up for <label>, then
# establish that it works BEFORE any fault: a scenario opening on a cluster that is not already
# converged cannot produce evidence about its fault.
freshCluster() {
  local label=$1
  echo "  --  fresh fixtures for '$label' (independent scenario, #88 stage 2)"
  # The count is incremented BEFORE the bring-up, and the label is taken inside it: a scenario that
  # failed to start is a scenario that ran and failed, not a scenario that never happened.
  scenariosRun=$((scenariosRun + 1))
  bringUpCluster "$label" || { fail "$label: could not bring up a clean cluster"; return 1; }
  # Each cluster is a different chain with different keys, so its own pins are recorded rather than
  # letting the run's first set stand for all of them.
  {
    echo "scenario=$label"
    echo "genesis=$(shasum -a 256 test-nodes/evm-genesis.json | cut -d' ' -f1)"
    echo "fundedGenesis=$(shasum -a 256 test-nodes/evm-genesis-funded.json | cut -d' ' -f1)"
    echo "shardConf=$(shasum -a 256 "test-nodes/shard-conf-${partitionID}_0.json" | cut -d' ' -f1)"
  } >"$runDir/$label-pins.txt"
  runWorkload "$label-pre" "$workloadTxs"
  convergenceGate "$label-pre" || return 1
  return 0
}

# --- leader <-> executed block correlation (#88 stage 1) ---------------------------------------
#
# #88 asks for "at least two distinct shard leaders producing executed, certified blocks", and is
# explicit that counting submissions does not answer it: a submission is not an executed block, and
# quiet rounds and uncertified attempts count the same as real work. The correlation below joins
# three facts that are each recorded independently, so the claim is assembled from evidence rather
# than assumed:
#
#   receipt        tx -> EVM block hash               (eth_getTransactionReceipt, the execution client)
#   anchor line    EVM block hash -> partition round  (shard node, AFTER UC.Verify — see below)
#   submit line    partition round -> leader          (shard node, from the technical record)
#
# The middle step is why this lane runs its validators at debug. "continuity: observed certificate"
# is logged by shardnode/round.go for every verified certificate, and it is the only place a
# partition round and the certified EVM block hash appear together. It is written after the
# certificate verified against the trust base, so the round-to-block binding is authenticated, not
# inferred from timing.
#
# THE FIELD NAMES ARE A CONTRACT WITH THE RUNTIME. This line replaced an older
# "execution anchor installed" one in #109, and the parser below had to move with it; nothing else
# ties these two changes together, so a rename on either side must update the other. Both the field
# it reads (blockHash=) and the transition it filters on (transition=installed) are asserted by
# scripts/reth-chaos-selftest.sh against a recorded sample of the real line.

# hexNoPrefix - the shard node logs hashes as raw %x (no 0x); JSON-RPC returns them 0x-prefixed.
hexNoPrefix() { local h=${1#0x}; echo "$h" | tr 'A-F' 'a-f'; }

# certifiedRoundOfBlock <validator> <blockHash> - the partition round in which that EVM block was
# certified, according to <validator>'s own verified-certificate log. Empty and nonzero if unknown.
certifiedRoundOfBlock() {
  local from=$1 want round
  want=$(hexNoPrefix "$2")
  # An empty hash matches every line, including the quiet rounds that name no block at all — so a
  # failed receipt lookup would correlate to whatever round happened to be last. Refuse it.
  [ -n "$want" ] || return 1
  round=$(grep 'continuity: observed certificate' "$(log "$from")" 2>/dev/null |
    grep 'transition=installed' |
    grep -F "blockHash=$want " | tail -1 |
    grep -o 'partitionRound=[0-9]*' | cut -d= -f2)
  [ -n "$round" ] || return 1
  echo "$round"
}

# leaderOfRound <round> - the validator that submitted for that round AS LEADER.
#
# Exactly one node leads a round, but a round can be re-attempted after a timeout with a different
# leader, and then two nodes have legitimately submitted as leader for it. That is reported as
# ambiguous and attributed to nobody rather than resolved by guessing: a wrong attribution is worse
# than a missing one for evidence whose whole point is which node produced which block.
leaderOfRound() {
  local round=$1 i found="" n=0
  for i in $(seq 1 "$validators"); do
    if grep 'submitting block certification request' "$(log "$i")" 2>/dev/null |
       grep -q "round=$round .*leader=true"; then
      found=$i; n=$((n + 1))
    fi
  done
  [ "$n" -eq 1 ] || return 1
  echo "$found"
}

# certifyingRootRound <validator> <partitionRound> - the root round of the certificate that
# certified that partition round, from the accepted-certificate line. Identifies the UC.
certifyingRootRound() {
  local from=$1 round=$2 r
  r=$(grep 'accepted certificate' "$(log "$from")" 2>/dev/null |
    grep "partitionRound=$round " | tail -1 | grep -o 'rootRound=[0-9]*' | cut -d= -f2)
  [ -n "$r" ] || return 1
  echo "$r"
}

# multiLeaderEvidence - the file every claim below is made from.
multiLeaderEvidence=$runDir/multi-leader.txt

# correlateExecutedBlocks <observer> - for every transaction executed so far, print and record
# "txHash blockHash partitionRound leaderValidator leaderPeer rootRound", skipping any that cannot
# be correlated. Prints the distinct leader indices it established, one per line.
correlateExecutedBlocks() {
  local from=$1 h blk round who peer root
  for h in ${txHashes[@]+"${txHashes[@]}"}; do
    if ! blk=$(rpcField "$(ethURL "$from")" eth_getTransactionReceipt "[\"$h\"]" '["result","blockHash"]'); then
      echo "SKIP $h no-receipt" >&2
      continue
    fi
    if ! round=$(certifiedRoundOfBlock "$from" "$blk"); then
      echo "SKIP $h no-certified-round-for-$blk" >&2
      continue
    fi
    if ! who=$(leaderOfRound "$round"); then
      echo "SKIP $h no-unambiguous-leader-for-round-$round" >&2
      continue
    fi
    peer=$(peerIDOf "$who")
    peer=${peer:-unknown}
    root=$(certifyingRootRound "$from" "$round" || echo unknown)
    grep -q "^$h " "$multiLeaderEvidence" 2>/dev/null ||
      echo "$h $blk $round $who $peer $root" >>"$multiLeaderEvidence"
    echo "$who"
  done | sort -u
}

# assertMultiLeaderExecution <observer> <minLeaders> <extraTxBudget>
#
# Drives the workload until <minLeaders> DISTINCT shard leaders have each produced an executed,
# certified EVM block, then asserts it. Bounded: at most <extraTxBudget> additional transactions,
# each individually bounded by submitAndConfirm. It does not wait for luck — leader rotation is per
# round, so sending more transactions is what makes a second leader produce one — and if the budget
# runs out it FAILS with what it actually observed.
assertMultiLeaderExecution() {
  local from=$1 minLeaders=${2:-2} budget=${3:-6} leaders count sent=0 via
  : >"$multiLeaderEvidence"

  if ! grep -q 'continuity: observed certificate' "$(log "$from")" 2>/dev/null; then
    fail "multi-leader: validator $from logged no 'continuity: observed certificate' line, so no executed block can be tied to a certified round — this lane requires debug logging (EVM_VALIDATOR_LOG_LEVEL)"
    return 1
  fi

  while :; do
    leaders=$(correlateExecutedBlocks "$from" 2>/dev/null)
    count=$(echo "$leaders" | grep -c '[0-9]' || true)
    [ "$count" -ge "$minLeaders" ] && break
    [ "$sent" -ge "$budget" ] && break
    via=$(( sent % validators + 1 ))
    [ -f "test-nodes/reth$via/pid" ] || via=$from
    sent=$((sent + 1))
    info "multi-leader: $count of $minLeaders distinct leaders so far; sending transaction $sent/$budget"
    submitAndConfirm "$via" >/dev/null || break
  done

  # Skipped transactions are reported, never swallowed. "0 leaders" and "0 transactions that could
  # be correlated" are different findings and the second one is a broken harness, not a shard
  # result — the first version of this function could not tell them apart and reported the wrong
  # one.
  local skipped
  skipped=$(correlateExecutedBlocks "$from" 2>&1 >/dev/null | grep -c '^SKIP ' || true)
  if [ "${skipped:-0}" -gt 0 ]; then
    fail "multi-leader: $skipped executed transaction(s) could not be correlated to a leader at all — the correlation itself is broken, so no leader claim can be made either way"
    correlateExecutedBlocks "$from" 2>&1 >/dev/null | sed 's/^/  ..   /'
  fi

  leaders=$(correlateExecutedBlocks "$from" 2>/dev/null | tr '\n' ' ')
  count=$(echo "$leaders" | wc -w | tr -d ' ')
  if [ "$count" -ge "$minLeaders" ]; then
    pass "multi-leader: $count distinct shard leaders each produced an executed, certified EVM block (validators:$leaders) — correlated per block in evidence/multi-leader.txt"
  else
    fail "multi-leader: only $count distinct leader(s) produced an executed certified block after $sent extra transaction(s) (validators:$leaders); #88 requires $minLeaders"
  fi
  while read -r line; do [ -n "$line" ] && info "  block correlation: $line"; done <"$multiLeaderEvidence"
}

# --- observation helpers ----------------------------------------------------------------------
log() { echo "test-nodes/evm$1/debug.log"; }
logLines() { wc -l <"$(log "$1")" 2>/dev/null | tr -d ' ' || echo 0; }

# certifiedRound - last partition round this validator logged ACCEPTING a certificate for.
certifiedRound() {
  local r
  r=$(grep -o 'partitionRound=[0-9]*' "$(log "$1")" 2>/dev/null | tail -1 | cut -d= -f2)
  echo "${r:-0}"
}

# execHead - the reth canonical head this validator's executor has applied, as "number:hash".
# Returns nonzero and prints nothing if the client cannot be observed: an unobservable head is not
# a head value, and must never flow into a comparison.
execHead() {
  local num hash
  num=$(rpcField "$(ethURL "$1")" eth_getBlockByNumber '["latest", false]' '["result","number"]') || return 1
  hash=$(rpcField "$(ethURL "$1")" eth_getBlockByNumber '["latest", false]' '["result","hash"]') || return 1
  case "$hash" in 0x*) ;; *) return 1 ;; esac
  echo "$(hexToDec "$num"):$hash"
}

# shardLeadersSince - distinct validators that logged themselves leader after line $2 of their log.
# Shard leadership is NOT root leadership; they rotate independently (#88 requires the
# distinction), so this reads the shard's own submission lines only.
shardLeadersSince() {
  local afterFile=$1 i mark found=""
  for i in $(seq 1 "$validators"); do
    mark=$(grep "^$i " "$afterFile" 2>/dev/null | awk '{print $2}')
    mark=${mark:-0}
    if awk -v n="$mark" 'NR > n && /submitting block certification request/ && /leader=true/ {f=1; exit} END{exit !f}' "$(log "$i")" 2>/dev/null; then
      found="$found $i"
    fi
  done
  echo "$found"
}

# validatorForPeer - map a peer ID (as it appears in TechnicalRecord.Leader) to a validator index,
# using each node's own node-info.json. Prints nothing if unknown.
# peerIDOf <validator> - that validator's libp2p node id, from the identity file it wrote. Used to
# record WHICH node a correlated block is attributed to in terms the certificates also use.
peerIDOf() {
  python3 -c "import json;print(json.load(open('test-nodes/evm$1/node-info.json'))['nodeId'])" 2>/dev/null
}

validatorForPeer() {
  local want=$1 i id
  for i in $(seq 1 "$validators"); do
    id=$(python3 -c "import json;print(json.load(open('test-nodes/evm$i/node-info.json'))['nodeId'])" 2>/dev/null)
    [ "$id" = "$want" ] && { echo "$i"; return 0; }
  done
  return 1
}

# currentShardLeader - the validator the shard's own latest accepted certificate names as leader
# for the NEXT round, i.e. the authenticated technical-record context rather than a guess from
# recent log lines. Prints "index peerID round" so the boundary can be recorded as evidence.
#
# The first version scanned for the lowest-index node whose last five submissions contained
# leader=true, which is neither the assigned nor the most recent leader; the reviewer was right
# that it made the scenario a shard-process restart rather than a leader experiment.
currentShardLeader() {
  local from=$1 line peer round idx
  line=$(grep 'accepted certificate' "$(log "$from")" 2>/dev/null | tail -1)
  [ -n "$line" ] || return 1
  peer=$(echo "$line" | grep -o 'nextLeader=[^ ]*' | cut -d= -f2)
  round=$(echo "$line" | grep -o 'nextRound=[0-9]*' | cut -d= -f2)
  [ -n "$peer" ] || return 1
  idx=$(validatorForPeer "$peer") || return 1
  echo "$idx $peer $round"
}

markAll() {
  local i out=$1
  : >"$out"
  for i in $(seq 1 "$validators"); do echo "$i $(logLines "$i")" >>"$out"; done
}

# waitForCertifiedProgress - bounded wait for validator $1 to accept a round above $2.
waitForCertifiedProgress() {
  local v=$1 above=$2 budget=${3:-90} waited=0
  while [ "$(certifiedRound "$v")" -le "$above" ]; do
    [ "$waited" -ge "$budget" ] && return 1
    sleep 2; waited=$((waited + 2))
  done
  return 0
}

# --- workload ---------------------------------------------------------------------------------
senderAcct=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
declare -a txHashes=()   # expanded as ${txHashes[@]+...}: bash 3.2 treats an empty "${a[@]}" as unbound under set -u

# nextNonce - ask the chain, do not count locally.
#
# A local counter desynchronises the moment a submission is counted as failed but is later mined:
# the harness reuses the nonce and every subsequent send dies with "nonce too low", which looks
# like a shard fault and is not one. The pending count is the authority on what this account has
# actually spent.
nextNonce() {
  local n
  n=$(rpc "$(ethURL "$1")" eth_getTransactionCount "[\"$senderAcct\",\"pending\"]" | pyget "['result']")
  hexToDec "${n:-0x0}"
}

# submitAndConfirm - send one funded transaction to validator $1's client and wait, bounded, for
# a receipt. Records hash, nonce, receipt block and status. Returns nonzero if it never executes.
submitAndConfirm() {
  local via=$1 budget=${2:-120} h waited=0 rcpt blkHex status gas nonce
  nonce=$(nextNonce "$via")
  h=$(go run ./scripts/evmtx -send -eth-url "$(ethURL "$via")" -chain-id "$chainID" -nonce "$nonce" 2>&1)
  if [[ "$h" != 0x* ]]; then
    fail "submitting tx nonce=$nonce via reth$via: $h"
    return 1
  fi
  while :; do
    rcpt=$(rpc "$(ethURL "$via")" eth_getTransactionReceipt "[\"$h\"]")
    blkHex=$(echo "$rcpt" | pyget "['result']['blockNumber']")
    [ -n "$blkHex" ] && [ "$blkHex" != "None" ] && break
    if [ "$waited" -ge "$budget" ]; then
      fail "tx $h (nonce $nonce) was never executed within ${budget}s"
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  status=$(echo "$rcpt" | pyget "['result']['status']")
  gas=$(echo "$rcpt" | pyget "['result']['gasUsed']")
  txHashes+=("$h")
  echo "$h $nonce $(hexToDec "$blkHex") $status $gas" >>"$runDir/workload.txt"
  info "tx $h nonce=$nonce -> block $(hexToDec "$blkHex") status=$status gasUsed=$gas"
  [ "$status" = "0x1" ] || { fail "tx $h reverted (status $status)"; return 1; }
  return 0
}

# runWorkload - a burst of unique transactions, recording how many distinct shard leaders produced
# certified work while it ran.
#
# Leaders are written to a file rather than returned on stdout, and this must NEVER be called in a
# command substitution: that runs it in a subshell, where the sender nonce and the recorded
# transaction hashes are updated in a copy and then thrown away. The first version did exactly
# that and the next burst failed with "nonce too low: next nonce 2, tx nonce 0".
runWorkload() {
  local label=$1 count=$2 via i ok=0 leaders
  markAll "$runDir/.marks"
  for i in $(seq 1 "$count"); do
    via=$(( (i - 1) % validators + 1 ))
    # only submit through a validator whose client is up
    [ -f "test-nodes/reth$via/pid" ] || via=1
    submitAndConfirm "$via" && ok=$((ok + 1))
  done
  leaders=$(shardLeadersSince "$runDir/.marks")
  echo "$label leaders:$leaders executed:$ok/$count" >>"$runDir/workload.txt"
  echo "$leaders" >"$runDir/.leaders-$label"
  if [ "$ok" -eq "$count" ]; then
    pass "$label: $ok/$count transactions executed and certified (shard leaders seen:$leaders)"
  else
    fail "$label: only $ok/$count transactions executed"
  fi
}

# --- cross-node agreement ---------------------------------------------------------------------
# assertConvergence - every live client must agree on the canonical head AND on the receipts and
# nonce for the workload so far. Head agreement alone would not catch divergent state.
assertConvergence() {
  local label=$1
  local i h expected live=0 bad=0
  local heads="" nonces="" rcpts=""

  # Bounded wait for propagation before comparing. A block reaches the other clients over devp2p
  # and through their own forkchoice, which is not instant; comparing immediately would measure
  # delivery latency and report it as divergence.
  local waited=0 probe seen
  # Budget is overridable so scripts/reth-chaos-selftest.sh can drive the oracle without waiting
  # out a propagation window that will never be satisfied by stubs.
  while [ "$waited" -lt "${CONVERGE_WAIT_BUDGET:-60}" ]; do
    seen=""; probe=0
    for i in $(seq 1 "$validators"); do
      [ -f "test-nodes/reth$i/pid" ] || continue
      probe=$((probe + 1))
      seen="$seen$(execHead "$i" || echo UNOBSERVABLE)"$'\n'
    done
    [ "$(printf '%s' "$seen" | sort -u | grep -c .)" = "1" ] && ! printf '%s' "$seen" | grep -q UNOBSERVABLE && break
    sleep 2; waited=$((waited + 2))
  done

  # Collect. Every live participant MUST be observable, and every submitted transaction MUST have
  # a receipt with the block and status it was recorded with. A failed observation is a failure,
  # never an empty string that happens to match another empty string.
  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/reth$i/pid" ] || continue
    live=$((live + 1))

    local head nonce
    if ! head=$(execHead "$i"); then
      fail "$label: validator $i's execution head could not be observed"
      bad=$((bad + 1)); continue
    fi
    heads="$heads$head"$'\n'

    if ! nonce=$(rpcField "$(ethURL "$i")" eth_getTransactionCount "[\"$senderAcct\",\"latest\"]" '["result"]'); then
      fail "$label: validator $i's sender nonce could not be observed"
      bad=$((bad + 1)); continue
    fi
    nonces="$nonces$(hexToDec "$nonce")"$'\n'

    local per="" blk st
    for h in ${txHashes[@]+"${txHashes[@]}"}; do
      if ! blk=$(rpcField "$(ethURL "$i")" eth_getTransactionReceipt "[\"$h\"]" '["result","blockNumber"]'); then
        fail "$label: validator $i has no receipt for $h (it was executed and recorded earlier)"
        bad=$((bad + 1)); per=""; break
      fi
      if ! st=$(rpcField "$(ethURL "$i")" eth_getTransactionReceipt "[\"$h\"]" '["result","status"]'); then
        fail "$label: validator $i has no receipt status for $h"
        bad=$((bad + 1)); per=""; break
      fi
      # Cross-check against what was recorded when the transaction executed, so a client that
      # agrees with its peers but disagrees with history is still caught.
      expected=$(awk -v hh="$h" '$1==hh {print $3" "$4}' "$runDir/workload.txt" | tail -1)
      if [ -n "$expected" ] && [ "$(hexToDec "$blk") $st" != "$expected" ]; then
        fail "$label: validator $i has $h at block $(hexToDec "$blk") status $st, recorded as $expected"
        bad=$((bad + 1))
      fi
      per="$per$(hexToDec "$blk"),$st;"
    done
    rcpts="$rcpts$per"$'\n'
  done

  {
    echo "--- $label (live=$live unobservable=$bad) ---"
    echo "heads:"; printf '%s' "$heads"
    echo "nonces:"; printf '%s' "$nonces"
    echo "receipts:"; printf '%s' "$rcpts"
  } >>"$runDir/convergence.txt"

  if [ "$live" -eq 0 ]; then
    fail "$label: no live execution clients to compare — convergence is unproven, not satisfied"
    return 1
  fi
  if [ "$bad" -gt 0 ]; then
    fail "$label: $bad of $live live clients could not be observed; convergence NOT established"
    return 1
  fi

  # Only now is agreement meaningful: every live client answered, for every recorded transaction.
  local uniqHeads uniqNonces uniqRcpts nHeads
  nHeads=$(printf '%s' "$heads" | grep -c .)
  uniqHeads=$(printf '%s' "$heads" | sort -u | grep -c .)
  uniqNonces=$(printf '%s' "$nonces" | sort -u | grep -c .)
  uniqRcpts=$(printf '%s' "$rcpts" | sort -u | grep -c .)

  [ "$nHeads" = "$live" ] || { fail "$label: observed $nHeads heads for $live live clients"; return 1; }

  # Every mismatch sets mismatched, and the function RETURNS NONZERO. It used to return 0
  # unconditionally after printing FAIL lines, so a caller could not tell agreement from
  # disagreement and the next fault was injected into a cluster already known to have diverged.
  # Reproduced by review with valid but differing heads 4:0xabc / 4:0xdef: canonical-head FAIL,
  # return=0, recoveryFailed empty.
  local mismatched=0
  if [ "$uniqHeads" = "1" ]; then
    pass "$label: all $live live clients agree on the canonical head"
  else
    fail "$label: canonical heads disagree"; printf '%s' "$heads"; mismatched=1
  fi
  if [ "$uniqNonces" = "1" ]; then
    pass "$label: all $live live clients agree on the sender nonce (no duplicate execution)"
  else
    fail "$label: sender nonce disagrees"; printf '%s' "$nonces"; mismatched=1
  fi
  if [ "$uniqRcpts" = "1" ]; then
    pass "$label: all $live live clients agree on every one of ${#txHashes[@]} recorded receipts"
  else
    fail "$label: receipts disagree"; printf '%s' "$rcpts"; mismatched=1
  fi
  return "$mismatched"
}

# convergenceGate - assertConvergence, with its result actually consumed.
#
# Every scenario calls this rather than assertConvergence directly. A convergence failure is a
# prerequisite failure for everything after it: continuing would inject the next fault into a
# cluster already known to disagree, and the retained convergence.txt from the first run showed
# exactly that contamination (node 1 stuck at block 4 while the others advanced, across three
# "independent" scenarios).
# observeQuietRecovery <validator> <target-head> <budget> - watch a returning node during a QUIET
# interval and report whether it recovers on its own, INJECTING NOTHING.
#
# This is deliberately not recoveredAndWorking. That helper submits a transaction as part of its
# check, which is fine for "does the node do new work" and useless for the question here: a
# transaction produces a non-quiet round, a non-quiet round carries a block hash, and a block hash
# is exactly the evidence a returning node is missing. Measuring recovery with a helper that
# supplies the missing evidence cannot distinguish "it recovered" from "it was given what it
# lacked".
#
# THREE OUTCOMES, because two of them used to be one:
#
#   0  RECOVERED            a valid observation equal to the target
#   1  OBSERVED, BEHIND     enough valid observations to say so, none of them the target
#   2  INVALID OBSERVATION  the executor could not be read well enough to say anything
#
# The third is a failure of the measurement, not a result. An earlier revision returned 1 for both
# "the node is behind" and "every RPC failed", so a scenario in which no executor was observed at
# all read as the interesting negative — and the positive control that follows could then bring the
# client back and leave the run green, having measured nothing. That is the same defect this
# harness's oracle was corrected for once already: a failed observation must never satisfy or refute
# an assertion.
#
# A partial outage is accounted for rather than papered over with the last good sample: the negative
# verdict requires a majority of polls to have succeeded AND the final poll to have succeeded.
observeQuietRecovery() {
  local v=$1 target=$2 budget=${3:-120}
  local waited=0 samples=0 failures=0 lastGood="" finalOK=false head
  quietSamples=0; quietFailures=0; quietLastHead=""; quietWaited=0   # for the caller's record

  while [ "$waited" -lt "$budget" ]; do
    if head=$(execHead "$v"); then
      samples=$((samples + 1)); lastGood=$head; finalOK=true
      if [ "$head" = "$target" ]; then
        quietSamples=$samples; quietFailures=$failures; quietLastHead=$head; quietWaited=$waited
        info "quiet observation: validator $v reached $target after ${waited}s with no new work ($samples valid sample(s), $failures failed)"
        return 0
      fi
    else
      failures=$((failures + 1)); finalOK=false
    fi
    sleep 3; waited=$((waited + 3))
  done

  quietSamples=$samples; quietFailures=$failures; quietLastHead=$lastGood; quietWaited=$waited
  # A STRICT majority, so an exact 50/50 split is refused rather than counted as observed. Half the
  # window unreadable is not a basis for saying what the executor did in it, and "not a majority of
  # failures" quietly admitted the tie.
  if [ "$samples" -eq 0 ] || [ $((samples * 2)) -le $((samples + failures)) ] || [ "$finalOK" != true ]; then
    info "quiet observation: INVALID — validator $v gave $samples valid sample(s) and $failures failed one(s) over ${budget}s (final poll ok: $finalOK)"
    return 2
  fi
  info "quiet observation: after ${budget}s of quiet rounds validator $v is at ${lastGood}, the shard at $target ($samples valid sample(s), $failures failed)"
  return 1
}

# quietPrecondition <victim> <survivor> <survivor-head-before> <mark> - establish that the interval
# really was quiet, from the shard's own behaviour rather than from "we did not submit anything":
# the survivor's canonical head must not have moved, every certificate the victim verified in the
# window must have been quiet, and rounds must have progressed.
quietPrecondition() {
  local victim=$1 survivor=$2 before=$3 mark=$4 after nonQuiet rounds ok=true
  after=$(execHead "$survivor") || { fail "quiet precondition: survivor $survivor's head is unobservable"; return 1; }
  if [ "$after" != "$before" ]; then
    fail "quiet precondition: the shard produced a block during the observation window ($before -> $after) — the interval was not quiet"
    ok=false
  fi
  nonQuiet=$(awk -v n="$mark" 'NR > n && /continuity: observed certificate/ && /quiet=false/' "$(log "$victim")" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$nonQuiet" != "0" ]; then
    fail "quiet precondition: validator $victim verified $nonQuiet non-quiet certificate(s) during the window"
    ok=false
  fi
  rounds=$(awk -v n="$mark" 'NR > n && /accepted certificate/' "$(log "$victim")" 2>/dev/null | grep -oE 'partitionRound=[0-9]+' | sort -u | wc -l | tr -d ' ')
  if [ "${rounds:-0}" -lt 2 ]; then
    fail "quiet precondition: only ${rounds:-0} distinct partition round(s) were certified during the window — the shard was not live"
    ok=false
  fi
  [ "$ok" = true ] && pass "quiet precondition: the shard stayed at $after, certified $rounds distinct rounds, and every certificate validator $victim saw was quiet"
  [ "$ok" = true ]
}

# quietObservationRecord <validator> <mark> <verdict> - the structured record of one observation
# window, written to the run directory as well as printed, so the interval and its result are
# archived rather than reconstructed from a log afterwards.
#
# DELIVERIES ARE NOT ROUNDS. An accepted-certificate line is one delivery, and a duplicate
# re-delivered after a failed application produces another; counting lines and calling them
# certified rounds overstates the shard's progress. Both numbers are reported.
quietObservationRecord() {
  local v=$1 mark=$2 verdict=$3 lg out
  # EVERY COUNT BELOW IS CUMULATIVE FROM <mark>, not per observation window. The control phase
  # reuses the restart mark on purpose — the point there is the node's whole history since it
  # returned — so the field names say so rather than inviting the reader to subtract two records.
  lg=$(log "$v")
  out=$runDir/quiet-observation.txt
  {
    echo "verdict=$verdict"
    echo "validator=$v"
    echo "thisWindowSeconds=${quietWaited:-0} thisWindowValidSamples=${quietSamples:-0} thisWindowFailedSamples=${quietFailures:-0}"
    echo "lastObservedHead=${quietLastHead:-none}"
    echo "deliveriesSinceRestart=$(awk -v n="$mark" 'NR > n && /accepted certificate/' "$lg" 2>/dev/null | wc -l | tr -d ' ')"
    echo "distinctPartitionRoundsSinceRestart=$(awk -v n="$mark" 'NR > n && /accepted certificate/' "$lg" 2>/dev/null | grep -oE 'partitionRound=[0-9]+' | sort -u | wc -l | tr -d ' ')"
    echo "distinctRootRoundsSinceRestart=$(awk -v n="$mark" 'NR > n && /accepted certificate/' "$lg" 2>/dev/null | grep -oE 'rootRound=[0-9]+' | sort -u | wc -l | tr -d ' ')"
    echo "retriedDeliveriesSinceRestart=$(awk -v n="$mark" 'NR > n && /retryOfFailedApply=true/' "$lg" 2>/dev/null | wc -l | tr -d ' ')"
    echo "firstAcceptedSinceRestart=$(awk -v n="$mark" 'NR > n && /accepted certificate/' "$lg" 2>/dev/null | head -1 | grep -oE 'partitionRound=[0-9]+ rootRound=[0-9]+' | head -1)"
    echo "lastAcceptedSinceRestart=$(awk -v n="$mark" 'NR > n && /accepted certificate/' "$lg" 2>/dev/null | tail -1 | grep -oE 'partitionRound=[0-9]+ rootRound=[0-9]+' | head -1)"
    echo "anchorDecisionsSinceRestart=$(awk -v n="$mark" 'NR > n && /continuity: observed certificate/' "$lg" 2>/dev/null | grep -oE 'transition=[a-z]+' | sort | uniq -c | tr '\n' ' ')"
    echo "nonQuietCertificatesSinceRestart=$(awk -v n="$mark" 'NR > n && /continuity: observed certificate/ && /quiet=false/' "$lg" 2>/dev/null | wc -l | tr -d ' ')"
    echo "firstRefusalSinceRestart=$(awk -v n="$mark" 'NR > n' "$lg" 2>/dev/null | grep -oE 'no-anchor|continuity-gap|anchor-mismatch|head-identity-mismatch|unavailable in the executor \(status [a-z]+\)|engine API error [-0-9]+|reading executor head' | head -1)"
    echo "refusalOccurrencesSinceRestart=$(awk -v n="$mark" 'NR > n' "$lg" 2>/dev/null | grep -cE 'no-anchor|continuity-gap|anchor-mismatch|head-identity-mismatch|unavailable in the executor|engine API error|reading executor head' | tr -d ' ')"
    echo "nonVotingGateLinesSinceRestart=$(awk -v n="$mark" 'NR > n && /will NOT vote/' "$lg" 2>/dev/null | wc -l | tr -d ' ')"
    echo "certificationRequestsSinceRestart=$(awk -v n="$mark" 'NR > n && /submitting block certification/' "$lg" 2>/dev/null | wc -l | tr -d ' ')"
    echo "executorHeadNow=$(execHead "$v" || echo UNOBSERVABLE)"
    echo "rethTail=$(grep -iE 'canonical|forkchoice|sync' "test-nodes/reth$v/reth.log" 2>/dev/null | tail -1 | cut -c1-160)"
  } | tee -a "$out" | sed 's/^/  ..     /'
  echo "  ..     (recorded in $out)"
}

# recoveredAndWorking - the returning node must (a) accept a certificate logged after its restart
# and (b) participate in executing a NEW transaction, agreeing with everyone else afterwards.
# A restart that merely re-reads an old certificate is not recovery.
# recoveryFailed is sticky. #88 requires that no further fault be injected until the returning node
# demonstrably executes and certifies new work, and the reviewer showed the consequence of ignoring
# it: after a failed recovery the next scenario ran against an already-degraded cluster, so its
# result said nothing about the fault it was supposed to isolate. Later scenarios are now marked
# NOT RUN instead of producing contaminated evidence.
: "${recoveryFailed:=}"

skipIfUnrecovered() {
  [ -n "$recoveryFailed" ] || return 1
  echo "  SKIP: $1 NOT RUN — the cluster never recovered from $recoveryFailed, so any result here"
  echo "        would be contaminated (#88: do not inject another fault until the returning node"
  echo "        demonstrably executes and certifies new work)."
  return 0
}

recoveredAndWorking() {
  local v=$1 mark=$2 label=$3 budget=${4:-120} waited=0
  while ! awk -v n="$mark" 'NR > n && /accepted certificate/ {f=1; exit} END{exit !f}' "$(log "$v")" 2>/dev/null; do
    if [ "$waited" -ge "$budget" ]; then
      fail "$label: validator $v accepted no NEW certificate within ${budget}s after returning"
      recoveryFailed="$label"
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  pass "$label: validator $v accepted a new certificate after returning"

  # Submit through a client that stayed up, never the returning node's own. Routing it through
  # the node under test measures whether its mempool and peering have caught up, which is a
  # different question from whether it applies newly certified work — and it produced spurious
  # "never executed" failures while the returning client was still syncing.
  local via headBefore
  via=$(( v % validators + 1 ))
  [ -f "test-nodes/reth$via/pid" ] || via=1
  headBefore=$(execHead "$v") || { fail "$label: validator $v's head is unobservable after returning"; recoveryFailed="$label"; return 1; }
  submitAndConfirm "$via" || { recoveryFailed="$label"; return 1; }
  # OBSERVATION SUCCESS IS CHECKED SEPARATELY FROM THE HEAD CHANGE.
  #
  # This loop used to be `while [ "$(execHead "$v" || echo UNOBSERVABLE)" = "$headBefore" ]`. A
  # failed observation substitutes UNOBSERVABLE, which differs from headBefore, so the loop exited
  # immediately and the node was declared recovered BECAUSE its client had stopped answering.
  # Review reproduced it: first observation 4:0xabc, every later one failing, two PASS lines,
  # return 0, failures 0. Only a VALID observed head that differs can establish recovery; a failed
  # observation is retried within the same bound and then fails.
  # The same budget bounds both waits. It used to be a hardcoded 120 here while the first loop used
  # $budget, so a caller could not bound this function at all — which made it untestable without
  # waiting out two minutes per case, and meant the two halves of one scenario had different
  # patience for no stated reason.
  waited=0
  local headAfter observed=false
  while [ "$waited" -lt "$budget" ]; do
    if headAfter=$(execHead "$v"); then
      observed=true
      [ "$headAfter" != "$headBefore" ] && break
    else
      observed=false
    fi
    sleep 2; waited=$((waited + 2))
  done
  if [ "$observed" != true ]; then
    fail "$label: validator $v's execution head was not observable within ${budget}s after returning — recovery is UNPROVEN, not established"
    recoveryFailed="$label"
    return 1
  fi
  if [ "$headAfter" = "$headBefore" ]; then
    fail "$label: validator $v's executor did not apply the new block (still $headBefore)"
    recoveryFailed="$label"
    return 1
  fi
  pass "$label: validator $v executed new work after returning ($headBefore -> $headAfter)"
  return 0
}

convergenceGate() {
  local label=$1
  if assertConvergence "$label"; then
    return 0
  fi
  recoveryFailed="${recoveryFailed:-$label}"
  info "$label did not converge — later scenarios will be marked NOT RUN rather than injected into a diverged cluster"
  return 1
}

# --- evidence ---------------------------------------------------------------------------------
snapshot() {
  local label=$1 i
  # Split deliberately: bash expands every assignment word before performing any of them, so
  # referring to $label in the same `local` that assigns it fails under `set -u`.
  local dir="$runDir/snapshots/$label"
  mkdir -p "$dir"
  for i in $(seq 1 "$validators"); do
    {
      echo "validator=$i certifiedRound=$(certifiedRound "$i") execHead=$(execHead "$i")"
      echo "rethRunning=$([ -f "test-nodes/reth$i/pid" ] && echo yes || echo no)"
      echo "shardRunning=$([ -f "test-nodes/evm$i/pid" ] && echo yes || echo no)"
      echo "lastCertLine=$(grep 'accepted certificate' "$(log "$i")" 2>/dev/null | tail -1)"
      echo "lastRootRound=$(grep -o 'rootRound=[0-9]*' "$(log "$i")" 2>/dev/null | tail -1)"
      # The decisive datum when a node does not catch up: WHICH named refusal it is sitting on.
      # Since F6b stage 3 every one of these maps to a row of the recovery transition table, so an
      # unrecovered node is a diagnosis rather than a mystery.
      echo "lastRecoveryDiagnostic=$(grep -Eo 'no-anchor|continuity-gap|anchor-mismatch|head-identity-mismatch|unavailable in the executor \(status [a-z]*\)' "$(log "$i")" 2>/dev/null | tail -1)"
      echo "nonVotingAfterRestart=$(grep -c 'will NOT vote' "$(log "$i")" 2>/dev/null | tr -d ' ')"
    } >"$dir/evm$i.txt"
    # The persisted certificate is one half of any conflict comparison and appears in no log.
    cp "test-nodes/evm$i/shard-node-luc.json" "$dir/evm$i-luc.bin" 2>/dev/null || true
  done
}

# collectEvidence [label] - copy the LIVE cluster's full artefacts into the run directory under
# <label>, verifying every required copy. Called once per scenario, before that scenario's cluster
# is destroyed, and once for the last cluster at the end of the run. Returns nonzero if anything
# that exists could not be copied — the caller must not destroy a cluster whose evidence did not
# survive.
collectEvidence() {
  local label=${1:-final}
  local out=$runDir/scenarios/$label
  local i missing=0 copied=0

  # SEALED MEANS SEALED. A scenario is collected once, at the boundary that ends it, and a second
  # attempt on the same label is a lifecycle bug — the one that let a failed bring-up file a broken
  # cluster over the evidence of the scenario before it. Refuse rather than overwrite: the run can
  # lose a scenario it never captured, but not one it did.
  if [ -d "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
    fail "evidence: '$label' is already sealed at $out — refusing to overwrite it"
    return 1
  fi
  mkdir -p "$out" || { fail "evidence: cannot create $out"; return 1; }

  # copyRequired records whether each expected artefact actually arrived. Completeness used to be
  # inferred from "the archive has more than five entries", which cannot distinguish a complete run
  # from one where half the logs failed to copy but the genesis files made up the count.
  copyRequired() {
    local src=$1 dst=$2
    if [ ! -e "$src" ]; then
      return 0 # legitimately absent (a node that never started); not a copy failure
    fi
    if cp "$src" "$dst" 2>/dev/null; then
      copied=$((copied + 1))
    else
      missing=$((missing + 1))
      info "evidence: failed to copy $src"
    fi
  }

  for i in $(seq 1 "$validators"); do
    copyRequired "$(log "$i")" "$out/evm$i-debug.log"
    copyRequired "test-nodes/reth$i/reth.log" "$out/reth$i.log"
    copyRequired "test-nodes/evm$i/shard-node-luc.json" "$out/evm$i-luc.bin"
    copyRequired "test-nodes/evm$i/node-info.json" "$out/evm$i-node-info.json"
  done
  for i in 1 2 3; do copyRequired "test-nodes/root$i/debug.log" "$out/root$i-debug.log"; done
  copyRequired "test-nodes/shard-conf-${partitionID}_0.json" "$out/shard-conf-${partitionID}_0.json"
  copyRequired test-nodes/trust-base.json "$out/trust-base.json"
  copyRequired test-nodes/evm-genesis.json "$out/evm-genesis.json"
  copyRequired test-nodes/evm-genesis-funded.json "$out/evm-genesis-funded.json"

  # Secrets are excluded by construction, never filtered after the fact: keys.json and jwt.hex
  # are simply not copied. The check below fails the run if one ever appears anyway.
  if find "$runDir" -name 'keys.json' -o -name 'jwt.hex' | grep -q .; then
    fail "evidence archive contains a secret file"
  else
    pass "evidence archive contains no keys.json or jwt.hex"
  fi

  if [ "$missing" -gt 0 ]; then
    fail "evidence collection incomplete for '$label': $missing required artefact(s) present but not copied ($copied succeeded)"
    return 1
  fi
  info "evidence sealed for '$label': $copied artefact(s) under $out"
  return 0
}

# archiveEvidence - one archive of the whole run directory, every scenario in it.
archiveEvidence() {
  local archive=$runDir.tar.gz
  if tar czf "$archive" -C "$(dirname "$runDir")" "$(basename "$runDir")" 2>/dev/null && [ -s "$archive" ]; then
    pass "evidence archived: $archive ($(du -h "$archive" | cut -f1), scenarios: $(ls "$runDir/scenarios" 2>/dev/null | tr '\n' ' '))"
  else
    fail "evidence archive was not produced — the run's evidence is only in $runDir/"
  fi
}

# collectEvidenceLegacyTail is what the old single-directory collection did after copying. It is
# kept only so the shape of the function below stays readable; see archiveEvidence.
collectEvidenceLegacyTail() {

  # The archive claim is made from tar's own exit status, not from counting what ended up inside.
  if tar czf test-nodes/reth-chaos-evidence.tar.gz -C test-nodes evidence 2>/dev/null &&
     [ -s test-nodes/reth-chaos-evidence.tar.gz ]; then
    if [ "$missing" -gt 0 ]; then
      info "archive written, but incomplete — see the failure above"
    elif [ "$copied" -eq 0 ]; then
      # An empty archive is not a successful collection. This happens when the run died before it
      # produced anything; saying PASS here would report an archive that contains nothing.
      info "archive written but EMPTY: the run produced no evidence to collect"
    else
      pass "evidence archived: test-nodes/reth-chaos-evidence.tar.gz ($(du -h test-nodes/reth-chaos-evidence.tar.gz | cut -f1), $copied artefact(s))"
    fi
  else
    fail "evidence archive was not produced — the run's evidence is only in $runDir/"
  fi
}

