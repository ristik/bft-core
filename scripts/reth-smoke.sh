#!/bin/bash
# reth-smoke.sh - the real-reth smoke lane (F1c, #90), the same script locally and in CI.
#
# Obtains the approved pinned execution client and verifies it, runs the stock-client control and
# the paired funded-transaction devnet against it, and then — whatever happened — collects the
# evidence, tears down every process the run started, archives the evidence and validates the
# archive. .github/workflows/reth-smoke.yml is a thin wrapper around this script.
#
# Usage (from anywhere; it runs from the repository root):
#   ./scripts/reth-smoke.sh --reth-bin PATH [options]   # a binary you built from the pinned commit
#   ./scripts/reth-smoke.sh --fetch [options]           # the upstream release artifact for this host
#
#     --reth-bin PATH        use PATH; accepted only if it reports the pinned commit
#     --fetch                fetch (or take from --cache-dir) the pinned release archive; its sha256
#                            is checked on every use, the extracted binary's commit likewise
#     --cache-dir DIR        archive cache for --fetch (default ${XDG_CACHE_HOME:-~/.cache}/reth-pin)
#     --baseline-blocks N    stock-client control length (default 20; the 160-block run is local)
#     --inject-failure       fail deliberately after the scenarios, to exercise collection (#90)
#     --run-dir DIR          where this run's evidence goes (default evidence-runs/smoke-<id>)
#     --archive PATH         the evidence archive (default <run-dir>.tar.gz)
#
# Exit status: 0 only if every scenario passed, the evidence archive validated and teardown left no
# process of this run alive. Anything else is nonzero — including an injected failure.
#
# Local runs and the pinned artifact. Upstream v2.5.0 publishes release artifacts for linux-x86_64,
# linux-aarch64 and darwin-arm64 only; on any other host --fetch refuses and --reth-bin with a
# source build of the pinned commit is the supported path. The provenance record says which was used:
# an operator-supplied binary is verified by the revision it reports, not by a release digest.
#
# Teardown is by ownership, not by name. It kills the pids this run recorded under the nodes
# directory and any ubft/reth process whose working directory is this checkout — never every
# `reth node` on the host, which on a shared machine would include other people's clients. (The
# hosted workflow adds a broader sweep afterwards, which is safe only on a disposable runner.)

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repoRoot=$(pwd -P)
. scripts/lib/reth-pin.sh

usage() { sed -n '2,33p' "$0"; exit 2; }

# The option loop below shifts every argument away; the supervisor re-executes itself with the
# ORIGINAL arguments, so keep them.
origArgs=("$@")
rethBin= fetch=false cacheDir=${XDG_CACHE_HOME:-$HOME/.cache}/reth-pin baselineBlocks=20
injectFailure=false runDir= archive=
while [ $# -gt 0 ]; do
  case "$1" in
    --reth-bin) rethBin=${2:-}; shift 2 ;;
    --fetch) fetch=true; shift ;;
    --cache-dir) cacheDir=${2:-}; shift 2 ;;
    --baseline-blocks) baselineBlocks=${2:-}; shift 2 ;;
    --inject-failure) injectFailure=true; shift ;;
    --run-dir) runDir=${2:-}; shift 2 ;;
    --archive) archive=${2:-}; shift 2 ;;
    -h | --help) usage ;;
    *) echo "reth-smoke: unknown argument '$1'" >&2; usage ;;
  esac
done
if { [ -n "$rethBin" ] && $fetch; } || { [ -z "$rethBin" ] && ! $fetch; }; then
  echo "reth-smoke: exactly one of --reth-bin PATH or --fetch is required" >&2
  exit 2
fi

: "${RETH_SMOKE_RUN_ID:=$(date -u +%Y%m%dT%H%M%SZ)-$$}"
export RETH_SMOKE_RUN_ID
runDir=${runDir:-evidence-runs/smoke-$RETH_SMOKE_RUN_ID}
archive=${archive:-$runDir.tar.gz}
nodesDir=${RETH_SMOKE_NODES_DIR:-test-nodes}
binDir=$(dirname "$runDir")/.bin-$(basename "$runDir")

# ownedPids prints the pid of every ubft/reth process started from this checkout, plus every pid
# recorded under the nodes directory that is still alive.
ownedPids() {
  local p cwd f
  [ -n "${childPid:-}" ] && pgrep -g "$childPid" 2>/dev/null
  for f in "$nodesDir"/*/pid; do
    [ -f "$f" ] || continue
    p=$(cat "$f" 2>/dev/null)
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
  done
  for p in $(pgrep -f 'ubft (root-node|shard-node)|reth node' 2>/dev/null); do
    if [ -d "/proc/$p" ]; then
      cwd=$(readlink "/proc/$p/cwd" 2>/dev/null)
    else
      cwd=$(lsof -a -p "$p" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)
    fi
    [ "$cwd" = "$repoRoot" ] && echo "$p"
  done
}

# ======================================================================= supervisor ============
#
# The parent re-executes this script as a child that runs the scenarios, and itself only waits,
# collects, tears down and judges. Nothing the child does — an unset-variable abort, a SIGKILL, a
# hang interrupted by the operator — can skip collection, because collection is not the child's
# job. The same design as reth-chaos.sh, reviewed under #88.
if [ "${RETH_SMOKE_SUPERVISED:-0}" != "1" ]; then
  if [ -e "$runDir" ]; then
    echo "reth-smoke: refusing to start: $runDir already exists, and a run never writes into another run's evidence" >&2
    exit 2
  fi
  mkdir -p "$runDir" || exit 1
  prov=$runDir/provenance.txt
  {
    echo "lane=real-reth-smoke"
    echo "bft=$(git rev-parse HEAD 2>/dev/null) dirty=$(git status --porcelain --untracked-files=no 2>/dev/null | grep -q . && echo yes || echo no)"
    echo "invocation=$0 ${origArgs[*]}"
    echo "host=$(rethPinPlatform) date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [ -n "${GITHUB_RUN_ID:-}" ] && echo "workflow_run=${GITHUB_RUN_ID} attempt=${GITHUB_RUN_ATTEMPT:-} event=${GITHUB_EVENT_NAME:-}"
    [ -n "${RETH_SMOKE_TEST_SCENARIOS:-}" ] && echo "scenarios=SELF-TEST STUB — this archive is not real-execution evidence"
  } >"$prov"

  # The child gets its own process group (job control on, for this one launch), and teardown signals
  # the WHOLE group. Killing only the child's pid would orphan whatever it had started — the paired
  # devnet script, and the clients that script starts — which could go on starting clients after
  # teardown had finished. The self-test pins this with a process recorded nowhere.
  set -m
  RETH_SMOKE_SUPERVISED=1 "$0" "${origArgs[@]}" --run-dir "$runDir" --archive "$archive" &
  childPid=$!
  set +m
  interrupted=false
  trap 'interrupted=true; echo; echo "=== interrupted: stopping the run, then collecting ==="; kill -TERM -- "-$childPid" 2>/dev/null' INT TERM
  wait "$childPid"; childStatus=$?
  # wait returns early when a trapped signal arrives; wait again for the child itself.
  while kill -0 "$childPid" 2>/dev/null; do wait "$childPid"; childStatus=$?; done
  trap - INT TERM
  sleep 1 # let the child's log tee drain before the log is archived

  verdict=0
  say() { echo "$*"; echo "$*" >>"$runDir/run.log"; }
  say ""
  say "=== supervisor: collect, tear down, archive, validate (whatever happened to the run) ==="
  if $interrupted; then say "reth-smoke: FAIL run interrupted"; verdict=1; fi
  if [ ! -f "$runDir/.finished" ]; then
    say "reth-smoke: FAIL incomplete run — the scenario process ended (status $childStatus) without recording a result"
    verdict=1
  elif [ "$childStatus" -ne 0 ]; then
    say "reth-smoke: FAIL the run reported failure (status $childStatus)"
    verdict=1
  fi

  say "$(rethEvidenceCollect "$nodesDir" "$runDir/nodes")"

  # Teardown by ownership, then verify it: a lane that leaves clients running holds ports and
  # datadirs the next run will trip over, and on a shared host belongs to somebody else's session.
  # First the run's own process group, then anything recorded or started from this checkout. Both
  # are counted separately: reporting only the sweep once said "0 stopped" for a cancelled run in
  # which the group signal had just stopped eleven processes.
  grouped=$(pgrep -g "$childPid" 2>/dev/null | wc -l | tr -d ' ')
  kill -TERM -- "-$childPid" 2>/dev/null
  for _ in $(seq 1 20); do pgrep -g "$childPid" >/dev/null 2>&1 || break; sleep 0.5; done
  kill -KILL -- "-$childPid" 2>/dev/null
  owned=$(ownedPids | sort -u)
  [ -n "$owned" ] && kill $owned 2>/dev/null
  for _ in $(seq 1 20); do
    left=$(for p in $owned; do kill -0 "$p" 2>/dev/null && echo "$p"; done)
    [ -z "$left" ] && break
    sleep 0.5
  done
  [ -n "$left" ] && kill -KILL $left 2>/dev/null && sleep 1
  left=$(ownedPids | sort -u)
  if [ -n "$left" ]; then
    say "reth-smoke: FAIL teardown left process(es) of this run alive: $(echo $left)"
    verdict=1
  else
    say "reth-smoke: teardown complete — $grouped process(es) still in the run's group when it was signalled, $(echo $owned | wc -w | tr -d ' ') more stopped by the ownership sweep, none of this run left"
  fi
  rm -rf "$binDir"

  echo "child_status=$childStatus supervisor_verdict_before_archive=$verdict" >>"$prov"
  minLogs=0
  [ -f "$runDir/.scenarios-started" ] && minLogs=1
  rm -f "$runDir/.finished" "$runDir/.scenarios-started"
  mkdir -p "$(dirname "$archive")"
  if tar czf "$archive" -C "$(dirname "$runDir")" "$(basename "$runDir")" 2>/dev/null; then
    rethEvidenceValidate "$archive" "$nodesDir" "$minLogs" provenance.txt run.log || verdict=1
  else
    echo "reth-smoke: FAIL the evidence archive could not be written; the evidence is only in $runDir"
    verdict=1
  fi

  if [ "$verdict" -eq 0 ]; then
    echo "reth-smoke: PASS — evidence $archive"
  else
    echo "reth-smoke: FAIL — evidence $archive"
  fi
  exit $verdict
fi

# ======================================================================= the run ===============
exec > >(tee -a "$runDir/run.log") 2>&1
export RETH_SMOKE_CHILD_PID=$$
prov=$runDir/provenance.txt
failures=0
step() { echo; echo "=== $* ==="; }

step "obtain and verify the pinned execution client"
mkdir -p "$binDir"
if $fetch; then
  if rethPinObtainPinned "$cacheDir" "$binDir"; then
    echo "reth=$RETH_PIN_COMMIT source=release-artifact asset=$RETH_PIN_ASSET sha256=$RETH_PIN_SHA256 cache=$RETH_PIN_CACHE_STATE" >>"$prov"
  else
    echo "reth=REFUSED source=release-artifact" >>"$prov"
    echo "reth-smoke: the pinned client could not be obtained; no scenario runs without it"
    touch "$runDir/.finished"; exit 1
  fi
else
  if rethPinVerifyBinary "$rethBin"; then
    abs=$(cd "$(dirname "$rethBin")" && pwd -P)/$(basename "$rethBin")
    ln -sf "$abs" "$binDir/reth"
    echo "reth=$RETH_PIN_COMMIT source=operator-binary path=$abs sha256=$(rethPinSha256 "$abs") (verified by reported revision, not by a release digest)" >>"$prov"
  else
    echo "reth=REFUSED source=operator-binary path=$rethBin" >>"$prov"
    echo "reth-smoke: the supplied binary is not the pinned client; no scenario runs without it"
    touch "$runDir/.finished"; exit 1
  fi
fi
PATH="$(cd "$binDir" && pwd -P):$PATH"
export PATH
if [ "$(command -v reth)" != "$(cd "$binDir" && pwd -P)/reth" ]; then
  echo "reth-smoke: 'reth' on PATH is $(command -v reth), not the verified binary"
  touch "$runDir/.finished"; exit 1
fi

touch "$runDir/.scenarios-started"
if [ -n "${RETH_SMOKE_TEST_SCENARIOS:-}" ]; then
  # Test-only: scripts/reth-smoke-selftest.sh substitutes a stub for the scenarios so the supervisor
  # can be exercised without reth. The provenance record marks such an archive as not evidence.
  step "SELF-TEST STUB scenarios"
  NODES=$nodesDir bash -c "$RETH_SMOKE_TEST_SCENARIOS" || failures=$((failures + 1))
else
  step "stock-client control (reth-baseline, $baselineBlocks blocks)"
  if ./setup-evm-nodes.sh -r 3 -v 4 >"$runDir/setup-evm-nodes.log" 2>&1 && ./scripts/reth-baseline.sh "$baselineBlocks"; then
    echo "reth-smoke: stock-client control passed"
  else
    echo "reth-smoke: stock-client control FAILED"; failures=$((failures + 1))
  fi
  step "paired real-reth devnet (4 validators, funded transaction)"
  if ./scripts/reth-paired-devnet.sh 4 5; then
    echo "reth-smoke: paired devnet passed"
  else
    echo "reth-smoke: paired devnet FAILED"; failures=$((failures + 1))
  fi
fi

if $injectFailure; then
  step "INJECTED FAILURE"
  echo "reth-smoke: INJECTED FAILURE requested with --inject-failure, to exercise evidence collection"
  failures=$((failures + 1))
fi

echo
echo "reth-smoke: scenario failures: $failures"
touch "$runDir/.finished"
[ "$failures" -eq 0 ]
