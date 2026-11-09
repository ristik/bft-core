#!/bin/bash
# root-scale-lane.sh - N distinct root nodes (one key, one home, real libp2p TCP on loopback) and one real
# fake-executor shard of 4 validators, on one machine. Stages: baseline, restart/rejoin, and the two quorum controls:
#   live = quorum   (N - (N - quorum) down)  -> the shard must keep certifying
#   live = quorum-1 (one more down)          -> certification must stall, roots still up
#   restart the last stopped root            -> certification must resume (control validity)
# Design: briefs/dev2-128-root-experiment-design.md (§49). N=128: quorum 86, 42 down / 43 down. N=16: quorum 11, 5 / 6.
# A same-host functional smoke, not a WAN, Byzantine or performance guarantee ("single server, one operator").
#
# Run from the repository root (helper.sh's ownership checks require the checkout as cwd). Stops only pids it recorded.
# Host lock (briefs/host-test-plan-2026-11-02.md): -L <lockDir> (e.g. ~/host-lock) makes the driver take <lockDir>/<name>-root-scale itself, refuse when
# anyone else holds a file there, and release it on every exit. A run on a shared host MUST pass -L; without it the driver warns.
# -P secs: how long the quorum-live progress control may take (default 180); -R secs: resume wait (240); -C secs: during that control, CPU-profile
#   root1 with `sudo perf record -g -p <its pid>` for that long (Linux, sudo needed: perf_event_paranoid=4) and write the top symbols and the share of
#   signature-verification symbols to the evidence; per-root CPU (utime+stime ticks) is always sampled in cpu-per-root.csv during that control.
# Usage: scripts/root-scale-lane.sh [-r roots] [-v validators] [-e evidenceDir] [-s seed] [-w windowSeconds] [-k keep] [-S samplerSeconds] [-L lockDir] [-N holderName]
set +u
roots=16 validators=4 partition_id=8 evidence="" seed=1 window=60 keep=false sample=5 lockdir="" tmpdir="" holder=${USER:-run} progwait=180 resumewait=240 perfsecs=0
while getopts "hr:v:e:s:w:kS:L:N:P:R:C:T:" o; do
  case "$o" in
  r) roots=$OPTARG ;; v) validators=$OPTARG ;; e) evidence=$OPTARG ;; s) seed=$OPTARG ;;
  w) window=$OPTARG ;; k) keep=true ;; S) sample=$OPTARG ;; L) lockdir=$OPTARG ;; N) holder=$OPTARG ;; P) progwait=$OPTARG ;; R) resumewait=$OPTARG ;; C) perfsecs=$OPTARG ;; T) tmpdir=$OPTARG ;;
  *) sed -n 1,14p "$0"; exit 0 ;;
  esac
done
[ -f helper.sh ] && [ -x build/ubft ] || { echo "run from the repo root with build/ubft built" >&2; exit 2; }
[ "$roots" -ge 4 ] || { echo "need >= 4 roots" >&2; exit 2; }
ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
echo "file descriptor limit: $(ulimit -n)"
[ -n "$evidence" ] || evidence="$HOME/evidence/49-root-scale-$(date -u +%Y%m%d-%H%M)"
mkdir -p "$evidence" || exit 2

pass() { echo "  PASS: $1" | tee -a "$evidence/result.txt"; }
failures=0
fail() { echo "  FAIL: $1" | tee -a "$evidence/result.txt" >&2; failures=$((failures + 1)); }

quorum=$((roots * 2 / 3 + 1))
maxdown=$((roots - quorum))
echo "roots=$roots quorum=$quorum progress with $maxdown down, stall with $((maxdown + 1)) down, seed=$seed" | tee "$evidence/params.txt"

# The host lock comes first: nothing below (sourcing, rm -rf test-nodes, starting processes) happens unless we hold it.
SAMPLER="" mylock=""
cleanup() {
  [ -z "$SAMPLER" ] || kill "$SAMPLER" 2>/dev/null
  if [ "$keep" != true ]; then
    declare -F stop_evm_validators >/dev/null && stop_evm_validators
    declare -F stop_root_nodes >/dev/null && stop_root_nodes
    [ -z "${tmpcleanup:-}" ] || { rm -rf "$tmpcleanup"; rm -f test-nodes; }
  [ -z "$mylock" ] || { rm -f "$mylock"; echo "host lock released: $mylock"; }
  elif [ -n "$mylock" ]; then
    echo "-k: roots and shard keep running, so the host lock stays: $mylock (remove it after stopping them)"
  fi
}
trap cleanup EXIT
if [ -n "$lockdir" ]; then
  mkdir -p "$lockdir"
  [ -z "$(ls -A "$lockdir")" ] || { echo "STOP: host lock is held by: $(ls -A "$lockdir" | tr '\n' ' ')" >&2; trap - EXIT; exit 1; }
  mylock="$lockdir/$holder-root-scale"
  # noclobber: never overwrite a file somebody else created in the gap; then re-check that we are the only holder
  if ! ( set -C; printf 'name=%s\ngeneration=root-scale-%s\npurpose=bft-core root-scale-lane %s roots (single server, one operator)\nstart=%s\n' "$holder" "$roots" "$roots" "$(date -u +%FT%TZ)" >"$mylock" ) 2>/dev/null; then
    echo "STOP: could not create $mylock (exists)" >&2; mylock=""; trap - EXIT; exit 1
  fi
  if [ "$(ls -A "$lockdir" | wc -l | tr -d ' ')" != 1 ]; then
    echo "STOP: another holder appeared while taking the lock: $(ls -A "$lockdir" | tr '\n' ' ')" >&2; rm -f "$mylock"; mylock=""; trap - EXIT; exit 1
  fi
  echo "host lock taken: $mylock"
else
  echo "WARNING: no -L lockDir: this run holds no host lock; use it on a shared host only under a lock taken by hand" >&2
fi

source helper.sh
export ROOT_LOG_LEVEL=info ROOT_DEBUG_ROOTS="${ROOT_DEBUG_ROOTS:-1}"   # root1 at debug: its per-round leader lines show where dead leaders fall
rm -rf test-nodes
if [ -n "$tmpdir" ]; then
  # measurement control (-T <dir on tmpfs>): every node's data directory and log lives on that memory-backed directory, so no node writes to the disk;
  # test-nodes is a symlink to it. Not a configuration: the data does not survive the run.
  rm -rf "$tmpdir/test-nodes" && mkdir -p "$tmpdir/test-nodes" && ln -s "$tmpdir/test-nodes" test-nodes
  tmpcleanup="$tmpdir/test-nodes"
else
  mkdir test-nodes
fi

# --- setup --------------------------------------------------------------------------------------
t0=$(date +%s)
init_root_nodes "$roots" >"$evidence/setup.log" 2>&1 || { echo "init failed, see $evidence/setup.log" >&2; exit 1; }
init_evm_validators "$validators" >>"$evidence/setup.log" 2>&1
generate_evm_shard_conf "$validators" "$partition_id" 31337 5000 exec >>"$evidence/setup.log" 2>&1 || exit 1
generate_log_configuration "test-nodes/*/" >>"$evidence/setup.log" 2>&1
echo "setup $(( $(date +%s) - t0 )) s"
for i in $(seq 1 "$roots"); do id=$(build/ubft node-id --home "test-nodes/root$i" | tail -n1); echo "$i,$id,16*${id: -6}"; done >"$evidence/node-ids.csv"
tbq=$(grep -o '"quorumThreshold": *[0-9]*' test-nodes/trust-base.json | grep -o '[0-9]*$')
if [ "${tbq:-}" = "$quorum" ]; then pass "trust base quorumThreshold = $quorum"; else fail "trust base quorumThreshold=${tbq:-?}, expected $quorum"; fi

# --- sampler: per-interval resource record of the roots (pids from our own pid files) -------------
threads_of() { if [ -r "/proc/$1/status" ]; then awk '/^Threads:/{print $2}' "/proc/$1/status"; else ps -M -p "$1" 2>/dev/null | tail -n +2 | wc -l | tr -d ' '; fi; }
snapshot() {
  local live=0 rss=0 maxrss=0 thr=0 f p r
  for f in test-nodes/root*/pid; do
    p=$(cat "$f" 2>/dev/null) || continue
    kill -0 "$p" 2>/dev/null || continue
    live=$((live + 1))
    r=$(ps -o rss= -p "$p" 2>/dev/null | tr -d ' '); r=${r:-0}
    rss=$((rss + r)); [ "$r" -le "$maxrss" ] || maxrss=$r
    thr=$((thr + $(threads_of "$p")))
  done
  echo "$(date -u +%H:%M:%S),$live,$rss,$maxrss,$thr,$(uptime | sed 's/.*load average[s]*: //')"
}
echo "time,liveRoots,rssKBsum,rssKBmax,threads,load" >"$evidence/samples.csv"
( while true; do snapshot >>"$evidence/samples.csv"; sleep "$sample"; done ) &
SAMPLER=$!

# --- start roots / shard ------------------------------------------------------------------------
echo -n "starting $roots root nodes..."
start_root_nodes >"$evidence/start-roots.log" 2>&1 || { echo "root start failed, see $evidence/start-roots.log" >&2; exit 1; }
echo " done ($(( $(date +%s) - t0 )) s since setup began)"
snapshot | tee "$evidence/after-start.csv"
wait_for_root_chain_settle
rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
start_evm_validators "$validators" "$partition_id" "$rootBoot" fake rpc

latest_round() { local r; r=$(grep -o 'partitionRound=[0-9]*' "test-nodes/evm$1/debug.log" 2>/dev/null | tail -1 | cut -d= -f2); echo "${r:-0}"; }
# max over all validators: rounds are certified shard-wide, any validator logging a higher round is progress
shard_round() { local m=0 i r; for i in $(seq 1 "$validators"); do r=$(latest_round "$i"); [ "$r" -le "$m" ] || m=$r; done; echo "$m"; }
wait_rounds() { # wait_rounds <rounds above current> <timeout s>: success if the shard advances by that many
  local want=$(( $(shard_round) + $1 )) w=0
  while [ "$(shard_round)" -lt "$want" ]; do [ "$w" -lt "$2" ] || return 1; sleep 1; w=$((w + 1)); done
}
rpc_up() { # root index: its RPC port is listening
  local port=$((25866 + $1 - 1)); (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
}
stop_root() { stop_pidfile "test-nodes/root$1/pid" 'ubft root-node' TERM; }
start_root() {
  local i=$1
  UBFT_Q4_SHIM_DIR="" build/ubft root-node run --home "test-nodes/root$i" --address "/ip4/127.0.0.1/tcp/$((rootPortStart + i - 1))" \
    --bootnodes="$rootBoot" --trust-base test-nodes/trust-base.json --rpc-server-address "127.0.0.1:$((25866 + i - 1))" \
    --log-format text --log-level info --metrics prometheus >>"test-nodes/root$i/debug.log" 2>&1 &
  echo $! >"test-nodes/root$i/pid"
}

echo "=== baseline: all $roots roots live ==="
if wait_rounds 3 180; then pass "shard certifies with $roots live roots (round $(shard_round))"; else fail "shard never advanced with all roots live"; snapshot; fi
r0=$(shard_round); sleep "$window"; r1=$(shard_round)
echo "baseline: $((r1 - r0)) rounds in ${window}s" | tee "$evidence/baseline.txt"
[ "$r1" -gt "$r0" ] && pass "baseline window: $((r1 - r0)) rounds in ${window}s" || fail "no rounds in the baseline window"
snapshot | tee "$evidence/baseline-resources.csv"

echo "=== restart/rejoin: one root ==="
# a root that is not root1 (the bootnode of the others); chosen by seed
pick() { # pick <count> <exclude-list>: seeded choice of distinct roots among 2..N
  python3 - "$roots" "$1" "$seed" "${2:-}" <<'PY'
import random, sys
n, k, seed = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
ex = {int(x) for x in sys.argv[4].split() if x}
pool = [i for i in range(2, n + 1) if i not in ex]
random.Random(seed).shuffle(pool)
print(" ".join(map(str, pool[:k])))
PY
}
one=$(pick 1)
stop_root "$one"; sleep 2
if wait_rounds 3 90; then pass "certification continues with root$one down"; else fail "stalled with a single root down"; fi
start_root "$one"; sleep 5
rpc_up "$one" && pass "root$one restarted and listening" || fail "root$one did not listen after restart"
wait_rounds 3 90 && pass "certification continues after root$one rejoined" || fail "no progress after root$one rejoined"

echo "=== control: $quorum live ($maxdown down) must progress ==="
event() { echo "$(date -u +%FT%TZ) $*" >>"$evidence/events.txt"; }
event "progress control: stopping $maxdown roots"
downs=$(pick $((maxdown + 1)) "")   # one spare, used for the stall control
echo "down set (seed $seed, in stop order): $downs" | tee "$evidence/down-set.txt"
n=0; last=""
for d in $downs; do
  [ "$n" -lt "$maxdown" ] || break
  stop_root "$d"; n=$((n + 1)); last=$d
done
spare=$(echo "$downs" | awk '{print $NF}')
sleep 5
event "progress control: $maxdown roots stopped, waiting for $progwait s at most"
echo "live roots now: $(snapshot | cut -d, -f2)"
cpu_ticks() { # utime+stime ticks of every live root, one "root,ticks" line each
  local f i p
  for f in test-nodes/root*/pid; do
    i=${f#test-nodes/root}; i=${i%/pid}; p=$(cat "$f" 2>/dev/null) || continue
    [ -r "/proc/$p/stat" ] || continue
    awk -v i="$i" '{sub(/^.*\) /, ""); print i "," $12 + $13}' "/proc/$p/stat"
  done
}
timeline="$evidence/progress-timeline.csv"; echo "time,shardRound,liveRoots" >"$timeline"
pc0=$(mktemp); pc1=$(mktemp); cpu_ticks >"$pc0"; ct0=$(date +%s)
if [ "$perfsecs" -gt 0 ] && command -v perf >/dev/null 2>&1; then
  rp=$(cat test-nodes/root1/pid)
  ( sleep 20; sudo perf record -F 99 -g -p "$rp" -o "$evidence/perf-root1.data" -- sleep "$perfsecs" >"$evidence/perf-record.log" 2>&1
    sudo perf report -i "$evidence/perf-root1.data" --stdio --no-children --sort symbol -g none 2>/dev/null | grep -v '^#' | grep -v '^$' | head -80 >"$evidence/perf-root1-top.txt"
    sudo chown "$(id -u):$(id -g)" "$evidence/perf-root1.data" 2>/dev/null || true ) &   # the raw data is root-owned: keep evidence cleanup unprivileged
  PERFJOB=$!
fi
progressed=0; w=0; want=$(( $(shard_round) + 5 ))
while [ "$w" -lt "$progwait" ]; do
  if [ $((w % 15)) -eq 0 ]; then echo "$(date -u +%T),$(shard_round),$(snapshot | cut -d, -f2)" >>"$timeline"; fi
  [ "$(shard_round)" -lt "$want" ] || { progressed=1; break; }
  sleep 1; w=$((w + 1))
done
ct1=$(date +%s); cpu_ticks >"$pc1"
tck=$(getconf CLK_TCK 2>/dev/null || echo 100)
join -t, <(sort -t, -k1,1 "$pc0") <(sort -t, -k1,1 "$pc1") | awk -F, -v dt=$((ct1 - ct0)) -v tck="$tck" 'BEGIN{print "root,cpu_percent_of_one_core"} {printf "%s,%.1f\n",$1,($3-$2)/tck/dt*100}' >"$evidence/cpu-per-root.csv"
rm -f "$pc0" "$pc1"
[ -z "${PERFJOB:-}" ] || wait "$PERFJOB" 2>/dev/null
if [ -s "$evidence/perf-root1-top.txt" ]; then
  awk '{p=$1; sub(/%/,"",p); tot+=p; if (tolower($0) ~ /verif|secp|ecdsa|schnorr|btcec|ecmult/) v+=p} END{printf "root1 perf: %.1f%% of samples in signature-verification symbols (sum over the top 80 symbols covering %.1f%%)\n", v, tot}' "$evidence/perf-root1-top.txt" | tee "$evidence/perf-verify-share.txt"
fi
echo "progress control took ${w} s, progressed=$progressed" | tee "$evidence/control-progress-time.txt"
if [ "$progressed" = 1 ]; then pass "$quorum live / $maxdown down: shard progressed to round $(shard_round) in ${w} s"; else fail "$quorum live / $maxdown down: no progress in ${progwait} s"; fi
snapshot | tee "$evidence/control-progress-resources.csv"

echo "=== control: $((quorum - 1)) live ($((maxdown + 1)) down) must stall ==="
event "stall control: stopping one more root ($spare)"; stop_root "$spare"; sleep 20          # let in-flight rounds drain
s0=$(shard_round); sleep "$window"; s1=$(shard_round)
echo "stall window: round $s0 -> $s1 over ${window}s with live roots $(snapshot | cut -d, -f2)" | tee "$evidence/control-stall.txt"
if [ "$s1" -eq "$s0" ]; then pass "$((quorum - 1)) live / $((maxdown + 1)) down: no new certification in ${window}s (stall)"; else fail "$((quorum - 1)) live: shard advanced $s0 -> $s1 (no stall; control invalid)"; fi
live_after=$(snapshot | cut -d, -f2)
[ "$live_after" -eq $((quorum - 1)) ] && pass "stall control: the $live_after live roots are all still running (not crashed)" || fail "expected $((quorum - 1)) live roots, found $live_after"

echo "=== restart one root: progress must resume (control validity) ==="
event "resume: restarting root$spare"; start_root "$spare"
if wait_rounds 5 "$resumewait"; then pass "quorum restored ($quorum live): certification resumed (round $(shard_round))"; else fail "no resume after restoring quorum"; fi

echo "=== evidence ==="
event "end"
# the consensus loop's per-message-type time (root1 and every other root) and root1's per-round leader lines (root1 runs at debug)
grep -h "consensus loop\|consensus proposal phase\|consensus storage write" test-nodes/root*/debug.log 2>/dev/null | gzip >"$evidence/loop-profile-all-roots.log.gz"
grep -h "next leader\|local timeout\|timeout quorum" test-nodes/root1/debug.log 2>/dev/null | gzip >"$evidence/root1-rounds.log.gz"
for i in $(seq 1 "$roots"); do
  grep -ciE 'panic|fatal error|SIGABRT|pthread_create' "test-nodes/root$i/debug.log" 2>/dev/null | sed "s/^/root$i,/"
done | awk -F, '$2>0' >"$evidence/abort-lines.txt"
[ ! -s "$evidence/abort-lines.txt" ] && pass "no root logged panic/fatal/abort lines" || fail "abort lines in $(wc -l <"$evidence/abort-lines.txt") root logs (abort-lines.txt)"
for k in "queue" "deadline" "timeout" "dropped"; do
  printf '%s,%s\n' "$k" "$(cat test-nodes/root*/debug.log | grep -ci "$k")"
done >"$evidence/log-word-counts.csv"
snapshot >"$evidence/final-resources.csv"
mkdir -p "$evidence/logs"; for i in 1 2 "$one" "$spare"; do tail -n 2000 "test-nodes/root$i/debug.log" | gzip >"$evidence/logs/root$i.tail.log.gz"; done
for i in $(seq 1 "$validators"); do tail -n 2000 "test-nodes/evm$i/debug.log" | gzip >"$evidence/logs/evm$i.tail.log.gz"; done
echo "failures: $failures (evidence: $evidence)"
[ "$failures" -eq 0 ]
