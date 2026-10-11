# Sourced by reth-paired-devnet.sh (Q4_LIVE_LANE=1, F8_MIXED_LANE=1, M2_PROFILE2=1) after the first paid certified block and the F8
# aggregator start, in place of the handoff script. Q4 #51 (B) REAL-PROCESS representatives of the weighted fault matrix, driven through
# the per-peer root shim (build/q4shim/ubft, make build-q4shim) and the F8 callbacks (f8_trace, f8_slow_stop_resume_evm,
# f8_inflight_evm_probe). Coverage label of every step: REAL-PROCESS root + EVM + three aggregator shards; crash model SIGKILL with the
# retained home (not a power loss). Every step prints PASS or FAIL; the first FAIL tears the lane down and exits nonzero.
#
# GATE: the rows are weighted-epoch rows. They run only when the lane's chain is in an activated weighted epoch (Q3 coupled activation,
# scheme 2, root-wrr-v1); Q4_WEIGHTED_CHECK is a command that exits 0 exactly then (the Q3 lane supplies it; it prints the active
# epoch's weights). Without it the lane stops BLOCKED (exit 3) before any fault, never as a pass on a unit-weight chain.
# The activation prefix is the Q3 flow library's: the same fresh-B1 unit PoA -> one coupled handoff to mirrored weights 6,1,1,1 that scripts/q3-weight-activation-steps.sh
# runs (candidate, readiness receipts from every entity, propose, install, activation record, authority advance, scheme 2 progress), so the weighted epoch the Q4 rows
# run in is established by exactly the flow whose evidence closed Q3, in this same devnet.
# The scenario picks the activated committee (the Q3 flow's mirrored weights, root i = entity i, W=9, Q=7, F=2): A (6,1,1,1) or B (3,3,2,1). The four-entity paired devnet
# is the only topology the Q3 flow builds, so the many-small (18,1x9) and the #399 outage control (3,2,2,2,2) committees are not live scenarios.
Q4_SCENARIO=${Q4_SCENARIO:-A}
# Q4_HEAVY_AT=k (scenario A only, k=2..4) places the weight-6 identity on root k instead of root 1 (F1: every heavy placement); such a run is a placement run
# and carries the placement rows only.
Q4_HEAVY_AT=${Q4_HEAVY_AT:-1}
case "$Q4_SCENARIO/$Q4_HEAVY_AT" in
  A/1) Q3_WEIGHTS="6 1 1 1"; Q4_HEAVY_ROOTS="1" ;;
  A/2) Q3_WEIGHTS="1 6 1 1"; Q4_HEAVY_ROOTS="2" ;;
  A/3) Q3_WEIGHTS="1 1 6 1"; Q4_HEAVY_ROOTS="3" ;;
  A/4) Q3_WEIGHTS="1 1 1 6"; Q4_HEAVY_ROOTS="4" ;;
  B/1) Q3_WEIGHTS="3 3 2 1"; Q4_HEAVY_ROOTS="1 2" ;;
  *) echo "Q4_SCENARIO must be A (Q4_HEAVY_AT 1..4) or B (Q4_HEAVY_AT 1), not $Q4_SCENARIO/$Q4_HEAVY_AT" >&2; return 2 2>/dev/null || exit 2 ;;
esac
export Q3_WEIGHTS Q4_SCENARIO
export Q3_LANE_DEFINE_ONLY=1
source scripts/q3-weight-activation-steps.sh
unset Q3_LANE_DEFINE_ONLY
source scripts/lib/q4-lib.sh
# the joiner helpers of the H3/T6 lanes (h3_q3_trust_base, h3_q3_start_joiner, h3_q3_joiner_shard_restore, h3_q3_wait_joiner) for the turnover.
# That library also defines the H3 flavour of q3_build_assignment (unit weights); the Q3 lane's weighted one stays the lane's.
eval "$(declare -f q3_build_assignment | sed '1s/^q3_build_assignment/q4_q3_build_assignment_weighted/')"
source scripts/lib/h3-q3-lib.sh
eval "$(declare -f q4_q3_build_assignment_weighted | sed '1s/^q4_q3_build_assignment_weighted/q3_build_assignment/')"
# the validators that are up are the lane's H3_ONLINE (the library's fixed 1..4 names a stopped validator and omits the joiner under the turnover)
m2_online_validators() { echo "${H3_ONLINE:-1 2 3 4}"; }

Q4_DIR=test-nodes/q4
Q4_ROOTS=${Q4_ROOTS:-"1 2 3 4"}
Q4_HEAVY_ROOT=${Q4_HEAVY_ROOT:-${Q4_HEAVY_ROOTS%% *}}   # A: the weight-6 root of 6,1,1,1; B: the first weight-3 root of 3,3,2,1 (Q4_HEAVY_ROOTS lists them all)
q4_is_heavy() { case " $Q4_HEAVY_ROOTS " in *" $1 "*) return 0 ;; esac; return 1; }
Q4_EPOCH=${Q4_EPOCH:-2}   # the installed epoch the Q3 flow activates, for restarts (--install-handoff-epoch)
Q4_STALL_SECONDS=${Q4_STALL_SECONDS:-20}
Q4_RECOVER_SECONDS=${Q4_RECOVER_SECONDS:-120}   # frozen before the run; never widened after a stall
q4_lights() { local r; for r in $Q4_ROOTS; do q4_is_heavy "$r" || echo "$r"; done; }
q4_without() { local r x skip; for r in $Q4_ROOTS; do skip=0; for x in "$@"; do [ "$x" = "$r" ] && skip=1; done; [ "$skip" = 1 ] || echo "$r"; done; }

q4_pass() { echo "  PASS: $*"; }
q4_teardown() {
  local p
  for p in $(owned_pids 'ubft root-node run|ubft shard-node (run|restore)|ubft signing-authority run|reth.* node|aggregator'); do kill -INT "$p" 2>/dev/null; done
  return 0
}
q4_die() { echo "  FAIL: $*" >&2; q4_teardown; exit 1; }
# Q4_DEV_RETRY=1 (development only, never evidence): a failed step does not tear the devnet down at once. The lane waits up to Q4_DEV_RETRY_SECONDS
# (default 900) for test-nodes/q4/retry (re-source this file, so an edited step is picked up, and run the step again on the kept chain) or
# test-nodes/q4/abort. The lane's own state survives the re-source. One lock slot then serves several fixes of the same step.
# A step that restarts processes (q4_first_successor_held) is not the same experiment on its second pass: its retry tells whether the fix parses and
# gets further, not what a first pass would have shown.
q4_dev_retry() {
  [ "${Q4_DEV_RETRY:-0}" = 1 ] || return 1
  local i w=$Q3_WEIGHTS w1=${Q3_WEIGHTS_1:-} e=${Q4_EPOCH:-} hs=$Q4_HEAVY_ROOTS h=$Q4_HEAVY_ROOT hr=$H3_ROOTS qr=$Q4_ROOTS ents=${Q3_ENTITIES:-} dir=$Q4_DIR
  echo "DEVELOPMENT (NOT EVIDENCE): step failed, devnet kept: touch $Q4_DIR/retry to re-source the steps and run it again, $Q4_DIR/abort to stop (${Q4_DEV_RETRY_SECONDS:-900}s)"
  rm -f "${Q4_DIR:?}/retry" "${Q4_DIR:?}/abort"
  for i in $(seq 1 "${Q4_DEV_RETRY_SECONDS:-900}"); do
    [ ! -f "$Q4_DIR/abort" ] || return 1
    if [ -f "$Q4_DIR/retry" ]; then
      rm -f "${Q4_DIR:?}/retry"
      Q4_LANE_DEFINE_ONLY=1 source scripts/q4-live-steps.sh || return 1
      Q3_WEIGHTS=$w; Q3_WEIGHTS_1=$w1; Q4_EPOCH=$e; Q4_HEAVY_ROOTS=$hs; Q4_HEAVY_ROOT=$h; H3_ROOTS=$hr; Q4_ROOTS=$qr; Q4_DIR=$dir
      if [ -n "$ents" ]; then Q3_ENTITIES=$ents; else unset Q3_ENTITIES; fi
      echo "DEVELOPMENT: steps re-sourced; running the step again"
      return 0
    fi
    sleep 1
  done
  echo "DEVELOPMENT: no retry within ${Q4_DEV_RETRY_SECONDS:-900}s" >&2
  return 1
}
q4_step() { local name=$1; shift; Q4_CUR_STEP=$name; echo "--- Q4 step: $name"; until "$@"; do echo "  step failed: $name" >&2; q4_dev_retry || q4_die "$name"; done; q4_pass "$name"; }

q4_round() { curl -fsS "http://127.0.0.1:$(m2_rpc_port "$1")/api/v1/roundInfo" | jq -r '.roundNumber'; }
# the certified IR round of the EVM shard (partition 8): moves only when a block is certified, never by a timeout certificate alone
q4_evm_ir() { curl -fsS "http://127.0.0.1:$(m2_rpc_port "${1:-1}")/api/v1/roundInfo" | jq -r '.partitionShards[] | select(.partitionId==8) | .roundNumber'; }
q4_evm_tr() { curl -fsS "http://127.0.0.1:$(m2_rpc_port "${1:-1}")/api/v1/roundInfo" | jq -r '.partitionShards[] | select(.partitionId==8) | .trRound'; }

# ---- timing (design v2 section 4, last paragraph): every progress assertion is polled every 0.25 s and its latencies are exported as numbers to
# q4/timing.jsonl: the time to the first and to the n-th (third) increment after the assertion starts, the largest gap between two increments, and the
# timeout certificates the observing root formed in the window. kind root-commit is the roots' committed round, evm-commit the EVM certified IR round
# (its first increment after a release or restart is the EVM recovery latency), control the no-fault window at the same load. The deadline
# (Q4_RECOVER_SECONDS) is frozen before the run.
q4_t() { if [ -n "${EPOCHREALTIME:-}" ]; then printf '%s\n' "${EPOCHREALTIME/,/.}"; else python3 -c 'import time; print("%.6f" % time.time())'; fi; }
q4_dt() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", a - b }'; }
q4_tc_mark() { wc -l <"test-nodes/root$1/debug.log" | tr -d ' '; }
q4_tc_since() { tail -n +"$(($2 + 1))" "test-nodes/root$1/debug.log" | grep -ac 'timeout quorum for round' || true; }
q4_timing() {
  python3 - "$Q4_DIR/timing.jsonl" "${Q4_CUR_STEP:-}" "$@" <<'PY2'
import json, sys
path, step, kind, *kv = sys.argv[1:]
rec = {"step": step, "kind": kind}
for x in kv:
    k, v = x.split("=", 1)
    try:
        rec[k] = float(v) if "." in v else int(v)
    except ValueError:
        rec[k] = v
open(path, "a").write(json.dumps(rec, sort_keys=True) + "\n")
PY2
}

# q4_progress_timed <kind> <reader> <root> <limit s> <n>: the reader's value (read at the root) rose by at least n within the frozen limit
q4_progress_timed() {
  local kind=$1 reader=$2 root=$3 limit=$4 n=$5 base now prev t0 t tlast first=- nth=- gap=0 g mark
  base=$($reader "$root") || return 1
  prev=$base; t0=$(q4_t); tlast=$t0; mark=$(q4_tc_mark "$root")
  while :; do
    now=$($reader "$root") || return 1
    t=$(q4_t)
    if [ "$now" -gt "$prev" ]; then
      if [ "$first" = - ]; then first=$(q4_dt "$t" "$t0"); else g=$(q4_dt "$t" "$tlast"); gap=$(awk -v a="$g" -v b="$gap" 'BEGIN { print (a > b) ? a : b }'); fi
      prev=$now; tlast=$t
    fi
    if [ $((now - base)) -ge "$n" ]; then
      nth=$(q4_dt "$t" "$t0")
      q4_timing "$kind" root="$root" from="$base" to="$now" n="$n" first_s="$first" nth_s="$nth" max_gap_s="$gap" tc="$(q4_tc_since "$root" "$mark")" deadline_s="$limit" ok=true
      echo "root$root $kind $base -> $now: first after ${first}s, +$n after ${nth}s, max gap ${gap}s (deadline ${limit}s)"
      return 0
    fi
    if awk -v a="$(q4_dt "$t" "$t0")" -v b="$limit" 'BEGIN { exit !(a >= b) }'; then
      q4_timing "$kind" root="$root" from="$base" to="$now" n="$n" first_s="$first" deadline_s="$limit" tc="$(q4_tc_since "$root" "$mark")" ok=false
      echo "root$root $kind stayed at $now (from $base) for ${limit}s" >&2
      return 1
    fi
    sleep 0.25
  done
}

# q4_commits_advance <root> <seconds> <n>: the EVM certified IR round rose by at least n within the window
q4_commits_advance() { q4_progress_timed evm-commit q4_evm_ir "$1" "$2" "$3"; }

# q4_stalled <root> <seconds>: no certified commit, no QC-driven progress: the EVM IR round is constant for the window
q4_stalled() {
  local root=$1 limit=$2 base now i
  sleep 5   # pre-issued evidence drains
  base=$(q4_evm_ir "$root") || return 1
  for i in $(seq 1 "$limit"); do
    sleep 1
    now=$(q4_evm_ir "$root") || return 1
    [ "$now" = "$base" ] || { echo "root$root EVM IR moved $base -> $now during the stall window" >&2; return 1; }
  done
  echo "root$root EVM IR constant at $base for ${limit}s"
}

# The fault rows judge the ROOT quorum, so progress there is the root's committed head round (roundInfo.roundNumber: it rises only when a root block commits, an empty block after a
# timeout certificate included, and it cannot rise without a quorum certificate or a timeout certificate of weight >= Q). The coupled EVM pipeline is judged in the baseline only: its
# certified round also needs the EVM nodes' durable archive acknowledgements, and an EVM node whose paired root is cut off cannot verify the blocks it is asked to acknowledge, so the
# EVM round can stand still while the roots (correctly) keep their quorum.
# q4_root_advance <root> <seconds> <n>: the root's committed round rose by at least n within the window
q4_root_advance() { q4_progress_timed root-commit q4_round "$1" "$2" "$3"; }

# q4_root_stalled <root> <seconds>: no block commits at all: the committed round is constant for the window
q4_root_stalled() {
  local root=$1 limit=$2 base now i
  sleep 5   # pre-issued evidence drains
  base=$(q4_round "$root") || return 1
  for i in $(seq 1 "$limit"); do
    sleep 1
    now=$(q4_round "$root") || return 1
    [ "$now" = "$base" ] || { echo "root$root committed round moved $base -> $now during the stall window" >&2; return 1; }
  done
  echo "root$root committed round constant at $base for ${limit}s"
}

q4_restart_root() {
  local node=$1
  m2_start_root "$node" "$Q4_EPOCH" "$(boot_node test-nodes/root1 "$rootPortStart")"
}

# The gate, from the Q3 flow library: the root's OWN verified state is a quorum certificate of the activated epoch under scheme 2, every signer carries its mirrored weight, and
# the committed activation record names scheme 2 and the committed tuple (the candidate config the root derived) names leader policy root-wrr-v1. Nothing is read from logs or from the process under test beyond its verified Q3 endpoints.
q4_weighted_epoch_check() {
  local root sg act signers
  root=$(h3_first_root) || return 1
  sg=$(q3_signers_of "$root") || return 1
  [ "$(printf '%s' "$sg" | jq -r '[.epoch, .scheme, .quorum] | join(",")')" = "$Q4_EPOCH,2,true" ] || { echo "root$root is not at a scheme-2 quorum certificate of epoch $Q4_EPOCH: $sg" >&2; return 1; }
  signers=$(mktemp); printf '%s' "$sg" | jq '.signers' >"$signers"
  q3_check_weights cert "$signers" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM" >/dev/null || { rm -f "$signers"; return 1; }
  python3 - "$signers" "$Q3_WEIGHTS" "$(for i in $H3_ROOTS; do printf '%s ' "$(h3_root_id "$i")"; done)" <<'PY' || { rm -f "$signers"; return 1; }
import json, sys
signers = json.load(open(sys.argv[1])); weights = sys.argv[2].split(); ids = sys.argv[3].split()
want = dict(zip(ids, map(int, weights)))
bad = [s for s in signers if want.get(s["nodeId"]) != int(s["weight"])]
if bad: sys.exit(f"signer weights differ from the mirrored weights {want}: {bad}")
PY
  rm -f "$signers"
  act=$(mktemp); build/ubft root handoff q3-activation --root-rpc "$(h3_rpc_url "$root")" --epoch "$Q4_EPOCH" --out "$act" >/dev/null || { rm -f "$act"; return 1; }
  jq -e --argjson e "$Q4_EPOCH" '.epoch == $e and .signingScheme == 2' "$act" >/dev/null || { echo "the committed activation record of epoch $Q4_EPOCH is not scheme 2" >&2; rm -f "$act"; return 1; }
  local cand=${Q4_GATE_CANDIDATE:-$Q3_DIR/candidate-config.json}
  [ "$(jq -r .leaderPolicy "$cand" 2>/dev/null)" = root-wrr-v1 ] || { echo "the committed tuple's leader policy is not root-wrr-v1: $(jq -c . "$cand" 2>&1)" >&2; return 1; }
  echo "activated weighted epoch confirmed from root$root: epoch $Q4_EPOCH, scheme 2, signed weight $(printf '%s' "$sg" | jq -r '[.signers[].weight] | add'), mirrored weights $Q3_WEIGHTS"
  cp "$act" "${Q4_EVIDENCE_DIR:-.}/weighted-check-activation$([ "$Q4_EPOCH" = 2 ] || printf -- '-%s' "$Q4_EPOCH").json" 2>/dev/null; rm -f "$act"
}
Q4_WEIGHTED_CHECK=${Q4_WEIGHTED_CHECK:-q4_weighted_epoch_check}

q4_precondition() {
  if [ -z "${Q4_WEIGHTED_CHECK:-}" ]; then
    echo "BLOCKED: Q4_WEIGHTED_CHECK is not set; the weighted rows need an activated weighted epoch (Q3 coupled activation)" >&2
    q4_teardown; exit 3
  fi
  # The gate is a caller-supplied command: the evidence keeps the command text, its output and its exit status, so the gate can be audited.
  local out rc gate_file=${Q4_EVIDENCE_DIR:-.}/weighted-check.txt
  out=$(eval "$Q4_WEIGHTED_CHECK" 2>&1) && rc=0 || rc=$?
  { printf '# command: %s\n# exit: %s\n' "$Q4_WEIGHTED_CHECK" "$rc"; printf '%s\n' "$out"; } > "$gate_file"
  [ "$rc" -eq 0 ] || { echo "BLOCKED: the chain is not in an activated weighted epoch (see $gate_file)" >&2; q4_teardown; exit 3; }
}

q4_peer_args() { local r; for r in $Q4_ROOTS; do printf -- '--peer %s=%s ' "$r" "$(q4_peer "$r")"; done; }

# ---- the rows ----
q4_row_baseline() { f8_trace >/dev/null && q4_commits_advance "$Q4_HEAVY_ROOT" 60 3; }

# q4_row_isolate <progress|stall> <roots...>: the named roots isolated from the rest (held both ways); the larger side either keeps committing or explicitly stalls, and a
# heal releases the stale traffic so that an isolated root commits again.
q4_row_isolate() {
  local expect=$1; shift
  local iso="$*" others observer rule
  # one rule name per isolation: the shim keeps a rule's hit counters AND its retired flag across control documents that reuse its name, and a release retires the rule, so
  # a reused name would pass its traffic untouched while the old hit count still satisfied q4_heal's "something was held" check
  rule=cut$(printf '%s' "$iso" | tr -d ' ')
  others=$(q4_without "$@" | tr '\n' ' ')
  observer=${others%% *}
  q4_partition "$rule" "$iso" "$others" || return 1
  case "$expect" in
    progress) q4_root_advance "$observer" "$Q4_RECOVER_SECONDS" 3 || return 1 ;;
    stall) q4_root_stalled "$observer" "$Q4_STALL_SECONDS" || return 1 ;;
  esac
  q4_heal "$rule" "$Q4_ROOTS" || return 1
  q4_root_advance "${iso%% *}" "$Q4_RECOVER_SECONDS" 3
}
q4_row_light_partition() { q4_row_isolate progress "$(q4_lights | head -n 1)"; }   # A: 6+1+1 = 8 of 9
q4_row_two_lights_partition() { q4_row_isolate progress $(q4_lights | tail -n 2); }   # A: heavy + one light = 7 = Q
q4_row_all_lights_partition() { q4_row_isolate stall $(q4_lights); }   # A: 6 | 3, B: 6 | 3 with one light folded in: neither side has Q
q4_row_b_light_one() { q4_row_isolate progress 4; }   # B: weight 1 isolated, 8 progress
q4_row_b_light_two() { q4_row_isolate progress 3; }   # B: weight 2 isolated, 7 = Q progress
q4_row_b_lights_both() { q4_row_isolate stall 3 4; }   # B: weight 2+1 isolated, the two weight-3 roots (6) stall

q4_row_heavy_delayed() {     # the heavy root's traffic held: the lights are weight 3 of 9, quorum lost until release
  q4_delay_outbound delay "$Q4_HEAVY_ROOT" || return 1
  local light; light=$(q4_lights | head -n 1)
  q4_root_stalled "$light" "$Q4_STALL_SECONDS" || return 1
  q4_heal delay "$Q4_HEAVY_ROOT" || return 1
  q4_root_advance "$light" "$Q4_RECOVER_SECONDS" 3
}

q4_row_light_sigkill() {     # SIGKILL a light root: the rest keep the quorum; restart over the retained home
  local light; light=$(q4_lights | head -n 1)
  q4_kill9 "$light" || return 1
  q4_root_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3 || return 1
  q4_restart_root "$light" || return 1
  q4_root_advance "$light" "$Q4_RECOVER_SECONDS" 3
}

q4_row_heavy_sigkill() {     # SIGKILL each heavy root in turn: A 3 of 9 left, B 6 of 9 left: explicit stall; restart over the retained home recovers
  local heavy observer
  for heavy in $Q4_HEAVY_ROOTS; do
    observer=$(q4_without "$heavy" | head -n 1)
    q4_kill9 "$heavy" || return 1
    q4_root_stalled "$observer" "$Q4_STALL_SECONDS" || return 1
    q4_restart_root "$heavy" || return 1
    q4_root_advance "$heavy" "$Q4_RECOVER_SECONDS" 3 || return 1
  done
}

q4_now() { python3 -c 'import datetime; print(datetime.datetime.now().astimezone().isoformat(timespec="microseconds"))'; }
q4_byz_sent() { jq -r '[.byzantine // {} | .[]] | add // 0' "$Q4_SHIM_DIR/root$1/status.json"; }

# A Byzantine row arms exactly its own roots and clears them before it ends, so the live Byzantine set of a row is the one the row claims and no row leaks into the next:
#   q4_byz_begin; q4_byz_arm <roots...>; ...the row's own assertion...; q4_byz_end <tag> <roots...>
# q4_byz_arm: the named roots also send a conflicting signed vote per round to every other root, and each has sent one. q4_byz_end: the live set is exactly the named roots
# (every other root's adapter has sent nothing), then the roots are cleared and the row's window [begin, end] is recorded; the trace check holds every equivocation in the
# traces to those windows.
q4_byz_begin() { Q4_BYZ_FROM=$(q4_now); }
q4_byz_arm() {
  local r others i
  for r in "$@"; do
    others=$(q4_without "$r" | tr '\n' ' ')
    q4_byzantine "$r" state "$others" || return 1
  done
  for r in "$@"; do
    for i in $(seq 1 60); do
      [ "$(q4_byz_sent "$r")" -gt 0 ] && break
      sleep 1
    done
    [ "$(q4_byz_sent "$r")" -gt 0 ] || { echo "root$r sent nothing Byzantine" >&2; return 1; }
  done
}
q4_byz_end() {
  local tag=$1 r in_set; shift
  for r in $Q4_ROOTS; do
    in_set=0; for x in "$@"; do [ "$x" = "$r" ] && in_set=1; done
    if [ "$in_set" = 1 ]; then
      [ "$(q4_byz_sent "$r")" -gt 0 ] || { echo "root$r was to equivocate in row $tag and sent nothing" >&2; return 1; }
    else
      [ "$(q4_byz_sent "$r")" = 0 ] || { echo "root$r equivocates during row $tag but is not in its Byzantine set ($*)" >&2; return 1; }
    fi
  done
  for r in "$@"; do q4_clear "$r" || return 1; done
  jq -n -c --arg tag "$tag" --arg from "$Q4_BYZ_FROM" --arg to "$(q4_now)" --arg roots "$*" '{tag: $tag, roots: ($roots | split(" ") | map(tonumber)), from: $from, to: $to}' >>"$Q4_DIR/byz-windows.jsonl" || return 1
  Q4_BYZ_ROOTS=$(echo $(echo ${Q4_BYZ_ROOTS:-} | tr ',' ' ') "$@" | tr ' ' ',' | sed 's/^,//')
}

q4_row_byzantine_lights() {  # IN BOUND (weight <= F=2): A two lights (1+1), B the weight-2 root; the honest weight 7 progresses
  local byz
  if [ "$Q4_SCENARIO" = A ]; then byz=$(q4_lights | tail -n 2 | tr '\n' ' '); else byz=3; fi
  q4_byz_begin
  q4_byz_arm $byz || return 1
  q4_root_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3 || return 1
  q4_byz_end lights $byz
}

# OUTSIDE THE ASSUMPTIONS (heavy weight 6 or 3 > F=2), alone (the in-bound row has cleared its adapters): no liveness claim at all. What the row shows is that the
# equivocation is real (the root's own adapter counted its conflicting signed votes, and the traces hold them inside this row's window) and that the independent checker
# classifies exactly the declared roots as equivocators (the trace check).
q4_row_byzantine_heavy() {
  q4_byz_begin
  q4_byz_arm "$Q4_HEAVY_ROOT" || return 1
  sleep 10   # several rounds of equivocation, not only the first vote
  q4_byz_end heavy "$Q4_HEAVY_ROOT"
}

# The F8 callbacks (f8_slow_stop_resume_evm: EVM stopped, aggregators certify new state roots, resumed; f8_inflight_evm_probe) run in the lane's preamble, in the
# unit epoch before the activation. In the weighted epoch two checks: the aggregator shards stay served by it (their authorized TR rounds keep advancing at the
# roots and the three aggregators answer their health endpoints), and each of them certifies a NEW state root with an rsmt proof the weighted roots verify
# (q4_row_f8_new_roots: the second state-changing block, the one that failed as ProofInvalid with an empty envelope before the lane set the aggregators'
# AGGREGATOR_CONSISTENCY_PROOF_MODE; the first block has no previous state root and is not verified).
q4_row_f8_new_roots() { f8_certify_new_roots 100 | tee "$Q4_DIR/f8-new-roots.txt"; [ "${PIPESTATUS[0]}" = 0 ]; }

q4_row_f8_follow() {
  local before after i
  f8_trace >/dev/null || return 1
  before=$(tail -n 4 "$F8_LOG_DIR/trace.jsonl" | jq -s -c '[.[] | select(.shard != "evm") | {shard, tr: (.authorizedTRRound | tonumber)}]')
  sleep 20
  f8_trace >/dev/null || return 1
  after=$(tail -n 4 "$F8_LOG_DIR/trace.jsonl" | jq -s -c '[.[] | select(.shard != "evm") | {shard, tr: (.authorizedTRRound | tonumber)}]')
  printf 'before: %s\nafter:  %s\n' "$before" "$after" | tee "$Q4_DIR/f8-follow.txt"
  [ "$(printf '%s' "$before" | jq length)" = 3 ] && [ "$(printf '%s' "$after" | jq length)" = 3 ] || return 1
  jq -n -e --argjson b "$before" --argjson a "$after" '[range(0;3) | ($a[.].tr > $b[.].tr)] | all' >/dev/null
}

# ---- lane additions (Q4 #51 closure path, owner decision 17): F1 F9 F10 F11 F14/L1 F17 T2 Q3 -----------------------------------------------------

# Q3: the no-fault control at the lane's own load, before any fault of the additions: the roots' commit latency and gaps over a fixed window,
# and the EVM shard's certified progress over the same window.
q4_row_nofault_control() {
  local root=$Q4_HEAVY_ROOT window=30 t0 t tlast prev now base commits=0 gap=0 g mark evm0 evm1
  base=$(q4_round "$root") || return 1; prev=$base; evm0=$(q4_evm_ir "$root") || return 1
  t0=$(q4_t); tlast=$t0; mark=$(q4_tc_mark "$root")
  while awk -v a="$(q4_dt "$(q4_t)" "$t0")" -v b="$window" 'BEGIN { exit !(a < b) }'; do
    now=$(q4_round "$root") || return 1; t=$(q4_t)
    if [ "$now" -gt "$prev" ]; then
      commits=$((commits + now - prev))
      g=$(q4_dt "$t" "$tlast"); gap=$(awk -v a="$g" -v b="$gap" 'BEGIN { print (a > b) ? a : b }')
      prev=$now; tlast=$t
    fi
    sleep 0.25
  done
  evm1=$(q4_evm_ir "$root") || return 1
  q4_timing control root="$root" window_s="$window" root_commits="$commits" max_gap_s="$gap" tc="$(q4_tc_since "$root" "$mark")" evm_commits="$((evm1 - evm0))" deadline_s="$Q4_RECOVER_SECONDS" ok=true
  echo "no-fault control at root$root: $commits root commits and $((evm1 - evm0)) EVM certifications in ${window}s, max root commit gap ${gap}s"
  [ "$commits" -ge 3 ] && [ $((evm1 - evm0)) -ge 1 ]
}

# T2 (design v2 section 4, second paragraph): during root quorum loss wall time cannot create a root-certified retry. The heavy root's traffic is held
# (A: the lights are weight 3 of 9; B: one weight-3 root, 6 of 9 left); for longer than three EVM T2 periods every root's epoch and committed round, the
# EVM shard's certified IR round and TR round at every root, and the EVM height are sampled and recorded SEPARATELY (q4/t2-quorum-loss.jsonl). The local
# T2 expiry is the shard's last certification plus its T2 (from the shard configuration); the EVM nodes' own inactivity expiries in the window are counted from
# their logs. Nothing may move: no root round, no IR or TR round of the EVM shard, no EVM block. Then the release recovers the roots and the EVM shard.
q4_row_t2_quorum_loss() {
  local out=$Q4_DIR/t2-quorum-loss.jsonl summary=$Q4_DIR/t2-quorum-loss.txt t2ms window i r light t0 marks=()
  t2ms=$(jq -r '[.. | objects | to_entries[] | select(.key | test("^t2"; "i")) | .value] | first // empty' test-nodes/shard-conf-8_0.json 2>/dev/null)
  t2ms=$(python3 -c 'import sys; v=sys.argv[1]; v=int(v) if v.isdigit() else 5000; print(v // 1000000 if v > 10**7 else v)' "${t2ms:-5000}")   # ns or ms in the configuration
  window=$(( (3 * t2ms + 999) / 1000 + 5 ))
  light=$(q4_lights | head -n 1)
  for i in 1 2 3 4; do marks+=("$(wc -l <"test-nodes/evm$i/debug.log" | tr -d ' ')"); done
  q4_delay_outbound t2hold "$Q4_HEAVY_ROOT" || return 1
  sleep 5   # pre-issued evidence drains
  : >"$out"; t0=$(q4_t)
  for i in $(seq 0 "$window"); do
    python3 - "$out" "$(q4_dt "$(q4_t)" "$t0")" "$(rpc "http://127.0.0.1:$rethEthBase" eth_blockNumber '[]' | pyget "['result']")" \
      $(for r in $Q4_ROOTS; do printf '%s ' "$(curl -fsS "http://127.0.0.1:$(m2_rpc_port "$r")/api/v1/roundInfo" | jq -c --arg r "$r" '{root: ($r | tonumber), epoch: .epochNumber, round: .roundNumber, evm: (.partitionShards[] | select(.partitionId == 8) | {ir: .roundNumber, tr: .trRound, leader: .trLeader})}')"; done) <<'PY' || return 1
import json, sys
path, elapsed, height, *roots = sys.argv[1:]
rec = {"elapsed_s": float(elapsed), "evm_height": int(height, 16), "roots": [json.loads(r) for r in roots]}
open(path, "a").write(json.dumps(rec, sort_keys=True) + "\n")
PY
    sleep 1
  done
  local evmExpiries=0
  for i in 1 2 3 4; do evmExpiries=$((evmExpiries + $(tail -n +"$((${marks[$((i - 1))]} + 1))" "test-nodes/evm$i/debug.log" | grep -ac 'inactivity timeout exceeded' || true))); done
  python3 - "$out" "$summary" "$t2ms" "$evmExpiries" <<'PY' || return 1
import json, sys
path, summary, t2ms, expiries = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
rows = [json.loads(l) for l in open(path) if l.strip()]
span = rows[-1]["elapsed_s"] - rows[0]["elapsed_s"]
# progress is a value above the highest any root held when the window opened; a lagging root catching up to an
# already-certified round is not a retry
def vals(r):
    return {"epoch": int(r["epoch"]), "round": int(r["round"]), "EVM ir": int(r["evm"]["ir"]), "EVM tr": int(r["evm"]["tr"])}
first = {r["root"]: vals(r) for r in rows[0]["roots"]}
top = {k: max(v[k] for v in first.values()) for k in ("epoch", "round", "EVM ir", "EVM tr")}
moved, caught = [], set()
for row in rows[1:]:
    for r in row["roots"]:
        for k, v in vals(r).items():
            if v > top[k]:
                moved.append(f"root{r['root']} {k} {top[k]} -> {v} at {row['elapsed_s']:.1f}s")
            elif v != first[r["root"]][k]:
                caught.add(f"root{r['root']} {k} {first[r['root']][k]} -> {v}")
    if row["evm_height"] != rows[0]["evm_height"]:
        moved.append(f"EVM height {rows[0]['evm_height']} -> {row['evm_height']} at {row['elapsed_s']:.1f}s")
lines = [f"root quorum lost for {span:.1f}s of samples (after a 5 s drain); EVM T2 = {t2ms} ms: the local T2 expiry fell at most {t2ms / 1000:.1f}s into the window,",
         f"the window ran {span - t2ms / 1000:.1f}s past it ({span / (t2ms / 1000):.1f} T2 periods); EVM nodes' local inactivity expiries logged in the window: {expiries}"]
for r in rows[0]["roots"]:
    lines.append(f"  root{r['root']}: epoch {r['epoch']}, committed round {r['round']}; EVM shard IR round {r['evm']['ir']}, TR round {r['evm']['tr']}")
lines.append(f"  EVM height {rows[0]['evm_height']}")
if caught:
    lines.append("caught up to values already held by another root (not progress): " + "; ".join(sorted(set(caught))))
lines.append("moved during the window: " + ("; ".join(moved) if moved else "nothing (no root round, no EVM IR/TR round, no EVM block): no root-certified retry"))
open(summary, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
if span < 3 * t2ms / 1000:
    sys.exit("the window is shorter than three T2 periods")
if moved:
    sys.exit("progress during root quorum loss")
PY
  q4_heal t2hold "$Q4_HEAVY_ROOT" || return 1
  q4_root_advance "$light" "$Q4_RECOVER_SECONDS" 3 || return 1
  q4_commits_advance "$light" "$Q4_RECOVER_SECONDS" 1
}

# ---- EVM-only faults: the roots keep their quorum; the EVM shard counts its requests by the mirrored EVM weights (W=9, request Q=5) ----
q4_evm_ids() { local i; for i in "$@"; do evm_validator_id "$i"; jq -r .nodeId "test-nodes/auth$i/node-info.json" 2>/dev/null; done; }
q4_evm_weight() { local i w=0; for i in "$@"; do w=$((w + $(q3_weight_of "$i"))); done; echo "$w"; }
q4_evm_head() { rpc "http://127.0.0.1:$((rethEthBase + $2 - 1))" eth_getBlockByNumber "[\"$(printf '0x%x' "$1")\",false]" | pyget "['result']['hash']"; }
q4_evm_height() { printf '%d' "$(rpc "http://127.0.0.1:$((rethEthBase + $1 - 1))" eth_blockNumber '[]' | pyget "['result']")"; }

# q4_evm_expect <progress|stall> <observer root>: with the root quorum intact, the EVM shard certifies (>= 3 within the deadline) or explicitly stalls
# while the roots keep committing
q4_evm_expect() {
  case "$1" in
    progress) q4_commits_advance "$2" "$Q4_RECOVER_SECONDS" 3 ;;
    stall) q4_stalled "$2" "$Q4_STALL_SECONDS" && q4_root_advance "$2" "$Q4_RECOVER_SECONDS" 3 ;;
  esac
}

# F1 (separate paired root/EVM outage): the EVM pairs of the named entities (shard node and Ureth, an orderly stop) are down while every root runs.
# The rest of the EVM weight certifies or stalls by request Q=5; the roots commit throughout; the pairs restart over their retained stores and the
# shard certifies again.
q4_row_evm_outage() {
  local expect=$1 i pid rootBoot bootnodes observer; shift
  observer=$(q4_without "$@" | head -n 1)
  echo "EVM pairs of entities $* down (EVM weight $(q4_evm_weight "$@") of 9 out; request Q=5): expect $expect; roots all up"
  for i in "$@"; do
    stop_one_evm_validator "$i" || return 1
    pid=$(cat "test-nodes/reth$i/pid" 2>/dev/null)
    stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
    # the client flushes on ctrl-c and holds its storage lock until it exits: it must be gone before the restart opens the same datadir
    for _ in $(seq 1 180); do [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || { echo "execution client $pid of entity $i still running 90 s after ctrl-c" >&2; return 1; }
  done
  q4_evm_expect "$expect" "$observer" || return 1
  rootBoot=$(m2_root_addr 1) || return 1
  for i in "$@"; do
    q3_restart_reth_same_secret "$i" || return 1
    bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $(m2_online_validators)) || return 1
    start_one_evm_validator "$i" 4 "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
  done
  q4_commits_advance "$observer" "$Q4_RECOVER_SECONDS" 3
}

# F9 (EVM-only partition variant) and the request-Q=5 rows: the EVM pairs of the named entities are cut from EVERY root by the roots' shard gates (their
# certification requests and handshakes held inbound, the roots' certification responses to them held outbound) while the roots keep their quorum.
# The heal releases the stale traffic both ways; no rollback: the EVM block at the pre-cut head keeps its hash and the EVM height only grows.
q4_row_evm_cut() {
  local expect=$1 rule observer h0 hash0 h1; shift
  rule=evmcut$(printf '%s' "$*" | tr -d ' ')$Q4_EPOCH
  observer=$(q4_without "$@" | head -n 1)
  h0=$(q4_evm_height "$observer") || return 1; hash0=$(q4_evm_head "$h0" "$observer") || return 1
  echo "EVM pairs of entities $* cut from every root (EVM weight $(q4_evm_weight "$@") of 9 out; request Q=5): expect $expect; pre-cut head $h0 $hash0"
  q4_shard_hold "$rule" "$Q4_ROOTS" "in out" 8 $(q4_evm_ids "$@") || return 1
  q4_evm_expect "$expect" "$observer" || return 1
  q4_shard_release "$rule" "$Q4_ROOTS" "in out" || return 1
  q4_commits_advance "$observer" "$Q4_RECOVER_SECONDS" 3 || return 1
  h1=$(q4_evm_height "$observer") || return 1
  [ "$h1" -gt "$h0" ] || { echo "EVM height $h0 -> $h1 across the heal" >&2; return 1; }
  [ "$(q4_evm_head "$h0" "$observer")" = "$hash0" ] || { echo "EVM block $h0 changed across the heal: rollback" >&2; return 1; }
  echo "healed without rollback: block $h0 keeps $hash0, height $h0 -> $h1"
}

# F10 (delay of shard requests): every root holds the EVM shard's certification requests; the roots keep committing and the EVM shard stalls; the release
# delivers them (stale by then: refused or superseded) and the shard certifies again.
q4_row_shard_requests_delayed() {
  local rule=shardreq$Q4_EPOCH observer=$Q4_HEAVY_ROOT
  q4_shard_hold "$rule" "$Q4_ROOTS" in 8 || return 1
  q4_evm_expect stall "$observer" || return 1
  q4_shard_release "$rule" "$Q4_ROOTS" in || return 1
  q4_commits_advance "$observer" "$Q4_RECOVER_SECONDS" 3
}

# G2 (rollback on a live pair). A pair never un-commits: a block is made canonical and final only with its certificate. So the rollback is this: every
# root holds the EVM shard's certification requests past the shard's T2; the round's block, sealed by the leader and executed (verified VALID) by every
# pair, cannot be certified; the roots' repeat certificate starts a fresh attempt and a DIFFERENT block is built on the same parent. A paid transaction
# is submitted under the hold, so an abandoned block carries it. While held every pair's latest and finalized block stay the parent; after the release
# the pairs agree on one certified block at the height, no pair has an abandoned block canonical, finalized never went back, the transaction is in a
# certified block once (the sender's nonce advances by one), and two pairs export the same root input, transitions and state for the certified block.
# The judge is scripts/q4-g2-rollback.py; its samples and verdict are q4/g2-rollback/.
q4_g2_urls() { local i; for i in 1 2 3 4; do printf '%s ' "http://127.0.0.1:$((rethEthBase + i - 1))"; done; }
q4_g2_sample() { # phase t0: one line of every pair's latest and finalized block
  python3 scripts/q4-g2-rollback.py heads $(q4_g2_urls) | jq -c --arg p "$1" --arg e "$(q4_dt "$(q4_t)" "$2")" '{phase: $p, elapsed_s: ($e | tonumber), pairs: .}' >>"$Q4_DIR/g2-rollback/samples.jsonl"
}
q4_row_g2_rollback() {
  local dir=$Q4_DIR/g2-rollback rule=g2hold$Q4_EPOCH observer=$Q4_HEAVY_ROOT i t0 logs=() urls=() head parent height sender nonce tx sent kids n=0 carried=0 tr0 tr=0 pair
  rm -rf "$dir"; mkdir -p "$dir"
  # the log marks are taken before the hold, so every block sealed on the parent during the settle below is listed
  for i in 1 2 3 4; do logs+=("test-nodes/evm$i/debug.log:$(wc -l <"test-nodes/evm$i/debug.log" | tr -d ' ')"); urls+=(--url "http://127.0.0.1:$((rethEthBase + i - 1))"); done
  Q4_SHARD_TYPES=request q4_shard_hold "$rule" "$Q4_ROOTS" in 8 || return 1
  sleep 3   # requests already past the gate are answered; from here nothing the shard builds can be certified
  t0=$(q4_t)
  head=$(python3 scripts/q4-g2-rollback.py heads $(q4_g2_urls)) || return 1
  [ "$(printf '%s' "$head" | jq -r '[.[] | .latest.hash, .finalized.hash] | unique | length')" = 1 ] || { echo "the pairs do not agree on one finalized head under the hold: $head" >&2; return 1; }
  parent=$(printf '%s' "$head" | jq -r '.[0].latest.hash'); height=$(( $(printf '%s' "$head" | jq -r '.[0].latest.number') + 1 ))
  sender=$(go run ./scripts/evmtx -address) || return 1
  nonce=$(printf '%d' "$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionCount "[\"$sender\",\"latest\"]" | pyget "['result']")") || return 1
  [ -z "${M2_NEXT_NONCE:-}" ] || [ "$M2_NEXT_NONCE" = "$nonce" ] || { echo "the lane's next nonce $M2_NEXT_NONCE is not the sender's $nonce" >&2; return 1; }
  for i in 1 2 3 4; do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase + i - 1))" -chain-id "${M2_CHAIN_ID:-31337}" -nonce "$nonce" 2>&1) || { echo "evmtx failed on pair $i: $sent" >&2; return 1; }
    [ -z "${tx:-}" ] || [ "$tx" = "$sent" ] || { echo "the pairs disagree on the transaction hash: $tx vs $sent" >&2; return 1; }
    tx=$sent
  done
  echo "certification requests of the EVM shard held at every root; parent $((height - 1)) $parent; transaction $tx (sender $sender nonce $nonce) submitted under the hold"
  # held until a block on the parent that every pair executed carries the transaction, and then until every root has issued two more repeat
  # certificates for the shard (its TR round moved on by 2): the block's request is for a round the roots have left, so it can no longer be
  # certified. Only the requests are held (Q4_SHARD_TYPES=request): the nodes' handshakes pass, so a node whose subscription at a root has
  # run out (two responses without a request) subscribes again and keeps receiving the repeat certificates. The step does not wait for a
  # further attempt under the hold.
  for i in $(seq 1 "$Q4_RECOVER_SECONDS"); do
    q4_g2_sample held "$t0" || return 1
    kids=$(python3 scripts/q4-g2-rollback.py children --parent "$parent" "${logs[@]}") || return 1
    n=$(printf '%s' "$kids" | jq 'length')
    carried=$(printf '%s' "$kids" | jq '[.[] | select(.userTransactions >= 1 and (.verifiedValidBy | length) == 4)] | length')
    [ "$carried" -ge 1 ] && break
    sleep 1
  done
  [ "$carried" -ge 1 ] || { echo "$n block(s) sealed on the parent within ${Q4_RECOVER_SECONDS}s of the hold, none carries the transaction and was verified VALID by all four pairs" >&2; return 1; }
  tr0=$(for i in $Q4_ROOTS; do q4_evm_tr "$i" || exit 1; done | sort -n | tail -n 1) || return 1
  for i in $(seq 1 "$Q4_RECOVER_SECONDS"); do
    q4_g2_sample held "$t0" || return 1
    tr=$(for pair in $Q4_ROOTS; do q4_evm_tr "$pair" || exit 1; done | sort -n | head -n 1) || return 1
    [ "$tr" -ge $((tr0 + 2)) ] && break
    sleep 1
  done
  [ "$tr" -ge $((tr0 + 2)) ] || { echo "the roots did not move the EVM shard's TR round from $tr0 to $((tr0 + 2)) within ${Q4_RECOVER_SECONDS}s (now $tr): no repeat certificates under the hold" >&2; return 1; }
  echo "a block carrying the transaction was executed by all four pairs under the hold; the roots moved the shard's TR round $tr0 -> $tr without certifying it"
  q4_root_advance "$observer" "$Q4_RECOVER_SECONDS" 1 || return 1   # the roots keep their quorum throughout
  q4_g2_sample held "$t0" || return 1
  q4_shard_release "$rule" "$Q4_ROOTS" in || return 1
  q4_commits_advance "$observer" "$Q4_RECOVER_SECONDS" 3 || return 1
  for i in $(seq 1 "$Q4_RECOVER_SECONDS"); do
    q4_g2_sample released "$t0" || return 1
    [ "$(tail -n 1 "$dir/samples.jsonl" | jq --argjson h "$height" '[.pairs[] | select(.finalized.number >= $h)] | length')" = 4 ] && break
    sleep 1
  done
  for i in $(seq 1 60); do   # the transaction's certified block on every pair
    [ "$(for pair in 1 2 3 4; do rpc "http://127.0.0.1:$((rethEthBase + pair - 1))" eth_getTransactionReceipt "[\"$tx\"]" | pyget "['result']['status']"; done | grep -c 0x1)" = 4 ] && break
    sleep 1
  done
  q4_g2_sample released "$t0" || return 1
  python3 scripts/q4-g2-rollback.py judge --dir "$dir" --parent "$parent" --height "$height" --tx "$tx" --sender "$sender" --nonce "$nonce" \
    "${urls[@]}" $(printf -- '--log %s ' "${logs[@]}") | tee "$dir/summary.txt"
  [ "${PIPESTATUS[0]}" = 0 ] || return 1
  [ -z "${M2_NEXT_NONCE:-}" ] || M2_NEXT_NONCE=$((nonce + 1))
  # two pairs' own retained bytes for the certified block are identical (the Q3 pair equality, here for the block that replaced the abandoned one)
  for pair in a:1 b:4; do
    build/ubft q3 pair-export --eth-url "$(q3_eth_url "${pair#*:}")" --block-number "$height" --root-input-out "$dir/pair-root-input-${pair%:*}.bin" \
      --transitions-out "$dir/pair-transitions-${pair%:*}.bin" --state-out "$dir/pair-state-${pair%:*}.json" || return 1
  done
  q3_pair_equal "$dir" || return 1
  echo "pairs 1 and 4 export identical root input, transitions and state for block $height" | tee -a "$dir/summary.txt"
}

# F10 (duplicate; no replayed weight): the heavy root's traffic is held (quorum lost) while every other root's traffic is DUPLICATED on the network:
# each vote and timeout of the lights arrives twice and must count once, so the stall holds; then the duplication goes on while the heavy is released,
# and the roots commit with every message doubled.
q4_row_duplicates() {
  local r light; light=$(q4_lights | head -n 1)
  for r in $(q4_lights); do q4_ctl "$r" "{'rules':[{'name':'dup$Q4_EPOCH','action':'duplicate','require':true}]}" || return 1; done
  q4_delay_outbound dupheavy$Q4_EPOCH "$Q4_HEAVY_ROOT" || return 1
  q4_root_stalled "$light" "$Q4_STALL_SECONDS" || return 1
  q4_heal dupheavy$Q4_EPOCH "$Q4_HEAVY_ROOT" || return 1
  q4_root_advance "$light" "$Q4_RECOVER_SECONDS" 3 || return 1
  for r in $(q4_lights); do
    [ "$(q4_hits "$r" "dup$Q4_EPOCH")" -gt 0 ] || { echo "root$r duplicated nothing" >&2; return 1; }
    q4_clear "$r" || return 1
  done
}

# F10 (reorder): the heavy root's traffic is held, then released LAST-IN-FIRST-OUT: proposals, votes and timeouts of later rounds reach the lights before
# earlier ones; the roots recover. The heavy root's own trace must show the release out of send order.
q4_row_reorder() {
  local rule=reorder$Q4_EPOCH light; light=$(q4_lights | head -n 1)
  q4_delay_outbound "$rule" "$Q4_HEAVY_ROOT" || return 1
  q4_root_stalled "$light" "$Q4_STALL_SECONDS" || return 1
  q4_ctl "$Q4_HEAVY_ROOT" "{'rules':[{'name':'$rule','action':'pass'}],'releases':[{'id':'$rule-lifo','rule':'$rule','order':'lifo'}]}" || return 1
  q4_root_advance "$light" "$Q4_RECOVER_SECONDS" 3 || return 1
  python3 - "$Q4_SHIM_DIR/root$Q4_HEAVY_ROOT/trace.jsonl" "$rule" <<'PY'
import collections, json, sys
last, inv, n = {}, 0, collections.Counter()
for line in open(sys.argv[1]):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    if ev.get("kind") == "release" and ev.get("rule") == sys.argv[2]:
        to = ev.get("to"); n[ev.get("class")] += 1
        if to in last and ev["sendId"] < last[to]:
            inv += 1
        last[to] = ev["sendId"]
print(f"released out of send order: {inv} inversions over {sum(n.values())} held messages {dict(n)}")
sys.exit(0 if inv > 0 else "the release did not reorder anything")
PY
}

# F11 (quorum-wide restart): every root SIGKILLed together, then restarted over its retained home; the roots commit again and the EVM shard certifies
# again (full-lane recovery: root commits and certified EVM blocks).
q4_row_quorum_restart() {
  local r
  for r in $Q4_ROOTS; do q4_kill9 "$r" || return 1; done
  sleep 2
  for r in $Q4_ROOTS; do curl -fsS -m 2 "http://127.0.0.1:$(m2_rpc_port "$r")/api/v1/roundInfo" >/dev/null 2>&1 && { echo "root$r still answers after SIGKILL" >&2; return 1; }; done
  echo "all $(echo $Q4_ROOTS | wc -w | tr -d ' ') roots SIGKILLed; restarting over the retained homes"
  for r in $Q4_ROOTS; do q4_restart_root "$r" || return 1; done
  q4_root_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3 || return 1
  q4_commits_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3
}

# F14 + L1 (authentication-refusal representatives): the heavy root's traffic is held, so the honest live weight is the lights' 3 (A) or 6 (B), below Q.
# A light root then sends, next to its own timeouts and votes, one forged message per variant to every other root, one variant at a time: an
# impersonation of the HEAVY root (its weight would complete a quorum if counted), an unknown signer, a corrupted signature, the wrong domain, the old
# signing form (scheme 1 in a scheme 2 epoch), the wrong epoch both ways, and its own stale message. For each variant the forger's adapter must have
# sent it and a receiving root must have logged its refusal; through all of it the roots stay stalled (zero live weight). The release then recovers.
Q4_FORGERY_VARIANTS="impersonate unknown-signer bad-signature wrong-domain old-form old-epoch future-epoch stale"
q4_refusal_pattern() {
  case "$1" in
    impersonate | bad-signature | wrong-domain) echo 'signature verification (failed|error)' ;;
    unknown-signer) echo 'is not part of the trust base' ;;
    old-form) echo 'is scheme 1, epoch [0-9]+ requires scheme 2' ;;
    old-epoch) echo 'vote epoch differs from the weighting epoch: message epoch [0-9]+, trust base epoch [0-9]+' ;;
    future-epoch) echo 'failed to get trust base for (timeout|vote) verification, epoch [0-9]+: trust base not found' ;;
    stale) echo 'stale (timeout )?vote for round' ;;
  esac
}
q4_row_auth_refusals() {
  local forger receivers v r i base marks line found out=$Q4_DIR/auth-refusals.txt rule=authhold$Q4_EPOCH
  forger=$(q4_lights | head -n 1)
  receivers=$(q4_without "$forger" | tr '\n' ' ')
  q4_delay_outbound "$rule" "$Q4_HEAVY_ROOT" || return 1
  sleep 5
  base=$(q4_round "$forger") || return 1
  : >"$out"
  echo "forger root$forger (weight $(q3_weight_of "$forger")); receivers $receivers; the heavy root$Q4_HEAVY_ROOT held; committed round $base" >>"$out"
  for v in $Q4_FORGERY_VARIANTS; do
    marks=(); for r in $receivers; do marks+=("$r:$(wc -l <"test-nodes/root$r/debug.log" | tr -d ' ')"); done
    if [ "$v" = impersonate ]; then q4_forge "$forger" "f-$v$Q4_EPOCH" "$v" "$receivers" "$Q4_HEAVY_ROOT" || return 1
    else q4_forge "$forger" "f-$v$Q4_EPOCH" "$v" "$receivers" || return 1; fi
    for i in $(seq 1 90); do [ "$(q4_forged "$forger" "f-$v$Q4_EPOCH")" -gt 0 ] && break; sleep 1; done
    [ "$(q4_forged "$forger" "f-$v$Q4_EPOCH")" -gt 0 ] || { echo "variant $v: the forger sent nothing in 90 s" >&2; return 1; }
    found=
    for i in $(seq 1 20); do
      for line in "${marks[@]}"; do
        r=${line%%:*}
        found=$(tail -n +"$((${line#*:} + 1))" "test-nodes/root$r/debug.log" | grep -aE 'msg="processing \*abdrc\.(TimeoutMsg|VoteMsg)"' | grep -aE "$(q4_refusal_pattern "$v")" | head -n 1)
        [ -n "$found" ] && { found="root$r: $found"; break; }
      done
      [ -n "$found" ] && break
      sleep 1
    done
    [ -n "$found" ] || { echo "variant $v: sent $(q4_forged "$forger" "f-$v$Q4_EPOCH") times, no receiving root logged its refusal" >&2; return 1; }
    printf '%s: sent %s, refused: %s\n' "$v" "$(q4_forged "$forger" "f-$v$Q4_EPOCH")" "$(printf '%s' "$found" | cut -c1-600)" >>"$out"
    q4_clear "$forger" || return 1
    [ "$(q4_round "$forger")" = "$base" ] || { echo "variant $v: the committed round moved $base -> $(q4_round "$forger") under forged traffic" >&2; return 1; }
  done
  echo "every variant refused; committed round still $base: zero live weight" >>"$out"
  cat "$out"
  q4_heal "$rule" "$Q4_HEAVY_ROOT" || return 1
  q4_root_advance "$forger" "$Q4_RECOVER_SECONDS" 3
}

# ---- F17: the second handoff A to B on the running chain ----------------------------------------------------------------------------------------
# The same four entities are reweighted (6,1,1,1) -> (3,3,2,1) by the Q3 flow's second handoff (plan, receipts, propose, commit at epoch 2), the roots
# restart into epoch 3 with the first successor proposal HELD (F10: every root holds its epoch-3 proposals from its first start in the new epoch; the
# earliest epoch-3 proposal of any root must be held), the release lets epoch 3 commit, the activation record of epoch 3 is read and the authorities
# acknowledge it (root epoch 3, shard epoch 2). Then the new committee is the one in effect: scheme 2 certificates of epoch 3 signed by the mirrored
# weights 3,3,2,1, a paid transaction certified, and the EVM request-Q=5 rows under the new EVM weights.
Q4_B_WEIGHTS="3 3 2 1"
q4_handoff_ab() { q3_handoff_n 2 3 "$Q4_B_WEIGHTS" 0 "$Q3_DIR/cand-identities.json"; }

# ---- F17 turnover and L5 non-members (Q4_TURNOVER=1) ---------------------------------------------------------------------------------------------
# The design's A to B (v2 section 2): old {H:6,a:1,b:1,c:1} -> new {H:3,a:3,b:2,d:1}. Coupled entity c (root and EVM validator 4, Q4_OUT) is replaced by a
# new coupled entity d (5, Q4_IN); H, a, b (entities 1 2 3) are retained and hold 8 of 9 in the old map and 8 of 9 in the new one (Q=7 in both). The
# joiner's stack comes from the H3/T6 helpers (scripts/lib/h3-q3-lib.sh): d's root runs as a follower and its shard node staging-only BEFORE the Commit.
# After the Commit d's root restarts into epoch 3 first, the retained roots follow, and c's root is restarted into epoch 3 as well and kept running: it
# is then a removed validator, a root the committee does not name.
# L5 (non-member, live): d's root before the Commit and c's root after the install each report follower, are refused every signature by their own
# membership gate and sign nothing; c's identity is in no epoch-3 certificate. What is NOT shown: a follower tracking the committee's rounds (#550: a root
# the committee does not name receives no consensus message; it reaches the new epoch through its install restart, not by catching up round by round).
Q4_TURNOVER=${Q4_TURNOVER:-0}
Q4_OUT=4; Q4_IN=5
Q4_B_ENTITIES="1 2 3 $Q4_IN"

# The successor identity records under a turnover: the retained entities keep their own records (staking id, payee, exposure digest) with the new
# weights; the joiner has no earlier record, so its record is generated for the successor set (as the H3 lane does), with its weight. Outside a
# turnover this is the Q3 lane's function unchanged.
eval "$(declare -f q3_successor_identities | sed '1s/^q3_successor_identities/q3_successor_identities_same/')"
q3_successor_identities() { # out ids...
  [ -n "${Q4_TURNOVER_ACTIVE:-}" ] || { q3_successor_identities_same "$@"; return; }
  local out=$1 tag=${1%-identities.json} id w=; shift
  for id in "$@"; do w+="${w:+,}\"$(h3_root_id "$id")\":$(q3_weight_of "$id")"; done
  H3_BIND_ROOTS="$*" h3_bindings_json "$tag-bindings.json" "$@" || return 1
  h3_successor_identities "$tag-identities-generated.json" "${Q3_NEXT_EPOCH:?}" "$tag-validators.json" "$tag-bindings.json" || return 1
  jq --argjson w "{$w}" --slurpfile old "${Q3_INCUMBENT:?}" '
    ($old[0] | map({key: .rootNodeId, value: .}) | from_entries) as $kept
    | map(($kept[.rootNodeId] // .) | .weight = $w[.rootNodeId] | .rawWeight = $w[.rootNodeId])' "$tag-identities-generated.json" >"$out" || return 1
  [ "$(jq 'length' "$out")" = "$#" ] && [ "$(jq '[.[] | select(.weight == null)] | length' "$out")" = 0 ] || { echo "successor identity records do not cover the successor set: $out" >&2; return 1; }
}

q4_status_of() { curl -fsS -m 5 -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url "$1")/api/v1/q3/status"; }
# q4_non_member <root> <epoch> <mark> <label>: the root reports follower, its membership gate refused at least one signature in that epoch since the log
# mark, and it signed nothing since the mark
q4_non_member() {
  local root=$1 epoch=$2 mark=$3 label=$4 log="test-nodes/root$1/debug.log" refused signed st
  st=$(q4_status_of "$root") || { echo "root$root does not answer its status" >&2; return 1; }
  [ "$(printf '%s' "$st" | jq -r .follower)" = true ] || { echo "root$root does not report follower ($label): $st" >&2; return 1; }
  refused=$(tail -n +"$((mark + 1))" "$log" | grep -ac "it follows and signs nothing: epoch $epoch" || true)
  signed=$(tail -n +"$((mark + 1))" "$log" | grep -acE 'msg="(signed vote|signed timeout vote|broadcast proposal|broadcast timeout vote)"' || true)
  [ "$refused" -gt 0 ] || { echo "root$root logged no refused signature in epoch $epoch ($label): the membership gate was not reached" >&2; return 1; }
  [ "$signed" = 0 ] || { echo "root$root signed or broadcast $signed consensus message(s) as a non-member ($label)" >&2; return 1; }
  echo "root$root ($(h3_root_id "$root")) $label: reports follower; $refused signature(s) refused by its membership gate in epoch $epoch; signed votes, timeouts and proposals: 0; committed round $(q4_round "$root" 2>/dev/null || echo '?')" | tee -a "$Q4_DIR/non-members.txt"
}

# The joiner's staging-only restore at its readiness turn. The restore fetches every block from the pinned tip back to genesis from the two replicas
# before it replays any, and serves its status only after the replay: the wait grows with the chain (about 10 minutes at height 414 in the first
# development run), so the budget is Q4_JOINER_RESTORE_SECONDS and the wait prints what the restore has retained so far.
q4_joiner_restore() {
  [ "$1" = "$Q4_IN" ] || return 0
  local i=$Q4_IN n t0=$SECONDS
  if ! { [ -f "test-nodes/evm$i/pid" ] && kill -0 "$(cat "test-nodes/evm$i/pid")" 2>/dev/null; }; then
    EVM_ARCHIVE_REPLICA_POOL="1 2 3 $i" H3_ONLINE="1 2 3" H3_RESTORE_NO_SESSION=1 H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json H3_RESTORE_LOG_LEVEL=debug \
      h3_restore_validator "$i" 2 || return 1
  fi
  for n in $(seq 1 "${Q4_JOINER_RESTORE_SECONDS:-2700}"); do
    if curl -fsS -m 5 -X POST -H 'content-type: application/json' -d '{}' "http://$(evm_validator_rpc_addr "$i")/api/v1/q3/status" >/dev/null 2>&1; then
      echo "joiner evm$i restored and serving its status after $((SECONDS - t0))s (archive $(du -sk "$H3_ARCHIVES/evm$i" 2>/dev/null | cut -f1) KiB)"
      return 0
    fi
    kill -0 "$(cat "test-nodes/evm$i/pid")" 2>/dev/null || { echo "the restoring joiner evm$i exited after $((SECONDS - t0))s" >&2; tail -30 "test-nodes/evm$i/debug.log" | cut -c1-400 >&2; return 1; }
    [ $((n % 60)) != 0 ] || echo "joiner evm$i restoring: $((SECONDS - t0))s, archive $(du -sk "$H3_ARCHIVES/evm$i" 2>/dev/null | cut -f1) KiB, log lines $(wc -l <"test-nodes/evm$i/debug.log" | tr -d ' '), source height $(grep -a 'certificate admitted' test-nodes/evm1/debug.log | tail -1 | grep -o 'height=[0-9]*')"
    sleep 1
  done
  echo "the restoring joiner evm$i never served its status within ${Q4_JOINER_RESTORE_SECONDS:-2700}s" >&2; tail -30 "test-nodes/evm$i/debug.log" | cut -c1-400 >&2
  return 1
}

q4_handoff_ab_turnover() {
  local next=3 in=$Q4_IN out=$Q4_OUT rc=0 i
  : >"$Q4_DIR/non-members.txt"
  # the retained weight in both maps, from the lane's own numbers (old: Q3_WEIGHTS over 1 2 3 4; new: Q4_B_WEIGHTS over Q4_B_ENTITIES)
  python3 - "$Q3_WEIGHTS" "$Q4_B_WEIGHTS" "$Q4_B_ENTITIES" "$out" "$in" <<'PY' | tee "$Q4_DIR/turnover-arithmetic.txt" || return 1
import sys
old = dict(zip("1 2 3 4".split(), map(int, sys.argv[1].split())))
new = dict(zip(sys.argv[3].split(), map(int, sys.argv[2].split())))
out, inn = sys.argv[4], sys.argv[5]
kept = [e for e in old if e in new]
W, V = sum(old.values()), sum(new.values())
qo, qn = 2 * W // 3 + 1, 2 * V // 3 + 1
ko, kn = sum(old[e] for e in kept), sum(new[e] for e in kept)
dist = sum(abs(old.get(e, 0) * V - new.get(e, 0) * W) for e in set(old) | set(new))
print(f"old map (root epoch 2): {old}, W={W}, Q={qo}")
print(f"new map (root epoch 3): {new}, V={V}, Q={qn}")
print(f"replaced: entity {out} (weight {old[out]}) by entity {inn} (weight {new[inn]}); changed identities 1 of {len(old)}")
print(f"retained entities {kept}: old weight {ko} >= {qo}, new weight {kn} >= {qn}")
print(f"weight distance sum|w*V-v*W| = {dist} over V*W = {V * W}")
ok = set(old) - set(new) == {out} and set(new) - set(old) == {inn} and ko >= qo and kn >= qn and 3 * 1 < len(old)
sys.exit(0 if ok else "the turnover is not one-of-four with a retained quorum in both maps")
PY
  H3_ONLINE="1 2 3 4"
  # the joiner's restore is anchored at the genesis trust base and catches up through the verified handoffs; the activation of epoch 2 is not archived
  # as a bundle, so the restore pin is told its V3 body identity (as the Q3 lane's second pair is)
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  export H4_RESTORE_BODY_IDS="2=$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id.txt")"
  if [ ! -f "test-nodes/root$in/node-info.json" ]; then
    build/ubft root-node init --home "test-nodes/root$in" -g >/dev/null || return 1
    generate_log_configuration "test-nodes/root$in/"
  fi
  # the successor trust base: roots 1 2 3 and the joiner's with the B weights, signed by them (the replaced root does not sign)
  Q3_WEIGHTS=$Q4_B_WEIGHTS h3_q3_trust_base "$next" "$Q4_B_ENTITIES" || { echo "the successor trust base was not built" >&2; return 1; }
  # the joiner before the Commit: its root a follower of the epoch-2 committee, its authority pending at the successor scope, its execution client
  # paired; it is a later joiner (one activation precedes it), so its shard node comes up by a staging-only restore at its readiness turn
  [ -n "${Q4_JOINER_MARK:-}" ] || { Q4_JOINER_MARK=$(wc -l <"test-nodes/root$in/debug.log" 2>/dev/null | tr -d ' '); Q4_JOINER_MARK=${Q4_JOINER_MARK:-0}; }
  # (a joiner whose root already answers as a follower is left as it is: the root's start is not idempotent, and a development retry re-enters here)
  if [ "$(q4_status_of "$in" 2>/dev/null | jq -r .follower 2>/dev/null)" != true ]; then
    EVM_ARCHIVE_REPLICA_POOL="1 2 3 $in" H3_ONLINE="1 2 3" h3_q3_start_joiner "$in" 2 "$next" "trust-base-epoch${next}.json" 2 || { echo "the joiner's stack did not start" >&2; return 1; }
  fi
  echo "joiner entity $in started before the Commit: root$in follows the epoch-2 committee"

  Q3_WEIGHTS=$Q4_B_WEIGHTS; Q3_SUFFIX=-2; Q3_NEXT_EPOCH=$next; Q3_ASSIGN_TAG=cand2; Q3_INCUMBENT=$Q3_DIR/cand-identities.json; Q3_ENTITIES=$Q4_B_ENTITIES
  Q4_TURNOVER_ACTIVE=1; unset Q3_SUPERSEDE
  Q3_BEFORE_READINESS=q4_joiner_restore h3_retry_handoff $((next - 1)) q3_attempt || rc=1
  if [ "$rc" = 0 ]; then
    [ "$(jq -r .signingScheme "$Q3_DIR/candidate-config-2.json")" = 2 ] || { echo "the turnover handoff does not select scheme 2" >&2; rc=1; }
    q3_check_weights set "$Q3_DIR/root-weights-2.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM" >/dev/null || rc=1
    q3_check_weights set-evm "$Q3_DIR/evm-weights-2.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM" >/dev/null || rc=1
    # the committed candidate names the joiner and not the replaced entity, on both sides
    for i in root evm; do
      if [ "$i" = root ]; then set -- "$(h3_root_id "$in")" "$(h3_root_id "$out")"; else set -- "$(evm_validator_id "$in")" "$(evm_validator_id "$out")"; fi
      jq -e --arg a "$1" --arg b "$2" '(map(.nodeId) | index($a)) != null and (map(.nodeId) | index($b)) == null' "$Q3_DIR/$i-weights-2.json" >/dev/null || {
        echo "the $i weights of the committed candidate do not replace entity $out by entity $in: $(jq -c . "$Q3_DIR/$i-weights-2.json")" >&2; rc=1; }
    done
  fi
  Q3_WEIGHTS=$Q3_WEIGHTS_1; unset Q3_SUFFIX Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_INCUMBENT Q3_ENTITIES Q4_TURNOVER_ACTIVE
  [ "$rc" = 0 ] || return 1
  echo "handoff 2 (turnover) committed at root epoch $((next - 1)): entity $out out, entity $in in"
}
# L5, the joiner before its install: a follower of epoch 2 that signed nothing while the committee planned and committed the handoff that names it.
# Its own step: the handoff step is not re-enterable after its Commit.
q4_joiner_follows() {
  [ -n "${Q4_JOINER_MARK:-}" ] || { echo "the joiner was not started by the turnover handoff" >&2; return 1; }
  q4_non_member "$Q4_IN" 2 "$Q4_JOINER_MARK" "the joiner before its install (epoch 2 committee, handoff committed)"
}

# After the turnover's install restart: the replaced entity's root, restarted into epoch 3 over its retained home, is a removed validator. Its EVM
# validator is stopped (the successor assignment does not name it). The committee commits without it.
q4_removed_validator_follows() {
  local out=$Q4_OUT base now i ids
  [ -n "${Q4_OUT_MARK:-}" ] || { echo "the replaced root was not restarted by the turnover install" >&2; return 1; }
  base=$(q4_round "$(h3_first_root)") || return 1
  for i in $(seq 1 "$Q4_RECOVER_SECONDS"); do   # at least one local timeout of the removed root (its refused signature) while the committee commits
    now=$(q4_round "$(h3_first_root)") || return 1
    [ "$now" -ge $((base + 5)) ] && tail -n +"$((Q4_OUT_MARK + 1))" "test-nodes/root$out/debug.log" | grep -aq 'it follows and signs nothing: epoch 3' && break
    sleep 1
  done
  [ "$now" -ge $((base + 5)) ] || { echo "the epoch-3 committee did not commit 5 rounds beside the removed root ($base -> $now)" >&2; return 1; }
  q4_non_member "$out" 3 "$Q4_OUT_MARK" "the removed validator after the install (epoch 3 committee committed rounds $base -> $now beside it)" || return 1
  # no epoch-3 certificate names it: the signers of the committee's current certificate, read from a member root's verified state
  ids=$(q3_signers_of "$(h3_first_root)") || return 1
  [ "$(printf '%s' "$ids" | jq -r .epoch)" = 3 ] || { echo "the first root's certificate is not of epoch 3" >&2; return 1; }
  printf '%s' "$ids" | jq -e --arg id "$(h3_root_id "$out")" '[.. | strings] | index($id) == null' >/dev/null || { echo "the removed root's identity is in an epoch-3 certificate: $ids" >&2; return 1; }
  echo "epoch-3 certificate at round $(printf '%s' "$ids" | jq -r .round): the removed root's identity is not among its signers" | tee -a "$Q4_DIR/non-members.txt"
  # the joiner is now a member: it no longer reports follower and it signs
  [ "$(q4_status_of "$Q4_IN" | jq -r .follower)" != true ] || { echo "the joiner's root still reports follower in epoch 3" >&2; return 1; }
  grep -aq 'msg="signed vote"' <(tail -n +"$((Q4_IN_MARK + 1))" "test-nodes/root$Q4_IN/debug.log") || { echo "the joiner's root signed no vote in epoch 3" >&2; return 1; }
  echo "root$Q4_IN ($(h3_root_id "$Q4_IN")) after the install: a member of epoch 3, no longer a follower, signs votes" | tee -a "$Q4_DIR/non-members.txt"
}

q4_first_successor_held() {
  local r i hits=0 before t0 successors=$H3_ROOTS
  [ "$Q4_TURNOVER" != 1 ] || successors=$Q4_B_ENTITIES
  for r in $H3_ROOTS; do
    before=$(q3_signers_of "$r" | jq -r .epoch) || return 1
    [ "$before" = 2 ] || { echo "root $r reports a certificate of epoch $before before its install restart into 3" >&2; return 1; }
  done
  # the rule goes to every root that can propose in epoch 3: the successor committee (under the turnover the joiner's root, not the replaced one)
  for r in $successors; do
    q4_ctl "$r" "{'rules':[{'name':'succ3','class':'proposal','epoch':3,'action':'hold','require':true}]}" || return 1
  done
  if [ "$Q4_TURNOVER" = 1 ]; then
    # the replaced entity's EVM validator and the joiner's staging-only shard node stop before the roots install the successor set (the joiner's
    # comes back by the post-install restore, with a session, in "B in effect")
    stop_pidfile "test-nodes/evm$Q4_OUT/pid" 'ubft shard-node (run|restore)' INT || return 1
    stop_pidfile "test-nodes/evm$Q4_IN/pid" 'ubft shard-node (run|restore)' INT || return 1
  fi
  # h3_restart_roots' restart loop without its final wait: the committed head cannot reach epoch 3 while every successor proposal is held
  local prev order=$H3_ROOTS
  # under the turnover the new root restarts first (h3_q3_activate_coupled's order), the retained roots follow, and the replaced root comes last: it is
  # restarted into epoch 3 too and stays up as a removed validator (L5), holding no rule (it is not a member and proposes nothing)
  [ "$Q4_TURNOVER" != 1 ] || order="$Q4_IN 1 2 3 $Q4_OUT"
  for r in $order; do
    prev=$(echo "$H3_ROOTS" | tr ' ' '\n' | grep -vx "$r" | head -1)
    stop_pidfile "test-nodes/root$r/pid" 'ubft root-node' || return 1
    for _ in $(seq 1 50); do lsof -nP -iTCP:"$(m2_rpc_port "$r")" -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 0.2; done
    m2_archive_root_state "$r" 3 || return 1
    [ "$r" != "${Q4_OUT:-}" ] || [ "$Q4_TURNOVER" != 1 ] || Q4_OUT_MARK=$(wc -l <"test-nodes/root$r/debug.log" | tr -d ' ')
    [ "$r" != "${Q4_IN:-}" ] || [ "$Q4_TURNOVER" != 1 ] || Q4_IN_MARK=$(wc -l <"test-nodes/root$r/debug.log" | tr -d ' ')
    m2_start_root "$r" 3 "$(m2_root_addr "$prev")" || { echo "root $r did not restart into epoch 3" >&2; return 1; }
  done
  # from here the committee is the successor set: the lane's root lists follow it (the replaced root stays up, outside them)
  # (the offline trace check still reads every root that ever ran: the Byzantine rows of epoch 2 armed the replaced root)
  if [ "$Q4_TURNOVER" = 1 ]; then Q4_TRACE_ROOTS="1 2 3 $Q4_OUT $Q4_IN"; H3_ROOTS=$Q4_B_ENTITIES; Q4_ROOTS=$Q4_B_ENTITIES; fi
  for i in $(seq 1 120); do
    hits=0; for r in $H3_ROOTS; do hits=$((hits + $(q4_hits "$r" succ3))); done
    [ "$hits" -gt 0 ] && break
    sleep 1
  done
  [ "$hits" -gt 0 ] || { echo "no root attempted an epoch-3 proposal within 120 s" >&2; return 1; }
  # A root that installed epoch 3 holds the new epoch's anchor as its committed head (roundInfo reports epoch 3 from the restart on) and answers the
  # signers query with an error until a quorum certificate of epoch 3 exists. While every successor proposal is held, no root may report an epoch-3
  # certificate and no root's committed round may move.
  local e rounds0 rounds1
  rounds0=$(for r in $H3_ROOTS; do q4_round "$r"; done | tr '\n' ' ')
  sleep 10
  rounds1=$(for r in $H3_ROOTS; do q4_round "$r"; done | tr '\n' ' ')
  [ "$rounds0" = "$rounds1" ] || { echo "committed rounds moved ($rounds0-> $rounds1) while every successor proposal was held" >&2; return 1; }
  for r in $H3_ROOTS; do
    e=$(q3_signers_of "$r" 2>/dev/null | jq -r .epoch 2>/dev/null)
    [ "$e" != 3 ] || { echo "root $r reached an epoch-3 certificate while every successor proposal was held" >&2; return 1; }
  done
  echo "while held: committed rounds constant at ${rounds1}for 10 s, no epoch-3 certificate at any root"
  python3 - "$Q4_SHIM_DIR" $H3_ROOTS <<'PY' | tee "$Q4_DIR/first-successor-proposal.txt" || return 1
import json, os, sys
first = None
for r in sys.argv[2:]:
    # a proposal's copy to its own author is never subject to a rule (the shim leaves self-sends alone): only the sends to other roots count
    me = json.load(open(os.path.join(sys.argv[1], f"root{r}", "status.json"))).get("self")
    evs = []
    for line in open(os.path.join(sys.argv[1], f"root{r}", "trace.jsonl")):
        try:
            evs.append(json.loads(line))
        except ValueError:
            pass
    for i, ev in enumerate(evs):
        if ev.get("kind") == "attempt" and ev.get("class") == "proposal" and ev.get("epoch") == 3 and ev.get("to") != me:
            nxt = next((e for e in evs[i + 1:] if e.get("sendId") == ev["sendId"] and e.get("to") == ev["to"]), None)
            if first is None or ev["time"] < first[0]:
                first = (ev["time"], r, ev["round"], nxt and nxt.get("kind"), nxt and nxt.get("rule"))
            break
if first is None:
    sys.exit("no epoch-3 proposal attempt in any trace")
print(f"first successor (epoch 3) proposal: root{first[1]} round {first[2]} at {first[0]}; its first outcome: {first[3]} by rule {first[4]}")
sys.exit(0 if first[3] == "hold" and first[4] == "succ3" else "the first successor proposal was not held")
PY
  t0=$(q4_t)
  q4_heal succ3 "$H3_ROOTS" || return 1
  for i in $(seq 1 "$Q4_RECOVER_SECONDS"); do
    [ "$(q3_signers_of "$(h3_first_root)" 2>/dev/null | jq -r .epoch 2>/dev/null)" = 3 ] && break
    sleep 1
  done
  q3_signers_of "$(h3_first_root)" | jq -c . >"$Q3_DIR/first-epoch3-certificate.json"
  [ "$(jq -r .epoch "$Q3_DIR/first-epoch3-certificate.json")" = 3 ] || { echo "no epoch-3 certificate within ${Q4_RECOVER_SECONDS}s of the release" >&2; return 1; }
  q4_timing successor-release root="$(h3_first_root)" first_s="$(q4_dt "$(q4_t)" "$t0")" deadline_s="$Q4_RECOVER_SECONDS" ok=true
  q3_history_ids "$Q3_DIR/history-ids-epoch3.txt"
  for r in $H3_ROOTS; do q4_clear "$r" || return 1; done
}

q4_b_in_effect() {
  local i
  q3_activation_n 2 3 || return 1
  if [ "$Q4_TURNOVER" = 1 ]; then
    # the retained validators' authorities advance to the activated scope; the joiner's authority is enrolled against it and the joiner's shard node
    # is restored through it from a retained validator's archive (the replaced validator is no longer a valid replica)
    # (online: the retained three until the joiner's restore; the joiner's shard node and the replaced one are stopped)
    H3_ONLINE="1 2 3"; export EVM_ARCHIVE_REPLICA_POOL=$Q4_B_ENTITIES; Q3_ENTITIES=$Q4_B_ENTITIES
    export H4_RESTORE_BODY_IDS="2=$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id.txt"),3=$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id-2.txt")"
    H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
    # no wait for replica acknowledgements: validators 2 and 3 name the joiner as a replica and it is down until its restore below
    M2_ADVANCE_NO_REPLICA_WAIT=1 H3_RESTORE_RESTART= h3_advance_authorities 3 2 1 2 3 || { echo "authority advance to root epoch 3 / shard epoch 2 failed" >&2; return 1; }
    h3_enroll_authority "$Q4_IN" 2 || { echo "enrolling the joiner's authority failed" >&2; return 1; }
    H3_RESTORE_LOG_LEVEL=debug h3_restore_validator "$Q4_IN" 2 || { echo "the joiner's shard node was not restored" >&2; return 1; }
  else
  M2_ADVANCE_NO_REPLICA_WAIT=0 h3_advance_authorities 3 2 1 2 3 4 || { echo "authority advance to root epoch 3 / shard epoch 2 failed" >&2; return 1; }
  fi
  for i in $(seq 1 180); do h3_registry_is 2 3 && break; sleep 1; done
  h3_registry_is 2 3 || { echo "registry did not reach shard epoch 2 / root epoch 3" >&2; return 1; }
  # from here the lane's own view of the committee is B: the weighted-epoch gate, the heavy roots and the restart epoch follow it
  Q3_WEIGHTS=$Q4_B_WEIGHTS; Q4_EPOCH=3; Q4_HEAVY_ROOTS="1 2"; Q4_HEAVY_ROOT=1
  Q4_GATE_CANDIDATE=$Q3_DIR/candidate-config-2.json q4_weighted_epoch_check | tee "$Q4_DIR/b-in-effect.txt" || return 1
  # under the turnover the joiner's EVM validator has caught up and takes part before the paid transaction goes to every online validator, it included
  if [ "$Q4_TURNOVER" = 1 ]; then q4_evm_joiner_participates || return 1; H3_ONLINE=$Q4_B_ENTITIES; fi
  h3_paid 3 || { echo "post-handoff paid transaction was not certified at root epoch 3" >&2; return 1; }
  q3_evm_request_weights_since_b
}

# Under the turnover the joiner's EVM validator is restored after the install. B in effect on the EVM side means it takes part: a root counts its
# certification request in an epoch-3 consensus of the EVM shard, and its own journal admits a certificate of root epoch 3.
q4_evm_joiner_participates() {
  local id line="" n r
  id=$(evm_validator_id "$Q4_IN") || return 1
  for n in $(seq 1 "${Q4_JOINER_RESTORE_SECONDS:-2700}"); do
    for r in $H3_ROOTS; do
      line=$(grep -a 'partition 00000008 reached consensus' "test-nodes/root$r/debug.log" | grep -a "requestNodeIDs=\"\[[^]]*$id" | tail -n 1)
      [ -z "$line" ] || break
    done
    [ -n "$line" ] && grep -Eaq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "test-nodes/evm$Q4_IN/debug.log" && break
    kill -0 "$(cat "test-nodes/evm$Q4_IN/pid")" 2>/dev/null || { echo "the joiner's EVM validator exited" >&2; tail -30 "test-nodes/evm$Q4_IN/debug.log" | cut -c1-400 >&2; return 1; }
    [ $((n % 60)) != 0 ] || echo "waiting for the joiner's EVM validator to take part: ${n}s, log lines $(wc -l <"test-nodes/evm$Q4_IN/debug.log" | tr -d ' ')"
    sleep 1
  done
  [ -n "$line" ] || { echo "no root counted a certification request of the joiner's EVM validator $id" >&2; tail -30 "test-nodes/evm$Q4_IN/debug.log" | cut -c1-400 >&2; return 1; }
  grep -Eaq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "test-nodes/evm$Q4_IN/debug.log" || { echo "the joiner's EVM validator admitted no certificate of root epoch 3" >&2; return 1; }
  { echo "the joiner's EVM validator $id is counted by root$r: ${line#*msg=}" | cut -c1-600
    echo "evm$Q4_IN: $(grep -Ea 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "test-nodes/evm$Q4_IN/debug.log" | tail -n 1 | sed 's/.*msg=//' | cut -c1-200)"; } | tee "$Q4_DIR/b-evm-joiner.txt"
}

# the roots' weighted EVM consensus lines since the handoff verify against the B weights (W=9, Q=5)
q3_evm_request_weights_since_b() {
  local out=$Q4_DIR/b-evm-request-weights.txt i
  : >"$out"
  # every root of the committee must show checked lines: a root whose lines fail the check is not dropped silently
  for i in $H3_ROOTS; do
    q3_check_request_weights "$Q3_EVM_TOTAL_WEIGHT" "$Q3_EVM_QUORUM" "test-nodes/root$i/debug.log" >>"$out" || { echo "root $i: its weighted EVM consensus lines do not verify (or it has none)" >&2; return 1; }
  done
  [ -s "$out" ] || { echo "no weighted EVM consensus line in any root log" >&2; return 1; }
}

# the heavy-placement scenario runs (Q4_HEAVY_AT=2..4): the weight-6 root is root k; F1's remaining placements
q4_run_placement_rows() {
  q4_step "placement: SIGKILL the heavy root: stall, restart recovers" q4_row_heavy_sigkill
  q4_step "placement: all lights isolated: heavy alone (6) and the lights (3) both stall, heal releases" q4_row_all_lights_partition
  q4_step "placement: two lights isolated: heavy and one light (7 = Q) progress, heal releases" q4_row_two_lights_partition
  q4_step "placement: EVM-only outage: the heavy entity's EVM pair down (3 < request Q=5): EVM stalls while the roots commit; restart recovers" q4_row_evm_outage stall "$Q4_HEAVY_ROOT"
}

# Q3: every recovery and the no-fault control left its numbers in q4/timing.jsonl, each within the frozen deadline; a summary table is written beside it
q4_row_timing_exported() {
  python3 - "$Q4_DIR/timing.jsonl" "$Q4_DIR/timing-summary.txt" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
ctl = [r for r in rows if r["kind"] == "control"]
rec = [r for r in rows if r["kind"] in ("root-commit", "evm-commit")]
bad = [r for r in rec if r.get("ok") != "true" or not isinstance(r.get("first_s"), (int, float)) or not isinstance(r.get("nth_s"), (int, float)) or r["nth_s"] > r["deadline_s"]]
lines = ["kind         first_s  nth_s   max_gap_s  tc  n  step"]
for r in ctl:
    lines.append(f"control      -        -       {r['max_gap_s']!s:<9}  {r['tc']!s:<3} {r['root_commits']} root / {r['evm_commits']} EVM commits in {r['window_s']}s  {r['step']}")
for r in rec + [r for r in rows if r["kind"] == "successor-release"]:
    lines.append(f"{r['kind']:<12} {r.get('first_s', '-')!s:<8} {r.get('nth_s', '-')!s:<7} {r.get('max_gap_s', '-')!s:<10} {r.get('tc', '-')!s:<3} {r.get('n', '-')}  {r['step']}")
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
if not ctl:
    sys.exit("no no-fault control record")
if not any(r["kind"] == "evm-commit" for r in rec):
    sys.exit("no EVM recovery record")
if bad:
    sys.exit(f"{len(bad)} recovery records without numbers or over the deadline: {bad[:3]}")
PY
}

q4_row_trace_check() {
  local list=${Q4_TRACE_ROOTS:-$Q4_ROOTS} roots r peers=() windows=(--byz-windows "$Q4_DIR/byz-windows.jsonl")
  roots=$(echo $list | tr ' ' ',')
  for r in $list; do peers+=(--peer "$r=$(q4_peer "$r")"); done
  # a development run that skips the fault rows armed no Byzantine adapter and wrote no windows file
  [ "${Q4_DEV_SKIP_FAULT_ROWS:-0}" != 1 ] || [ -f "$Q4_DIR/byz-windows.jsonl" ] || windows=()
  # a SIGKILLed root's torn last trace line is dropped by the checker's loader only if it is the final line. The declared Byzantine set is the union of the rows' sets; the
  # windows hold every equivocation in the traces to the row that armed it.
  python3 scripts/q4-trace-check.py "$Q4_SHIM_DIR" --roots "$roots" ${Q4_BYZ_ROOTS:+--byzantine "$Q4_BYZ_ROOTS"} ${windows[@]+"${windows[@]}"} "${peers[@]}" \
    | tee "$Q4_DIR/trace-report.json" | jq -e '.verdict == "PASS"' >/dev/null
}

# the Q3 flow's own initialisation (what q3_run_lane does before its steps) and the activation prefix; each step is the Q3 step, with its Q3 evidence under $Q3_DIR
Q4_ACTIVATION_STEPS="q3_baseline q3_candidate q3_handoff q3_install_epoch2 q3_activation q3_acknowledge q3_progress_scheme2"
# after the activation prefix and before any fault: the leader selector in effect (the Q3 step, over a window of rounds) and the follower status of every root
Q4_PRE_FAULT_STEPS="q4_leader_schedule q4_no_followers"
q4_activate_weighted_epoch() {
  local s
  q3_lane_init
  echo "=== Q4 live lane, scenario $Q4_SCENARIO: fresh-B1 unit PoA -> mirrored weights $Q3_WEIGHTS (the Q3 flow), then the Q4 fault rows ==="
  for s in $Q4_ACTIVATION_STEPS; do q3_step "$s" "$s"; done
}

# The selector in effect is part of the weighted epoch the rows run in: enough epoch-2 rounds to judge the schedule, then the Q3 step that measures who led them
# (weight-proportional root-wrr-v1, not the legacy uniform selector) from the roots' own logs.
q4_leader_window() {
  local astar round i
  astar=$(jq -r .activationRound "$Q3_DIR/activation-record.json") || return 1
  for i in $(seq 1 180); do
    round=$(q3_signers_of "$(h3_first_root)" | jq -r .round) || return 1
    [ $((round - astar)) -ge 45 ] && return 0
    sleep 1
  done
  echo "fewer than 45 rounds of epoch $Q4_EPOCH after A*=$astar within 180 s" >&2
  return 1
}
q4_leader_schedule() { q4_leader_window && q3_leader_schedule; }

# #515: every root of the weighted epoch is a member of its committee, so none reports itself a follower and the membership gate in the signing path admits it.
q4_no_followers() {
  local r st
  : >"$Q4_DIR/followers.txt"
  for r in $H3_ROOTS; do
    st=$(curl -fsS -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url "$r")/api/v1/q3/status") || return 1
    printf 'root%s: %s\n' "$r" "$(printf '%s' "$st" | jq -c .)" >>"$Q4_DIR/followers.txt"
    [ "$(printf '%s' "$st" | jq -r '.follower // false')" = false ] || { echo "root$r reports itself a follower in the weighted epoch: $st" >&2; return 1; }
    [ "$(printf '%s' "$st" | jq -r .activeEpoch)" = "$Q4_EPOCH" ] || { echo "root$r is not at the installed epoch $Q4_EPOCH: $st" >&2; return 1; }
  done
}

q4_run_lane() {
  mkdir -p "$Q4_DIR"
  : >"$Q4_DIR/byz-windows.jsonl"
  q4_activate_weighted_epoch
  q4_step "leader selector in effect: weight-proportional root-wrr-v1 over the epoch's rounds" q4_leader_schedule
  q4_step "no root of the weighted epoch reports itself a follower (#515 membership gate)" q4_no_followers
  q4_precondition
  q4_step "baseline: weighted epoch commits (F8 trace and EVM IR)" q4_row_baseline
  q4_step "no-fault control at the lane's load: root commit latency, gaps and TC count, EVM certifications (Q3 timing control)" q4_row_nofault_control
  if [ "$Q4_HEAVY_AT" != 1 ]; then
    q4_run_placement_rows
    q4_step "Q3 timing: first/third commit latency, max commit gap, TC count and EVM recovery latency exported as numbers" q4_row_timing_exported
    q4_step "offline trace check: attempts have outcomes, equivocators are exactly the declared Byzantine roots" q4_row_trace_check
    echo "Q4 live lane: all steps PASSED"
    q4_teardown
    return 0
  fi
  q4_step "F8 aggregator shards stay served by the weighted epoch (authorized TR rounds advance, aggregators answer)" q4_row_f8_follow
  q4_step "F8 aggregator shards certify new state roots in the weighted epoch; the roots verify their rsmt proofs (T1)" q4_row_f8_new_roots
  if [ "$Q4_SCENARIO" = A ]; then
   if [ "${Q4_DEV_SKIP_FAULT_ROWS:-0}" = 1 ]; then echo "DEVELOPMENT OVERRIDE: scenario A's fault rows before the handoff are skipped: NOT EVIDENCE"; else
    q4_step "one light root isolated (held both ways): 8 of 9 progresses, heal releases" q4_row_light_partition
    q4_step "two lights isolated: heavy and one light (7 = Q) progress, heal releases" q4_row_two_lights_partition
    q4_step "all lights isolated: heavy alone (6) and the lights (3) both stall, heal releases" q4_row_all_lights_partition
    q4_step "heavy root delayed: quorum lost, explicit stall, release recovers" q4_row_heavy_delayed
    q4_step "SIGKILL a light root and restart over the retained home" q4_row_light_sigkill
    q4_step "SIGKILL the heavy root: stall, restart recovers" q4_row_heavy_sigkill
    q4_step "two Byzantine lights (weight 2) equivocate: honest 7 progresses" q4_row_byzantine_lights
    q4_step "the heavy root (weight 6 > F) equivocates alone, outside the assumptions: the equivocation is real, the checker classifies it" q4_row_byzantine_heavy
    q4_step "T2: root quorum lost (heavy held): local T2 expiry, root epoch/round, shard IR/TR round and EVM height recorded separately; no root-certified retry" q4_row_t2_quorum_loss
    q4_step "EVM-only outage: the heavy entity's EVM pair down (3 < request Q=5): EVM stalls while the roots commit; restart recovers" q4_row_evm_outage stall "$Q4_HEAVY_ROOT"
    q4_step "EVM-only outage: one light entity's EVM pair down (8 >= request Q=5): EVM certifies while the roots commit; restart" q4_row_evm_outage progress "$(q4_lights | tail -n 1)"
    q4_step "EVM-only partition: the heavy entity's EVM pair cut from every root (3 < request Q=5): EVM stalls, roots commit; heal without rollback" q4_row_evm_cut stall "$Q4_HEAVY_ROOT"
    q4_step "EVM-only partition: one light entity's EVM pair cut from every root (8 >= request Q=5): EVM certifies; heal without rollback" q4_row_evm_cut progress "$(q4_lights | tail -n 1)"
    q4_step "delay of shard requests: every root holds the EVM shard's certification requests: EVM stalls, roots commit; release recovers" q4_row_shard_requests_delayed
    q4_step "G2 rollback: an executed EVM block is abandoned uncertified and a different block is certified on its parent; finalized never moves back, the transaction lands once" q4_row_g2_rollback
    q4_step "duplicate on the network: the lights' traffic duplicated while the heavy is held: no replayed weight (stall), then commits with every message doubled" q4_row_duplicates
    q4_step "reorder on the network: the heavy root's held traffic released last-in-first-out: recovery" q4_row_reorder
    q4_step "authentication refusals: impersonation of the heavy, unknown signer, bad signature, wrong domain, old form, wrong epoch both ways, stale: each refused, zero live weight" q4_row_auth_refusals
    q4_step "quorum-wide restart: every root SIGKILLed and restarted together over its retained home: roots and EVM recover" q4_row_quorum_restart
   fi
    if [ "$Q4_TURNOVER" = 1 ]; then
      q4_step "F17 turnover: second handoff A to B committed on the running chain: entity c replaced by a new entity d (6,1,1,1 -> 3,3,2,1), the retained three hold 8 of 9 in both maps" q4_handoff_ab_turnover
      q4_step "L5: the joiner's root, running beside the epoch-2 committee through the handoff that names it, follows and signs nothing before its install" q4_joiner_follows
    else
      q4_step "F17: second handoff A to B committed on the running chain (the four entities reweighted 6,1,1,1 -> 3,3,2,1)" q4_handoff_ab
    fi
    q4_step "F17: the first successor proposal held across the install restart into epoch 3; release, epoch 3 commits" q4_first_successor_held
    [ "$Q4_TURNOVER" != 1 ] || q4_step "L5: the removed validator's root, restarted into epoch 3, follows and signs nothing while the new committee commits; the joiner's root is a member and signs" q4_removed_validator_follows
    q4_step "F17: B in effect: epoch 3 activated and acknowledged, scheme 2 certificates of 3,3,2,1, paid transaction certified" q4_b_in_effect
    q4_step "F17 B: the EVM pair of one weight-3 entity cut from every root (6 >= request Q=5): EVM certifies; heal without rollback" q4_row_evm_cut progress 1
    q4_step "F17 B: the EVM pairs of both weight-3 entities cut from every root (3 < request Q=5): EVM stalls, roots commit; heal without rollback" q4_row_evm_cut stall 1 2
  else
    q4_step "B: the weight-1 root isolated: 8 of 9 progresses, heal releases" q4_row_b_light_one
    q4_step "B: the weight-2 root isolated: 7 = Q progresses, heal releases" q4_row_b_light_two
    q4_step "B: the weight-2 and weight-1 roots isolated: the two weight-3 roots (6) stall, heal releases" q4_row_b_lights_both
    q4_step "B: one weight-3 root delayed: 6 of 9, quorum lost, explicit stall, release recovers" q4_row_heavy_delayed
    q4_step "B: SIGKILL the weight-2 root and restart over the retained home" q4_row_light_sigkill
    q4_step "B: SIGKILL each weight-3 root in turn: 6 left, stall, restart recovers" q4_row_heavy_sigkill
    q4_step "B: the weight-2 root (= F, in bound) equivocates: honest 3+3+1 progress" q4_row_byzantine_lights
    q4_step "B: a weight-3 root (> F) equivocates alone, outside the assumptions: the equivocation is real, the checker classifies it" q4_row_byzantine_heavy
    q4_step "B T2: root quorum lost (one weight-3 root held): local T2 expiry, root epoch/round, shard IR/TR round and EVM height recorded separately; no root-certified retry" q4_row_t2_quorum_loss
    q4_step "B: the EVM pair of one weight-3 entity cut from every root (6 >= request Q=5): EVM certifies; heal without rollback" q4_row_evm_cut progress 1
    q4_step "B: the EVM pairs of both weight-3 entities cut from every root (3 < request Q=5): EVM stalls, roots commit; heal without rollback" q4_row_evm_cut stall 1 2
    q4_step "B G2 rollback: an executed EVM block is abandoned uncertified and a different block is certified on its parent; finalized never moves back, the transaction lands once" q4_row_g2_rollback
    q4_step "B: authentication refusals: impersonation of a weight-3 root, unknown signer, bad signature, wrong domain, old form, wrong epoch both ways, stale: each refused, zero live weight" q4_row_auth_refusals
    q4_step "B: quorum-wide restart: every root SIGKILLed and restarted together over its retained home: roots and EVM recover" q4_row_quorum_restart
  fi
  q4_step "Q3 timing: first/third commit latency, max commit gap, TC count and EVM recovery latency exported as numbers" q4_row_timing_exported
  q4_step "offline trace check: attempts have outcomes, equivocators are exactly the declared Byzantine roots" q4_row_trace_check
  echo "Q4 live lane: all steps PASSED"
  q4_teardown
}
# q4_unresolved <function>...: every command name a function body calls, transitively through the lane's own functions, that is neither a function,
# a builtin nor a program on PATH. Read from `declare -f` (one command per line): the first word of each line and of each list or substitution.
# Leading `NAME=value` words of a command are skipped (the command is the word after them).
# The dry run uses it, so a helper that is not sourced is found without a devnet.
q4_unresolved() {
  local -a todo=("$@"); local seen=" " fn w
  while [ "${#todo[@]}" -gt 0 ]; do
    fn=${todo[0]}; todo=("${todo[@]:1}")
    case "$seen" in *" $fn "*) continue ;; esac
    seen+="$fn "
    declare -F "$fn" >/dev/null || { echo "$fn"; continue; }
    for w in $(declare -f "$fn" | sed '1,2d;$d' | awk "/<<'?PY'?/ {skip=1; print; next} /^PY\$/ {skip=0; next} !skip" \
      | sed -E -e ':a' -e 's/(^[[:space:]]*|[;&|(][[:space:]]*|(^|[[:space:]])(if|then|do|else|elif|while|until|!)[[:space:]]+)[A-Za-z_][A-Za-z0-9_]*=("[^"]*"|\$\([^)]*\)|[^[:space:];|&]*)[[:space:]]+/\1/' -e 'ta' \
      | grep -oE "(^[[:space:]]*|[;&|(][[:space:]]*|(^|[[:space:]])\\{[[:space:]]+|\\$\\([[:space:]]*|(^|[[:space:]])(if|then|else|elif|do|while|until|!)[[:space:]]+)[A-Za-z_][A-Za-z0-9_]*=?" \
      | grep -v '=$' | grep -oE '[A-Za-z_][A-Za-z0-9_]*$' | grep -E '_' | grep -vE '^[A-Z0-9_]+$' | sort -u); do
      case "$w" in *_*) ;; *) continue ;; esac
      if declare -F "$w" >/dev/null; then todo+=("$w"); elif ! type -t "$w" >/dev/null 2>&1; then
        case "$seen" in *" $w "*) ;; *) seen+="$w "; echo "$w (called by $fn)" ;; esac
      fi
    done
  done
}
# Sourcing this file defines the lane and runs nothing. The lane itself starts only in the queued runner's process tree: scripts/q4-live-lane.sh
# sets Q4_LANE_LOCKED=1 when it holds the devnet lock, and its devnet script is what sources this file there.
q4_lane_may_run() { [ "${Q4_LANE_LOCKED:-0}" = 1 ] && [ "${Q4_LIVE_LANE:-0}" = 1 ] && [ "${Q4_LANE_DEFINE_ONLY:-0}" != 1 ]; }
if q4_lane_may_run; then q4_run_lane; fi
