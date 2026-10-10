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
case "$Q4_SCENARIO" in
  A) Q3_WEIGHTS="6 1 1 1"; Q4_HEAVY_ROOTS="1" ;;
  B) Q3_WEIGHTS="3 3 2 1"; Q4_HEAVY_ROOTS="1 2" ;;
  *) echo "Q4_SCENARIO must be A or B, not $Q4_SCENARIO" >&2; return 2 2>/dev/null || exit 2 ;;
esac
export Q3_WEIGHTS Q4_SCENARIO
export Q3_LANE_DEFINE_ONLY=1
source scripts/q3-weight-activation-steps.sh
unset Q3_LANE_DEFINE_ONLY
source scripts/lib/q4-lib.sh

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
q4_step() { local name=$1; shift; echo "--- Q4 step: $name"; "$@" || q4_die "$name"; q4_pass "$name"; }

q4_round() { curl -fsS "http://127.0.0.1:$(m2_rpc_port "$1")/api/v1/roundInfo" | jq -r '.roundNumber'; }
# the certified IR round of the EVM shard (partition 8): moves only when a block is certified, never by a timeout certificate alone
q4_evm_ir() { curl -fsS "http://127.0.0.1:$(m2_rpc_port "${1:-1}")/api/v1/roundInfo" | jq -r '.partitionShards[] | select(.partitionId==8) | .roundNumber'; }

# q4_commits_advance <root> <seconds> <n>: the EVM certified IR round rose by at least n within the window
q4_commits_advance() {
  local root=$1 limit=$2 n=$3 base now i
  base=$(q4_evm_ir "$root") || return 1
  for i in $(seq 1 "$limit"); do
    now=$(q4_evm_ir "$root") || return 1
    [ $((now - base)) -ge "$n" ] && { echo "root$root EVM IR $base -> $now in ${i}s"; return 0; }
    sleep 1
  done
  echo "root$root EVM IR stayed at $now (from $base) for ${limit}s" >&2
  return 1
}

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
q4_root_advance() {
  local root=$1 limit=$2 n=$3 base now i
  base=$(q4_round "$root") || return 1
  for i in $(seq 1 "$limit"); do
    now=$(q4_round "$root") || return 1
    [ $((now - base)) -ge "$n" ] && { echo "root$root committed round $base -> $now in ${i}s"; return 0; }
    sleep 1
  done
  echo "root$root committed round stayed at $now (from $base) for ${limit}s" >&2
  return 1
}

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
  [ "$(jq -r .leaderPolicy "$Q3_DIR/candidate-config.json" 2>/dev/null)" = root-wrr-v1 ] || { echo "the committed tuple's leader policy is not root-wrr-v1: $(jq -c . "$Q3_DIR/candidate-config.json" 2>&1)" >&2; return 1; }
  echo "activated weighted epoch confirmed from root$root: epoch $Q4_EPOCH, scheme 2, signed weight $(printf '%s' "$sg" | jq -r '[.signers[].weight] | add'), mirrored weights $Q3_WEIGHTS"
  cp "$act" "${Q4_EVIDENCE_DIR:-.}/weighted-check-activation.json" 2>/dev/null; rm -f "$act"
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

q4_row_trace_check() {
  local roots; roots=$(echo $Q4_ROOTS | tr ' ' ',')
  # a SIGKILLed root's torn last trace line is dropped by the checker's loader only if it is the final line. The declared Byzantine set is the union of the rows' sets; the
  # windows hold every equivocation in the traces to the row that armed it.
  python3 scripts/q4-trace-check.py "$Q4_SHIM_DIR" --roots "$roots" ${Q4_BYZ_ROOTS:+--byzantine "$Q4_BYZ_ROOTS"} --byz-windows "$Q4_DIR/byz-windows.jsonl" $(q4_peer_args) \
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
  q4_step "F8 aggregator shards stay served by the weighted epoch (authorized TR rounds advance, aggregators answer)" q4_row_f8_follow
  q4_step "F8 aggregator shards certify new state roots in the weighted epoch; the roots verify their rsmt proofs (T1)" q4_row_f8_new_roots
  if [ "$Q4_SCENARIO" = A ]; then
    q4_step "one light root isolated (held both ways): 8 of 9 progresses, heal releases" q4_row_light_partition
    q4_step "two lights isolated: heavy and one light (7 = Q) progress, heal releases" q4_row_two_lights_partition
    q4_step "all lights isolated: heavy alone (6) and the lights (3) both stall, heal releases" q4_row_all_lights_partition
    q4_step "heavy root delayed: quorum lost, explicit stall, release recovers" q4_row_heavy_delayed
    q4_step "SIGKILL a light root and restart over the retained home" q4_row_light_sigkill
    q4_step "SIGKILL the heavy root: stall, restart recovers" q4_row_heavy_sigkill
    q4_step "two Byzantine lights (weight 2) equivocate: honest 7 progresses" q4_row_byzantine_lights
    q4_step "the heavy root (weight 6 > F) equivocates alone, outside the assumptions: the equivocation is real, the checker classifies it" q4_row_byzantine_heavy
  else
    q4_step "B: the weight-1 root isolated: 8 of 9 progresses, heal releases" q4_row_b_light_one
    q4_step "B: the weight-2 root isolated: 7 = Q progresses, heal releases" q4_row_b_light_two
    q4_step "B: the weight-2 and weight-1 roots isolated: the two weight-3 roots (6) stall, heal releases" q4_row_b_lights_both
    q4_step "B: one weight-3 root delayed: 6 of 9, quorum lost, explicit stall, release recovers" q4_row_heavy_delayed
    q4_step "B: SIGKILL the weight-2 root and restart over the retained home" q4_row_light_sigkill
    q4_step "B: SIGKILL each weight-3 root in turn: 6 left, stall, restart recovers" q4_row_heavy_sigkill
    q4_step "B: the weight-2 root (= F, in bound) equivocates: honest 3+3+1 progress" q4_row_byzantine_lights
    q4_step "B: a weight-3 root (> F) equivocates alone, outside the assumptions: the equivocation is real, the checker classifies it" q4_row_byzantine_heavy
  fi
  q4_step "offline trace check: attempts have outcomes, equivocators are exactly the declared Byzantine roots" q4_row_trace_check
  echo "Q4 live lane: all steps PASSED"
  q4_teardown
}
[ "${Q4_LANE_DEFINE_ONLY:-0}" = 1 ] || q4_run_lane
