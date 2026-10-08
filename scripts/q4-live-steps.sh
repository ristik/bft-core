# Sourced by reth-paired-devnet.sh (Q4_LIVE_LANE=1, F8_MIXED_LANE=1, M2_PROFILE2=1) after the first paid certified block and the F8
# aggregator start, in place of the handoff script. Q4 #51 (B) REAL-PROCESS representatives of the weighted fault matrix, driven through
# the per-peer root shim (build/q4shim/ubft, make build-q4shim) and the F8 callbacks (f8_trace, f8_slow_stop_resume_evm,
# f8_inflight_evm_probe). Coverage label of every step: REAL-PROCESS root + EVM + three aggregator shards; crash model SIGKILL with the
# retained home (not a power loss). Every step prints PASS or FAIL; the first FAIL tears the lane down and exits nonzero.
#
# GATE: the rows are weighted-epoch rows. They run only when the lane's chain is in an activated weighted epoch (Q3 coupled activation,
# scheme 2, root-wrr-v1); Q4_WEIGHTED_CHECK is a command that exits 0 exactly then (the Q3 lane supplies it; it prints the active
# epoch's weights). Without it the lane stops BLOCKED (exit 3) before any fault, never as a pass on a unit-weight chain.
source scripts/lib/m2-handoff-lib.sh
source scripts/lib/q4-lib.sh

Q4_DIR=test-nodes/q4
mkdir -p "$Q4_DIR"
Q4_ROOTS=${Q4_ROOTS:-"1 2 3 4"}
Q4_HEAVY_ROOT=${Q4_HEAVY_ROOT:-1}   # the weight-6 root of the activated 6,1,1,1 epoch
Q4_EPOCH=${Q4_EPOCH:?Q4_EPOCH: the installed epoch number, for restarts (--install-handoff-epoch)}
Q4_STALL_SECONDS=${Q4_STALL_SECONDS:-20}
Q4_RECOVER_SECONDS=${Q4_RECOVER_SECONDS:-120}   # frozen before the run; never widened after a stall
q4_lights() { local r; for r in $Q4_ROOTS; do [ "$r" = "$Q4_HEAVY_ROOT" ] || echo "$r"; done; }

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

q4_restart_root() {
  local node=$1
  m2_start_root "$node" "$Q4_EPOCH" "$(boot_node test-nodes/root1 "$rootPortStart")"
}

q4_precondition() {
  if [ -z "${Q4_WEIGHTED_CHECK:-}" ]; then
    echo "BLOCKED: Q4_WEIGHTED_CHECK is not set; the weighted rows need an activated weighted epoch (Q3 coupled activation)" >&2
    q4_teardown; exit 3
  fi
  eval "$Q4_WEIGHTED_CHECK" || { echo "BLOCKED: the chain is not in an activated weighted epoch" >&2; q4_teardown; exit 3; }
}

q4_peer_args() { local r; for r in $Q4_ROOTS; do printf -- '--peer %s=%s ' "$r" "$(q4_peer "$r")"; done; }

# ---- the rows ----
q4_row_baseline() { f8_trace >/dev/null && q4_commits_advance "$Q4_HEAVY_ROOT" 60 3; }

q4_row_light_partition() {   # one light isolated both ways: 6+1+1 = 8 of 9 progresses; heal releases the stale traffic
  local light others
  light=$(q4_lights | head -n 1)
  others=$(for r in $Q4_ROOTS; do [ "$r" = "$light" ] || echo "$r"; done | tr '\n' ' ')
  q4_partition cut "$light" "$others" || return 1
  q4_commits_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3 || return 1
  q4_heal cut "$Q4_ROOTS" || return 1
  q4_commits_advance "$light" "$Q4_RECOVER_SECONDS" 3
}

q4_row_heavy_delayed() {     # the heavy root's traffic held: the lights are weight 3 of 9, quorum lost until release
  q4_delay_outbound delay "$Q4_HEAVY_ROOT" || return 1
  local light; light=$(q4_lights | head -n 1)
  q4_stalled "$light" "$Q4_STALL_SECONDS" || return 1
  q4_heal delay "$Q4_HEAVY_ROOT" || return 1
  q4_commits_advance "$light" "$Q4_RECOVER_SECONDS" 3
}

q4_row_light_sigkill() {     # SIGKILL a light root: the rest keep the quorum; restart over the retained home
  local light; light=$(q4_lights | head -n 1)
  q4_kill9 "$light" || return 1
  q4_commits_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3 || return 1
  q4_restart_root "$light" || return 1
  q4_commits_advance "$light" "$Q4_RECOVER_SECONDS" 3
}

q4_row_heavy_sigkill() {     # SIGKILL the heavy root: 3 of 9 left, explicit stall; restart over the retained home recovers
  local light; light=$(q4_lights | head -n 1)
  q4_kill9 "$Q4_HEAVY_ROOT" || return 1
  q4_stalled "$light" "$Q4_STALL_SECONDS" || return 1
  q4_restart_root "$Q4_HEAVY_ROOT" || return 1
  q4_commits_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3
}

q4_row_byzantine_lights() {  # two lights (weight 2 <= F) also send a conflicting signed vote per round; the honest weight 7 progresses
  local byz honest
  byz=$(q4_lights | tail -n 2 | tr '\n' ' ')
  honest=$(for r in $Q4_ROOTS; do case " $byz " in *" $r "*) ;; *) echo "$r";; esac; done | tr '\n' ' ')
  for r in $byz; do q4_byzantine "$r" state "$honest" || return 1; done
  q4_commits_advance "$Q4_HEAVY_ROOT" "$Q4_RECOVER_SECONDS" 3 || return 1
  for r in $byz; do [ "$(jq -r '.byzantine.byz // 0' "$Q4_SHIM_DIR/root$r/status.json")" -gt 0 ] || { echo "root$r sent nothing Byzantine" >&2; return 1; }; done
  Q4_BYZ_ROOTS=$(echo $byz | tr ' ' ',')
  for r in $byz; do q4_clear "$r"; done
}

q4_row_f8_callbacks() {      # F8: EVM paused with the root quorum intact, aggregators still certify new state roots, then resumed
  f8_slow_stop_resume_evm && f8_inflight_evm_probe
}

q4_row_trace_check() {
  local roots; roots=$(echo $Q4_ROOTS | tr ' ' ',')
  # a SIGKILLed root's torn last trace line is dropped by the checker's loader only if it is the final line
  python3 scripts/q4-trace-check.py "$Q4_SHIM_DIR" --roots "$roots" ${Q4_BYZ_ROOTS:+--byzantine "$Q4_BYZ_ROOTS"} $(q4_peer_args) | tee "$Q4_DIR/trace-report.json" | jq -e '.verdict == "PASS"' >/dev/null
}

q4_precondition
q4_step "baseline: weighted epoch commits (F8 trace and EVM IR)" q4_row_baseline
q4_step "one light root isolated (held both ways): 8 of 9 progresses, heal releases" q4_row_light_partition
q4_step "heavy root delayed: quorum lost, explicit stall, release recovers" q4_row_heavy_delayed
q4_step "F8 callbacks: EVM stop/resume with the root quorum intact, in-flight EVM proposal across root rotation" q4_row_f8_callbacks
q4_step "SIGKILL a light root and restart over the retained home" q4_row_light_sigkill
q4_step "SIGKILL the heavy root: stall, restart recovers" q4_row_heavy_sigkill
q4_step "two Byzantine lights (weight 2) equivocate: honest 7 progresses" q4_row_byzantine_lights
q4_step "offline trace check: attempts have outcomes, equivocators are exactly the declared Byzantine roots" q4_row_trace_check
echo "Q4 live lane: all steps PASSED"
