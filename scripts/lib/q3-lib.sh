# Sourced by scripts/q3-weight-activation-lane.sh (the runner) and scripts/q3-weight-activation-steps.sh (the steps): the Q3 #50 slice E
# weight-activation lane helpers (briefs/q3-design-v2.md section 5, item 3). Definitions and defaults only: sourcing starts nothing, so the
# runner's --dry-run can load and self-test them without a devnet.
#
# Scope: briefs/q3-design-v3-delta.md (v3). One fresh-genesis deployment, one layout, one execution format: no old-binary, layout-1 or
# compatibility lanes, no protocol/version negotiation, and no Rust proof verifier. Execution is checked by two independently verifying pairs.
#
# Everything the lane calls exists on the stacked PRs it is built on (#424 E-1 runtime wiring, #444 CLI/node admission): `ubft root handoff
# q3-candidate|q3-readiness|q3-activation|propose --readiness-receipts`, `ubft q3 history|proof-envelope|signers|pair-export|pair-control`,
# `ubft trust-base generate --root-weights` and `trust-base id`, `--q3-lane` on root and shard nodes, and the Ureth pair-binding flags (ureth#52).

# ---- the arithmetic the lane asserts (design section 5, item 2: W=9, root Q=7, faulty bound 2, EVM Q=5) ----------------------------------
Q3_WEIGHTS=${Q3_WEIGHTS:-"6 1 1 1"}        # mirrored: root entity i and its delegated EVM validator i carry the same weight
Q3_TOTAL_WEIGHT=9
Q3_ROOT_QUORUM=7
Q3_EVM_TOTAL_WEIGHT=9
Q3_EVM_QUORUM=5
Q3_FAULT_BOUND=2
Q3_EVM_QUORUM=5

# ---- the evidence the design lists (section 5, last paragraph); the lane fails if any is missing or empty ---------------------------------
Q3_EVIDENCE_REQUIRED="pins.txt commands.log candidate.cbor candidate-config.json v3-body-id.txt activation-record.json \
old-commit-proof.json old-commit-signers.json activation-coordinates.txt scheme-before.txt scheme-after.txt \
genesis-identities.json signers-root.json root-weights.json evm-weights.json frozen-parent-ack.json registry-layout.txt b1-profile.json registry-hash.txt \
proof-envelope.cbor history-ids-pre-restart.txt history-ids-post-restart.txt \
recovered-message.txt rebroadcast-trace.txt tc-trace.txt commit-trace.txt evm-request-weights.txt \
pair-root-input-a.bin pair-root-input-b.bin pair-transitions-a.bin pair-transitions-b.bin pair-state-a.json pair-state-b.json pair-equality.txt \
refusals-pair.log pair-restart.txt aggregator-before.json aggregator-after.json"

q3_evidence_check() { # dir: every required item exists and is non-empty
  local dir=$1 f missing=
  for f in $Q3_EVIDENCE_REQUIRED; do [ -s "$dir/$f" ] || missing="$missing $f"; done
  [ -z "$missing" ] || { echo "Q3 evidence incomplete in $dir; missing or empty:$missing" >&2; return 1; }
}

# ---- typed refusals: each sentinel is the Display text of a named PairBindingError variant (ureth#52, crates/unicity/execution/src/pairing.rs,
# `pair binding refused: {variant:?}`; each variant is raised by exactly one comparison), checked against the head the lane is pinned to. A
# refusal counts only if ITS OWN sentinel is in the log. ureth#52 is a pinned dependency: if its error text changes, this block alone changes. ---
Q3_SENTINEL_PAIR_MISSING="pair binding refused: Missing"
Q3_SENTINEL_PAIR_PARENT="pair binding refused: ParentHashMismatch"
Q3_SENTINEL_PAIR_JOB="pair binding refused: JobMismatch"
Q3_SENTINEL_PAIR_ROOT_INPUT="pair binding refused: RootInputMismatch"
Q3_SENTINELS="PAIR_MISSING PAIR_PARENT PAIR_JOB PAIR_ROOT_INPUT"

q3_assert_refusal() { # logfile sentinel what: the sentinel text appears in the log
  local log=$1 sentinel=$2 what=$3
  if grep -aqF -- "$sentinel" "$log" 2>/dev/null; then echo "refusal observed: $what: \"$sentinel\""; return 0; fi
  echo "no typed refusal for $what: \"$sentinel\" is absent from $log" >&2; return 1
}

# ---- EVM request weights: the root's own record of which shard requests it counted, and their weights under the view that counted them. -------
# q3_check_request_weights <W> <Q> <logfile>...: every "partition 00000008 reached consensus" line of the weighted EVM view (totalWeight=W) must show
# a matching weight of at least Q and agree with the weights it lists; prints those lines (the evidence) and fails if there are none. A heavy signer
# alone and a set of light signers are both visible in it: only the first can reach Q here.
q3_check_request_weights() {
  python3 - "$@" <<'PY'
import re, sys
W, Q, logs = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3:]
seen = 0
for path in logs:
    for line in open(path, errors="replace"):
        if "partition 00000008 reached consensus" not in line or "totalWeight=%d" % W not in line:
            continue
        m = re.search(r'requestWeights="?\[([^\]]*)\]"? matchingWeight=(\d+) threshold=(\d+) totalWeight=(\d+)', line)
        if not m:
            sys.exit("unparseable weighted consensus line: " + line.strip()[:200])
        ws = [int(x) for x in m.group(1).split()]
        matching, threshold, total = int(m.group(2)), int(m.group(3)), int(m.group(4))
        if sum(ws) != matching:
            sys.exit("listed weights %s do not sum to the matching weight %d" % (ws, matching))
        if threshold != Q or total != W:
            sys.exit("threshold %d / total %d, expected %d / %d" % (threshold, total, Q, W))
        if matching < threshold:
            sys.exit("counted weight %d is below the threshold %d" % (matching, threshold))
        print(line.strip()[line.index("partition"):][:300])
        seen += 1
if not seen:
    sys.exit("no weighted EVM consensus line found")
PY
}

# ---- weights: the committed record's signer weights against the design's totals --------------------------------------------------------------
# q3_assert_weights <signers.json> <expected total> <expected quorum>: the file is [{"nodeId":..,"weight":n},...] (the whole epoch's set for a
# "set" file, or the signers of a certificate). Prints the signed total. Each property is its own exit code so the self-test isolates them.
q3_check_weights() { # mode(set|set-evm|cert) file W Q
  python3 - "$@" <<'PY'
import json, sys
mode, path, W, Q = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
rows = json.load(open(path))
ws = [int(r["weight"]) for r in rows]
ids = [r["nodeId"] for r in rows]
if len(set(ids)) != len(ids): sys.exit("duplicate signer identity")
if any(w <= 0 for w in ws): sys.exit("non-positive weight")
total = sum(ws)
if mode in ("set", "set-evm"):
    if total != W: sys.exit(f"epoch weight total {total} != {W}")
    # the root quorum is floor(2W/3)+1; the EVM shard's request quorum is the majority floor(W/2)+1 (the two are never substitutes)
    want = (2 * total) // 3 + 1 if mode == "set" else total // 2 + 1
    if want != Q: sys.exit(f"{'root' if mode == 'set' else 'EVM request'} threshold for total {total} is {want}, not {Q}")
else:
    if total < Q: sys.exit(f"signed weight {total} is below the quorum {Q}")
print(total)
PY
}

# ---- log patterns (extended regex) over the root logs -----------------------------------------------------------------------------------
# The root's own lines: the timeout quorum (consensus_manager.go) and the identified timeout-vote lines this stack adds (signed / recovered /
# broadcast, each with the SHA-256 of the exact statement). Certificate schemes, epochs and signer weights are NOT read from logs: they come
# from the root's verified Q3 endpoints (`ubft q3 signers`, `root handoff q3-activation`).
Q3_PAT_TC=${Q3_PAT_TC:-'timeout quorum for round [0-9]+ achieved'}
Q3_PAT_SIGNED_TIMEOUT=${Q3_PAT_SIGNED_TIMEOUT:-'msg="signed timeout vote" .*epoch=%E% .*messageID=[0-9a-f]{64}'}
Q3_PAT_RECOVERED=${Q3_PAT_RECOVERED:-'msg="recovered recorded timeout vote" .*epoch=%E% .*messageID=[0-9a-f]{64}'}
Q3_PAT_REBROADCAST=${Q3_PAT_REBROADCAST:-'msg="broadcast timeout vote" .*messageID=[0-9a-f]{64}'}

q3_pat() { # pattern epoch: substitutes %E%
  local p=$1; p=${p//%E%/$2}; printf '%s' "$p"
}

# ---- ownership-checked teardown (the #383 lessons) ---------------------------------------------------------------------------------------
# Only processes of THIS checkout, matched by command AND working directory (helper.sh owned_pid/owned_pids/stop_pidfile), are signalled: never
# a pattern kill (no pkill/killall), never another worktree's or user's process, and a pid file is acted on only if its process is still ours.
# Extra processes this lane starts (the second pair) are recorded in test-nodes/q3/extra-pids and checked the same way.
q3_teardown() {
  local p f pattern='ubft root-node run|ubft shard-node (run|restore)|ubft signing-authority run|reth.* node|aggregator'
  if [ -f test-nodes/q3/extra-pids ]; then
    while read -r p pattern_extra; do
      [ -n "${p:-}" ] || continue
      owned_pid "$p" "${pattern_extra:-$pattern}" && kill -INT "$p" 2>/dev/null
    done <test-nodes/q3/extra-pids
    rm -f test-nodes/q3/extra-pids
  fi
  for f in test-nodes/evm*/pid test-nodes/auth*/pid test-nodes/reth*/pid test-nodes/root*/pid; do
    [ -f "$f" ] || continue
    case "$f" in
      */evm*) stop_pidfile "$f" 'ubft shard-node (run|restore)' INT ;;
      */auth*) stop_pidfile "$f" 'ubft signing-authority run' INT ;;
      */reth*) stop_pidfile "$f" 'reth.* node' INT ;;
      */root*) stop_pidfile "$f" 'ubft root-node run' INT ;;
    esac
  done
  for p in $(owned_pids "$pattern"); do kill -INT "$p" 2>/dev/null; done
  return 0
}

q3_record_extra_pid() { # pid command-regex: a process the devnet's own cleanup does not know
  mkdir -p test-nodes/q3
  printf '%s %s\n' "$1" "$2" >>test-nodes/q3/extra-pids
}

# ---- bounded waits: a timeout fails the lane; the absence of a crash is not progress evidence ---------------------------------------------
q3_wait_grep() { # seconds file extended-regex: the pattern appears in the file
  local limit=$1 file=$2 re=$3 i
  for i in $(seq 1 "$limit"); do
    grep -aEq -- "$re" "$file" 2>/dev/null && return 0
    sleep 1
  done
  echo "timed out after ${limit}s waiting for /$re/ in $file" >&2
  return 1
}

# ---- two independently verifying pairs: equality of the exported bytes and state ------------------------------------------------------------
# q3_pair_equal <a-dir-file-prefix...>: byte-identical authenticated root input and transition bytes, and identical EVM head and state root.
q3_cmp_bytes() { cmp -s "$1" "$2" && [ -s "$1" ]; }
q3_pair_equal() { # dir: pair-root-input-{a,b}.bin, pair-transitions-{a,b}.bin, pair-state-{a,b}.json ({head, stateRoot, number})
  local d=$1 f
  q3_cmp_bytes "$d/pair-root-input-a.bin" "$d/pair-root-input-b.bin" || { echo "pairs differ in root-input bytes" >&2; return 1; }
  q3_cmp_bytes "$d/pair-transitions-a.bin" "$d/pair-transitions-b.bin" || { echo "pairs differ in transition bytes" >&2; return 1; }
  for f in head stateRoot number; do
    [ -n "$(jq -r ".$f // empty" "$d/pair-state-a.json")" ] || { echo "pair A state lacks $f" >&2; return 1; }
    [ "$(jq -r ".$f" "$d/pair-state-a.json")" = "$(jq -r ".$f" "$d/pair-state-b.json")" ] || { echo "pairs differ in EVM $f" >&2; return 1; }
  done
}

# ---- self-test (the runner's --dry-run): every property below is exercised in isolation, by a mutation that must make exactly it fail --------
# No devnet, no network, no build. The teardown test starts two harmless fake processes, one in this directory and one elsewhere, and requires
# that only the first is signalled.
q3_selftest() {
  local t f n fails=0 ok
  t=$(mktemp -d "${TMPDIR:-/tmp}/q3-selftest.XXXXXX") || return 1
  q3_st() { # name command...: the command must succeed
    local name=$1; shift
    if "$@" >/dev/null 2>&1; then echo "  selftest PASS: $name"; else echo "  selftest FAIL: $name" >&2; fails=$((fails+1)); fi
  }
  q3_st_neg() { # name command...: the command must FAIL
    local name=$1; shift
    if "$@" >/dev/null 2>&1; then echo "  selftest FAIL: $name (accepted)" >&2; fails=$((fails+1)); else echo "  selftest PASS: $name"; fi
  }

  # evidence completeness: the full set passes; removing each required item, alone, fails
  mkdir -p "$t/ev"; for f in $Q3_EVIDENCE_REQUIRED; do echo x >"$t/ev/$f"; done
  q3_st "evidence pack: a complete set passes" q3_evidence_check "$t/ev"
  for f in $Q3_EVIDENCE_REQUIRED; do
    mv "$t/ev/$f" "$t/ev/$f.gone"; q3_st_neg "evidence pack: missing $f is refused" q3_evidence_check "$t/ev"; mv "$t/ev/$f.gone" "$t/ev/$f"
    : >"$t/ev/$f"; q3_st_neg "evidence pack: empty $f is refused" q3_evidence_check "$t/ev"; echo x >"$t/ev/$f"
  done

  # weights: the design's 6,1,1,1 numbers, and one mutation per property
  echo '[{"nodeId":"a","weight":6},{"nodeId":"b","weight":1},{"nodeId":"c","weight":1},{"nodeId":"d","weight":1}]' >"$t/set.json"
  q3_st "weights: set 6,1,1,1 is W=9 with Q=7" q3_check_weights set "$t/set.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  q3_st_neg "weights: the same set is not root Q=5" q3_check_weights set "$t/set.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM"
  q3_st "weights: the same set is EVM request Q=5 (majority)" q3_check_weights set-evm "$t/set.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM"
  q3_st_neg "weights: the same set is not EVM request Q=7" q3_check_weights set-evm "$t/set.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  echo '[{"nodeId":"a","weight":5},{"nodeId":"b","weight":1},{"nodeId":"c","weight":1},{"nodeId":"d","weight":1}]' >"$t/bad.json"
  q3_st_neg "weights: total 8 is refused" q3_check_weights set "$t/bad.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  echo '[{"nodeId":"a","weight":6},{"nodeId":"b","weight":1}]' >"$t/cert.json"
  q3_st "weights: heavy plus one light (7) reaches the root quorum" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  echo '[{"nodeId":"a","weight":6}]' >"$t/cert.json"
  q3_st_neg "weights: heavy alone (6) does not" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  q3_st "weights: heavy alone (6) reaches the EVM quorum 5" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM"
  echo '[{"nodeId":"b","weight":1},{"nodeId":"c","weight":1},{"nodeId":"d","weight":1}]' >"$t/cert.json"
  q3_st_neg "weights: three lights (3) do not reach the root quorum" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  q3_st_neg "weights: three lights (3) do not reach the EVM quorum" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM"
  echo '[{"nodeId":"a","weight":6},{"nodeId":"a","weight":1}]' >"$t/cert.json"
  q3_st_neg "weights: a duplicated signer identity is refused" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  echo '[{"nodeId":"a","weight":0},{"nodeId":"b","weight":9}]' >"$t/cert.json"
  q3_st_neg "weights: a zero weight is refused" q3_check_weights cert "$t/cert.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM"
  echo '[{"nodeId":"a","weight":1},{"nodeId":"b","weight":1},{"nodeId":"c","weight":1}]' >"$t/cert.json"
  q3_st "weights: the old unit epoch's three signers reach its Q=3 (W=4)" q3_check_weights cert "$t/cert.json" 4 3

  # typed refusals: a sentinel is satisfied only by its own text
  for n in $Q3_SENTINELS; do
    eval "printf '%s\n' \"\$Q3_SENTINEL_$n\" >\"\$t/refusal-$n.log\""
  done
  for n in $Q3_SENTINELS; do
    for f in $Q3_SENTINELS; do
      eval "s=\$Q3_SENTINEL_$f"
      if [ "$n" = "$f" ]; then q3_st "refusal: $n log satisfies $f" q3_assert_refusal "$t/refusal-$n.log" "$s" x
      else q3_st_neg "refusal: $n log does not satisfy $f" q3_assert_refusal "$t/refusal-$n.log" "$s" x; fi
    done
  done
  # the near-miss variants of ureth#52 must not satisfy the parent-hash sentinel (each variant is raised by exactly one comparison)
  echo "pair binding refused: ParentNumberMismatch" >"$t/near.log"
  q3_st_neg "refusal: ParentNumberMismatch does not satisfy the parent-hash sentinel" q3_assert_refusal "$t/near.log" "$Q3_SENTINEL_PAIR_PARENT" x
  q3_st_neg "refusal: a missing log is refused" q3_assert_refusal "$t/none.log" "$Q3_SENTINEL_PAIR_MISSING" x

  # two pairs: identical exports pass; each single difference fails
  mkdir -p "$t/pr"; for f in pair-root-input-a.bin pair-root-input-b.bin; do printf 'ri' >"$t/pr/$f"; done
  for f in pair-transitions-a.bin pair-transitions-b.bin; do printf 'tr' >"$t/pr/$f"; done
  for f in a b; do echo '{"head":"0x1","stateRoot":"0x2","number":7}' >"$t/pr/pair-state-$f.json"; done
  q3_st "pairs: identical exports are equal" q3_pair_equal "$t/pr"
  printf 'rx' >"$t/pr/pair-root-input-b.bin"; q3_st_neg "pairs: differing root input is refused" q3_pair_equal "$t/pr"; printf 'ri' >"$t/pr/pair-root-input-b.bin"
  printf 'tx' >"$t/pr/pair-transitions-b.bin"; q3_st_neg "pairs: differing transitions are refused" q3_pair_equal "$t/pr"; printf 'tr' >"$t/pr/pair-transitions-b.bin"
  echo '{"head":"0x1","stateRoot":"0x3","number":7}' >"$t/pr/pair-state-b.json"; q3_st_neg "pairs: differing state root is refused" q3_pair_equal "$t/pr"
  echo '{"head":"0x9","stateRoot":"0x2","number":7}' >"$t/pr/pair-state-b.json"; q3_st_neg "pairs: differing head is refused" q3_pair_equal "$t/pr"
  echo '{"head":"0x1","stateRoot":"0x2","number":8}' >"$t/pr/pair-state-b.json"; q3_st_neg "pairs: differing height is refused" q3_pair_equal "$t/pr"
  echo '{"head":"0x1","stateRoot":"0x2","number":7}' >"$t/pr/pair-state-b.json"
  : >"$t/pr/pair-root-input-a.bin"; : >"$t/pr/pair-root-input-b.bin"; q3_st_neg "pairs: equal but empty root input is refused" q3_pair_equal "$t/pr"

  # log patterns: the identified timeout lines match only their own kind and epoch
  echo 'time=t level=INFO msg="signed timeout vote" node_id=n round=9 epoch=2 messageID=0000000000000000000000000000000000000000000000000000000000000001' >"$t/sg.log"
  q3_st "patterns: a signed timeout line at epoch 2 matches" grep -aEq -- "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" "$t/sg.log"
  q3_st_neg "patterns: the same line does not match epoch 1" grep -aEq -- "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 1)" "$t/sg.log"
  q3_st_neg "patterns: a signed line is not a recovered line" grep -aEq -- "$(q3_pat "$Q3_PAT_RECOVERED" 2)" "$t/sg.log"
  echo 'msg="signed timeout vote" epoch=2 messageID=short' >"$t/short.log"
  q3_st_neg "patterns: a truncated message identity does not match" grep -aEq -- "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" "$t/short.log"

  # the step list is well formed
  if [ -n "${Q3_STEPS:-}" ]; then
    for n in $Q3_STEPS; do q3_st "steps: $n is defined" declare -F "$n"; done
  fi

  # teardown: only this checkout's processes, matched by command AND cwd; never a pattern kill
  q3_st_neg "teardown: no pkill or killall in q3_teardown" bash -c "declare -f q3_teardown | grep -E 'pkill|killall'"
  if declare -F owned_pids >/dev/null; then
    mkdir -p "$t/mine" "$t/other"
    local mine other
    # background jobs of a non-interactive shell start with SIGINT ignored; the fake re-installs a handler, as the Go nodes do with signal.Notify
    local fake='import signal,sys,time; signal.signal(signal.SIGINT, lambda *a: sys.exit(0)); time.sleep(120)'
    (cd "$t/mine" && python3 -c "$fake" ubft root-node run 120 >/dev/null 2>&1 &)
    (cd "$t/other" && python3 -c "$fake" ubft root-node run 121 >/dev/null 2>&1 &)
    sleep 1
    mine=$(pgrep -f 'root-node run 120' | head -1); other=$(pgrep -f 'root-node run 121' | head -1)
    if [ -n "$mine" ] && [ -n "$other" ]; then
      ( cd "$t/mine" && q3_teardown ) >/dev/null 2>&1
      sleep 1
      ok=1; kill -0 "$mine" 2>/dev/null && ok=0
      q3_st "teardown: this checkout's matching process is stopped" test "$ok" = 1
      q3_st "teardown: another directory's identical process is left alone" kill -0 "$other"
      kill "$other" 2>/dev/null; kill "$mine" 2>/dev/null
    else
      echo "  selftest SKIP: teardown ownership (could not start the fake processes with these command lines on this host)"
      kill "$mine" "$other" 2>/dev/null
    fi
  else
    echo "  selftest SKIP: teardown ownership (helper.sh not sourced)"
  fi
  rm -rf "$t"
  [ "$fails" -eq 0 ] || { echo "Q3 lane self-test: $fails check(s) FAILED" >&2; return 1; }
  echo "Q3 lane self-test: all checks passed"
}
