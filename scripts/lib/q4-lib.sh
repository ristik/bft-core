#!/usr/bin/env bash
# Q4 #51 (B) live-lane helpers: control documents for the root fault shim (rootchain/consensus/q4shim, binary build/q4shim/ubft built
# with `make build-q4shim`), shim status and trace access, process faults. Sourced by scripts/q4-live-steps.sh and by the lane runner;
# `scripts/lib/q4-lib.sh --selftest-docs <dir>` writes one document of every kind so that a Go test decodes them with the shim's own
# strict decoder (an unknown field or action is a failure there, not here).
#
# Roots are addressed by number (test-nodes/root<N>); each shim directory is $Q4_SHIM_DIR/root<N> with control.json (written here,
# read by the shim every 100 ms), status.json (written by the shim) and trace.jsonl (appended by the shim).

q4_gen_file() { echo "$Q4_SHIM_DIR/root$1/.gen"; }

q4_next_gen() {
  local f; f=$(q4_gen_file "$1")
  local g=0
  [ -f "$f" ] && g=$(cat "$f")
  g=$((g + 1))
  echo "$g" >"$f"
  echo "$g"
}

# q4_peer <root>: the root's libp2p peer id
q4_peer() { build/ubft node-id --home "test-nodes/root$1" | tail -n 1; }

# q4_doc <gen> <python expression building the document body dict>: prints canonical JSON
q4_doc() {
  python3 - "$1" "$2" <<'PY'
import json, sys
gen = int(sys.argv[1])
body = eval(sys.argv[2], {"__builtins__": {}}, {"true": True, "false": False})
doc = {"gen": gen}
doc.update(body)
print(json.dumps(doc, sort_keys=True))
PY
}

# q4_ctl <root> <body>: install a control document (full rule set; a rule that keeps its name keeps its counters) and wait until the
# shim reports having read it.
q4_ctl() {
  local root=$1 body=$2 gen dir
  dir="$Q4_SHIM_DIR/root$root"
  mkdir -p "$dir"
  gen=$(q4_next_gen "$root")
  q4_doc "$gen" "$body" >"$dir/control.json.tmp" && mv "$dir/control.json.tmp" "$dir/control.json"
  local i
  for i in $(seq 1 100); do
    [ "$(jq -r '.gen // 0' "$dir/status.json" 2>/dev/null || echo 0)" = "$gen" ] && return 0
    sleep 0.2
  done
  echo "root$root shim did not read control generation $gen" >&2
  return 1
}

q4_status() { jq -c . "$Q4_SHIM_DIR/root$1/status.json"; }
q4_hits() { jq -r --arg r "$2" '.rules[$r] // 0' "$Q4_SHIM_DIR/root$1/status.json"; }
q4_held() { jq -r --arg r "$2" '.held[$r] // 0' "$Q4_SHIM_DIR/root$1/status.json"; }

# q4_hold_between <rule> <isolated roots, space separated> <other roots, space separated>
# A bidirectional partition by holding: every isolated root holds its traffic to the others and every other root holds its traffic to
# the isolated ones, so that a heal delivers the stale traffic in order (nothing is lost and no honest message is altered).
q4_partition() {
  local rule=$1 isolated=$2 others=$3 r o peers
  for r in $isolated; do
    peers=$(for o in $others; do printf '"%s",' "$(q4_peer "$o")"; done)
    q4_ctl "$r" "{'rules':[{'name':'$rule','to':[${peers%,}],'action':'hold','require':true}]}" || return 1
  done
  for o in $others; do
    peers=$(for r in $isolated; do printf '"%s",' "$(q4_peer "$r")"; done)
    q4_ctl "$o" "{'rules':[{'name':'$rule','to':[${peers%,}],'action':'hold','require':true}]}" || return 1
  done
}

# q4_heal <rule> <all roots>: release in arrival order and clear the rule; fails if the rule never held anything (the fault was not
# injected)
q4_heal() {
  local rule=$1 roots=$2 r total=0 n
  for r in $roots; do
    n=$(q4_hits "$r" "$rule")
    total=$((total + n))
    q4_ctl "$r" "{'rules':[{'name':'$rule','action':'pass'}],'releases':[{'id':'$rule-$(date +%s%N)','rule':'$rule','order':'fifo'}]}" || return 1
  done
  [ "$total" -gt 0 ] || { echo "rule $rule matched no message on any root: nothing was injected" >&2; return 1; }
}

# q4_delay_outbound <rule> <root>: hold everything one root sends (a delayed heavy validator); q4_heal releases it
q4_delay_outbound() { q4_ctl "$2" "{'rules':[{'name':'$1','action':'hold','require':true}]}"; }

# q4_byzantine <root> <variant> <recipient roots>: the root also sends a second validly signed vote per round to the recipients
q4_byzantine() {
  local root=$1 variant=$2 recipients=$3 r list
  list=$(for r in $recipients; do printf '"%s",' "$(q4_peer "$r")"; done)
  q4_ctl "$root" "{'equivocation':[{'name':'byz','recipients':[${list%,}],'variant':'$variant','require':true}]}"
}

q4_clear() { q4_ctl "$1" "{}"; }

# process faults: SIGKILL (not a power loss) and restart over the retained home
q4_kill9() { local pid; pid=$(cat "test-nodes/root$1/pid") && kill -9 "$pid"; }

q4_selftest_docs() {
  local dir=$1
  mkdir -p "$dir"
  q4_doc 1 "{'rules':[{'name':'cut','to':['p1','p2'],'action':'hold','require':true}],'triggers':[{'name':'t','class':'vote','roundMin':4}]}" >"$dir/hold.json"
  q4_doc 2 "{'rules':[{'name':'cut','action':'pass'}],'releases':[{'id':'r1','rule':'cut','order':'fifo'}]}" >"$dir/release.json"
  q4_doc 3 "{'equivocation':[{'name':'byz','recipients':['12D3KooWL87szaxU9JaLbSKmHMTfuTg6xgcbUs8L4KH4JRn6Ujc9'],'variant':'state','require':true}]}" >"$dir/byzantine.json"
  q4_doc 4 "{'rules':[{'name':'late','class':'timeout','epoch':2,'action':'drop','after':'t'}],'triggers':[{'name':'t','class':'vote'}]}" >"$dir/after.json"
}

if [ "${1:-}" = "--selftest-docs" ]; then
  q4_selftest_docs "$2"
fi
