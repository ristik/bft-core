#!/usr/bin/env bash
# check-no-global-kill.sh - fail if a script under scripts/ or the repo root can stop processes by name machine-wide.
#
# Every checkout starts its nodes as `build/ubft ...` relative to its own root, so a command-line pattern cannot tell one
# checkout's devnet from another's. On 2026-10-11 a `./stop.sh -a` in an idle checkout stopped two other lanes' running devnets
# that way. Processes are stopped only by this checkout's pid files or working directory (helper.sh: owned_pid, stop_pidfile,
# stop_evm_validators, stop_root_nodes).
#
# Flagged, on any non-comment line of a *.sh file under scripts/ or the repo root:
#   - pkill or killall as a command;
#   - a pipeline or substitution that feeds ps or pgrep output into kill (ps ... | grep ... | kill, kill $(pgrep ...), pgrep ... | xargs kill);
#   - a process listing filtered by name (ps ... | grep ...) without -p <pid>, whatever follows: the kill may be on the next line.
# A line that is safe for a stated reason carries the marker `global-kill-ok: <reason>` in a trailing comment.
#
# Usage: scripts/check-no-global-kill.sh             check the repository (exit 1 on a finding)
#        scripts/check-no-global-kill.sh --selftest  the checker finds each bad form and passes each allowed one
set -euo pipefail

# scan <file>...: prints file:line:text for every finding
scan() {
  awk '
    /global-kill-ok: [^ ]/ { next }
    {
      line = $0
      sub(/^[ \t]+/, "", line)
      if (line ~ /^#/) next
      code = line
      gsub(/"[^"]*"/, "\"\"", code); gsub(/\047[^\047]*\047/, "\047\047", code)   # what is quoted is data (an echo, a grep pattern), not a command
      sub(/[ \t]#.*$/, "", code)
      bad = 0
      if (code ~ /(^|[;&|({ \t])(pkill|killall)([ \t]|$)/) bad = 1
      # ps or pgrep output reaching kill on the same line; the unquoted text is checked for the commands, the full line for the flow
      if (line ~ /(^|[^a-zA-Z_])(ps|pgrep)[ \t].*(\|[ \t]*(xargs[ \t]+)?kill([ \t]|$))/) bad = 1
      if (line ~ /(^|[^a-zA-Z_])kill[ \t][^;|&]*\$\(([^)]*[^a-zA-Z_])?(ps|pgrep)[ \t]/) bad = 1
      if (line ~ /(^|[^a-zA-Z_])kill[ \t][^;|&]*`([^`]*[^a-zA-Z_])?(ps|pgrep)[ \t]/) bad = 1
      # a process listing filtered by name (ps ... | grep ...), whatever is done with it later: the form stop.sh had, with the kill on
      # the next line. A ps of one given pid (-p) is not a listing.
      if (match(line, /(^|[^a-zA-Z_])ps[ \t][^|]*\|[ \t]*grep/) && substr(line, RSTART, RLENGTH) !~ /[ \t]-p[ \t]/) bad = 1
      if (bad) printf "%s:%d:%s\n", FILENAME, FNR, $0
    }' "$@"
}

if [ "${1:-}" = "--selftest" ]; then
  dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
  fails=0
  expect() { # <bad|ok> <name> <line>
    printf '%s\n' "$3" >"$dir/case.sh"
    if [ -n "$(scan "$dir/case.sh")" ]; then got=bad; else got=ok; fi
    if [ "$got" = "$1" ]; then echo "ok: $2"; else echo "FAIL: $2 (wanted $1, got $got): $3"; fails=$((fails + 1)); fi
  }
  expect bad "pkill by pattern" "pkill -f 'ubft shard-node run' 2>/dev/null"
  expect bad "pkill after another command" "./stop-evm.sh -a || true; pkill -f 'reth node'"
  expect bad "killall" "  killall ubft"
  expect bad "ps | grep | kill through xargs" "ps -eaf | grep 'build/ubft' | grep -v grep | awk '{print \$2}' | xargs kill"
  expect bad "kill of a ps substitution" "kill \$(ps -eaf | grep build/ubft | awk '{print \$2}')"
  expect bad "kill of a pgrep substitution" "kill -9 \$(pgrep -f 'ubft root-node')"
  expect bad "kill of a backquoted pgrep" "kill \`pgrep -f ubft\`"
  expect bad "pgrep | xargs kill" "pgrep -f 'ubft root-node' | xargs kill"
  expect bad "a ps listing filtered by name, the kill on a later line (stop.sh before the fix)" "PID=\$(ps -eaf | grep \"\$program\" | grep -v grep | awk '{print \$2}')"
  expect ok "ps of one pid filtered" "ps -o command= -p \"\$pid\" 2>/dev/null | grep -qE -- \"\$pattern\" || return 1"
  expect ok "a comment that names pkill" "# never pkill: see helper.sh"
  expect ok "an echo that prints the word" "echo \"do not pkill these\" >&2"
  expect ok "a grep for the word" "declare -f q3_teardown | grep -E 'pkill|killall'"
  expect ok "kill of a recorded pid" "kill \"\$(cat test-nodes/root1/pid)\""
  expect ok "pgrep without kill" "stale=\$(pgrep -f 'ubft shard-node run' 2>/dev/null || true)"
  expect ok "kill of an owned pid" "for p in \$(owned_pids 'ubft root-node'); do kill \"\$p\"; done"
  expect ok "a marked line" "pkill -f 'reth node'   # global-kill-ok: single-tenant CI runner"
  expect bad "a marker without a reason" "pkill -f 'reth node'   # global-kill-ok: "
  [ "$fails" = 0 ] || { echo "$fails self-test case(s) failed" >&2; exit 1; }
  echo "check-no-global-kill self-test passed"
  exit 0
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
files=()
while IFS= read -r f; do files+=("$f"); done < <(git ls-files '*.sh' | grep -E '^(scripts/.*|[^/]+)$')
found=$(scan "${files[@]}")
if [ -n "$found" ]; then
  echo "$found"
  echo "machine-wide process kill in the script(s) above: stop processes by this checkout's pid files or working directory" >&2
  echo "(helper.sh: stop_pidfile, stop_evm_validators, stop_root_nodes, owned_pids); see scripts/check-no-global-kill.sh" >&2
  exit 1
fi
echo "no machine-wide process kill in ${#files[@]} scripts"
