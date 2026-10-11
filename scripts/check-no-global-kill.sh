#!/usr/bin/env bash
# check-no-global-kill.sh - fail if a script under scripts/ or the repo root can stop processes by name machine-wide.
#
# Every checkout starts its nodes as `build/ubft ...` relative to its own root, so a command-line pattern cannot tell one
# checkout's devnet from another's. On 2026-10-11 a `./stop.sh -a` in an idle checkout stopped two other lanes' running devnets
# that way. Processes are stopped only by this checkout's pid files or working directory (helper.sh: owned_pid, stop_pidfile,
# stop_evm_validators, stop_root_nodes).
#
# Flagged, on any non-comment line of a *.sh file under scripts/ or the repo root, or of a workflow under .github/workflows/:
#   - pkill, killall or fuser -k as a command, also inside a command line handed to bash -c, sh -c, ssh or eval;
#   - a pipeline or substitution that feeds ps, pgrep, pidof or lsof output into kill (ps ... | grep ... | kill, kill $(pgrep ...),
#     lsof -ti :port | xargs kill);
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
      if (code ~ /(^|[;&|({ \t])fuser[ \t]+(-[a-zA-Z]*[ \t]+)*-[a-zA-Z]*k/) bad = 1
      # a command line handed to another shell is a command even though it is quoted
      if (code ~ /(^|[;&|({ \t])((ba)?sh[ \t]+-c|ssh|eval)([ \t]|$)/ && line ~ /(^|[^a-zA-Z_])(pkill|killall)([ \t]|$)/) bad = 1
      # ps, pgrep, pidof or lsof output reaching kill on the same line; the unquoted text is checked for the commands, the full line for the flow
      if (line ~ /(^|[^a-zA-Z_])(ps|pgrep|pidof|lsof)[ \t].*(\|[ \t]*(xargs[ \t]+)?kill([ \t]|$))/) bad = 1
      if (line ~ /(^|[^a-zA-Z_])kill[ \t][^;|&]*\$\(([^)]*[^a-zA-Z_])?(ps|pgrep|pidof|lsof)[ \t]/) bad = 1
      if (line ~ /(^|[^a-zA-Z_])kill[ \t][^;|&]*`([^`]*[^a-zA-Z_])?(ps|pgrep|pidof|lsof)[ \t]/) bad = 1
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
  # the cases are data, not shell: scripts/testdata/check-no-global-kill.cases, one per line as <bad|ok>|<name>|<the script line>
  cases="$(dirname "${BASH_SOURCE[0]}")/testdata/check-no-global-kill.cases"
  n=0
  while IFS= read -r c; do
    case "$c" in ''|'#'*) continue ;; esac
    want=${c%%|*}; rest=${c#*|}
    expect "$want" "${rest%%|*}" "${rest#*|}"; n=$((n + 1))
  done <"$cases"
  [ "$n" -ge 20 ] || { echo "only $n self-test cases read from $cases" >&2; exit 1; }
  [ "$fails" = 0 ] || { echo "$fails self-test case(s) failed" >&2; exit 1; }
  echo "check-no-global-kill self-test passed"
  exit 0
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
files=()
# tracked and not yet tracked alike: a new script is scanned before it is committed
while IFS= read -r f; do files+=("$f"); done < <(git ls-files --cached --others --exclude-standard '*.sh' '.github/workflows/*.yml' | grep -E '^(scripts/.*\.sh|[^/]+\.sh|\.github/workflows/.*)$' | sort -u)
found=$(scan "${files[@]}")
if [ -n "$found" ]; then
  echo "$found"
  echo "machine-wide process kill in the script(s) above: stop processes by this checkout's pid files or working directory" >&2
  echo "(helper.sh: stop_pidfile, stop_evm_validators, stop_root_nodes, owned_pids); see scripts/check-no-global-kill.sh" >&2
  exit 1
fi
echo "no machine-wide process kill in ${#files[@]} scripts and workflows"
