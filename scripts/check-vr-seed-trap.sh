#!/usr/bin/env bash
# VT-11 shell check: sourcing scripts/vr-seed-steps.sh into a harness shell must neither replace the harness's EXIT trap nor consume the lane's shared
# extra-pids ledger. Run from the repository root; exits non-zero on a failure.
set -u
fail=0
out=$(bash -c '
  trap "echo HARNESS-TRAP-RAN" EXIT
  vrb_log() { :; }; VR_EVIDENCE=$(mktemp -d)
  source scripts/vr-seed-steps.sh
  trap -p EXIT >&2
  exit 0' 2>&1)
case "$out" in *HARNESS-TRAP-RAN*) echo "ok   the harness EXIT trap still runs after sourcing vr-seed-steps.sh" ;; *) echo "FAIL the harness EXIT trap was replaced: $out"; fail=1 ;; esac

d=$(mktemp -d)
( cd "$d" && mkdir -p test-nodes/q3 && printf '%s\n' "999999 aggregator" "999998 ubft seed serve" "999997 some other helper" >test-nodes/q3/extra-pids
  owned_pid() { return 1; }   # nothing is "owned": no process is signalled
  vrb_log() { :; }; VR_EVIDENCE=$d
  source "$OLDPWD/scripts/vr-seed-steps.sh"
  vrs_kill_extra >/dev/null 2>&1
  left=$(cat test-nodes/q3/extra-pids)
  case "$left" in *"999999 aggregator"*"999997 some other helper"*) ;; *) echo "FAIL other helpers' ledger entries were consumed: $left"; exit 1 ;; esac
  case "$left" in *"seed serve"*) echo "FAIL the seed server's own entry stayed in the ledger"; exit 1 ;; esac
  echo "ok   the preflight drops only its own ledger entry and keeps the other helpers'" ) || fail=1
rm -rf "$d"
exit $fail
