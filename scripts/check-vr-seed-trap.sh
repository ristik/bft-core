#!/usr/bin/env bash
# VT-11 shell check: sourcing scripts/vr-seed-steps.sh into a harness shell must neither replace the harness's EXIT trap nor consume the lane's shared
# extra-pids ledger. Run from the repository root; exits non-zero on a failure.
set -u
fail=0
ROOT=$PWD; export ROOT
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

# the harness cleanup (run for EXIT, INT and TERM) sweeps the seed servers by ownership before its unqualified wait
body=$(awk '/^cleanup\(\) \{/,/^\}/' scripts/reth-paired-devnet.sh)
sweep=$(printf '%s\n' "$body" | grep -n "owned_pids 'ubft seed serve'" | head -1 | cut -d: -f1)
wait=$(printf '%s\n' "$body" | grep -n "^  wait " | head -1 | cut -d: -f1)
if [ -n "$sweep" ] && [ -n "$wait" ] && [ "$sweep" -lt "$wait" ]; then echo "ok   the harness cleanup stops the seed servers before it waits"; else echo "FAIL the harness cleanup does not sweep the seed servers before wait ($sweep, $wait)"; fail=1; fi
traps=$(grep -c "^trap 'exit 1[34][03]' \(INT\|TERM\)" scripts/reth-paired-devnet.sh)
[ "$traps" = 2 ] && echo "ok   INT and TERM exit through the EXIT trap (cleanup)" || { echo "FAIL INT/TERM traps changed"; fail=1; }

# one offset for the root listener and the export URL
off=$(LANE_SLOT=2 bash -c 'source scripts/lib/utb-lib.sh; echo $(seed_port_offset)')
flags=$(LANE_SLOT=2 VR_SEED=1 bash -c 'source "$ROOT/scripts/lib/utb-lib.sh"; cd "$(mktemp -d)"; mkdir -p test-nodes; echo 0x00 >test-nodes/utb-genesis.id; echo x >test-nodes/utb-genesis.cbor; utb_root_flags 1')
url=$(LANE_SLOT=2 VR_EVIDENCE=/tmp bash -c 'vrb_log(){ :; }; source scripts/vr-seed-steps.sh; echo $vrs_bundle_url')
case "$flags" in *"127.0.0.1:40600"*) ;; *) echo "FAIL root listener not at slot 2's port: $flags"; fail=1 ;; esac
case "$url" in *":40600") echo "ok   the root's bundle listener and the export URL use the same slot offset ($off)" ;; *) echo "FAIL export URL $url"; fail=1 ;; esac
exit $fail
