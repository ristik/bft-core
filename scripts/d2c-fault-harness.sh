#!/bin/bash
# Scenario entry point for the D2-C multi-process fault matrix.
# Run once per scenario so each run owns a fresh test-nodes tree and log.
set -uo pipefail
scenario=${D2C_SCENARIO:-}
case "$scenario" in
  pair-term|pair-kill|ureth-kill|all-kill|leader-kill|proof-outage|proof-corrupt|missing-body|wrong-genesis) ;;
  *) echo "set D2C_SCENARIO to one of: pair-term pair-kill ureth-kill all-kill leader-kill proof-outage proof-corrupt missing-body wrong-genesis" >&2; exit 2 ;;
esac

mkdir -p briefs/d2c-harness
stamp=$(date -u +%Y%m%dT%H%M%SZ)
log="briefs/d2c-harness/${stamp}-${scenario}.log"
case "$scenario" in
  missing-body)
    echo "D2C[${scenario}] EXPECTED-FAIL(needs D2-A journal entry)" | tee "$log"
    exit 0
    ;;
  pair-term|pair-kill|ureth-kill|all-kill|leader-kill|proof-outage|proof-corrupt|wrong-genesis)
    # The current D2-C branch has only the shard-only SIGTERM probe. Preserve a real
    # B1..B10 baseline log, then report this requested fault as blocked unless its exact
    # process/RPC hook is present. Never label the baseline probe as the requested fault.
    if [ "$scenario" = pair-term ]; then
      D2C_RESTART_PROBE=1 SIGNING=authority ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$log"
      lane_status=${PIPESTATUS[0]}
      if [ "$lane_status" -ne 0 ]; then
        echo "D2C[${scenario}] FAIL(lane baseline exited ${lane_status}; see preceding diagnostics)" | tee -a "$log"
        exit "$lane_status"
      fi
    else
      echo "D2C[${scenario}] EXPECTED-FAIL(process fault hook absent on D2-C branch)" | tee "$log"
      exit 0
    fi
    echo "D2C[${scenario}] EXPECTED-FAIL(existing probe restarts shard only; pair SIGTERM/relaunch not exercised)" | tee -a "$log"
    ;;
esac
