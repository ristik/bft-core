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
  pair-term|pair-kill|ureth-kill|all-kill|leader-kill)
    D2C_FAULT_SCENARIO="$scenario" SIGNING=authority ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$log"
    lane_status=${PIPESTATUS[0]}
    if [ "$lane_status" -eq 0 ]; then
      echo "D2C[${scenario}] PASS" | tee -a "$log"
      exit 0
    fi
    if grep -q "D2C\[$scenario\] injection at certified B5" "$log"; then
      reason=$(grep -E 'D1 FAIL: stalled before height|D1 FAIL: B[0-9]+ lacks|D1 FAIL: canonical disagreement|D1 FAIL: discontinuity' "$log" | tail -1)
      if [ -n "$reason" ]; then
        echo "D2C[${scenario}] EXPECTED-FAIL(no automatic re-drive: ${reason#D1 FAIL: })" | tee -a "$log"
        exit 0
      fi
    fi
    echo "D2C[${scenario}] FAIL(lane exited ${lane_status}; see diagnostics above)" | tee -a "$log"
    exit "$lane_status"
    ;;
  proof-outage|proof-corrupt)
    D2C_FAULT_SCENARIO="$scenario" SIGNING=authority ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$log"
    lane_status=${PIPESTATUS[0]}
    if [ "$lane_status" -eq 0 ]; then
      echo "D2C[${scenario}] PASS" | tee -a "$log"
      exit 0
    fi
    if grep -q "D2C\[$scenario\] FAIL(injection/relaunch" "$log"; then
      echo "D2C[${scenario}] FAIL(injection/relaunch hook failed; see controller diagnostic above)" | tee -a "$log"
      exit "$lane_status"
    fi
    if grep -q "D2C\[$scenario\] dropped proof RPC\|D2C\[$scenario\] corrupted proof RPC" "$log"; then
      reason=$(grep -E 'D1 FAIL: stalled before height|D1 FAIL: B[0-9]+ lacks|D1 FAIL: canonical disagreement|D1 FAIL: discontinuity' "$log" | tail -1)
      if [ -n "$reason" ]; then
        echo "D2C[${scenario}] EXPECTED-FAIL(proof fault was injected/restored; ${reason#D1 FAIL: })" | tee -a "$log"
        exit 0
      fi
    fi
    echo "D2C[${scenario}] FAIL(lane exited ${lane_status}; see diagnostics above)" | tee -a "$log"
    exit "$lane_status"
    ;;
  wrong-genesis)
    echo "D2C[${scenario}] EXPECTED-FAIL(needs retained-state wrong-genesis restart hook)" | tee "$log"
    ;;
esac
