#!/bin/bash
# Scenario entry point for the D2-C multi-process fault matrix.
# Run once per scenario so each run owns a fresh test-nodes tree and log.
set -uo pipefail
scenario=${D2C_SCENARIO:-}
case "$scenario" in
  pair-term|pair-kill|ureth-kill|all-kill|leader-kill|proof-outage|proof-corrupt|missing-body|wrong-genesis) ;;
  *) echo "set D2C_SCENARIO to one of: pair-term pair-kill ureth-kill all-kill leader-kill proof-outage proof-corrupt missing-body wrong-genesis" >&2; exit 2 ;;
esac

retain_root=${D2C_RETAIN_DIR:-briefs/d2c-harness}
mkdir -p "$retain_root"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
log="$retain_root/${stamp}-${scenario}.log"
retain_run_logs() {
  local destination="$retain_root/${stamp}/${scenario}"
  mkdir -p "$destination"
  for file in test-nodes/evm*/debug.log test-nodes/root*/debug.log \
              test-nodes/reth*/reth.log test-nodes/proof-proxy/proxy.log; do
    [ -f "$file" ] || continue
    mkdir -p "$destination/$(dirname "$file")"
    cp -p "$file" "$destination/$file"
  done
  cp -p "$log" "$destination/$(basename "$log")"
  echo "D2C retained scenario evidence: $destination" | tee -a "$log"
}
trap 'destination="$retain_root/${stamp}/${scenario}"; mkdir -p "$destination"; [ ! -f "$log" ] || cp -p "$log" "$destination/$(basename "$log")"' EXIT
case "$scenario" in
  pair-term|pair-kill|ureth-kill|all-kill|leader-kill|missing-body|wrong-genesis)
    D2C_FAULT_SCENARIO="$scenario" SIGNING=authority ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$log"
    lane_status=${PIPESTATUS[0]}
    retain_run_logs
    if [ "$lane_status" -eq 0 ]; then
      case "$scenario" in
        missing-body)
          if ! grep -q '^D2C\[missing-body\] deleted certified candidate at B5; restarting validator 1$' "$log" ||
             ! grep -q '^D2C\[missing-body\] journal rejected restart after certified B5: .*durable state is damaged or untrusted' "$log" ||
             ! grep -q '^D1 impaired validator 1 expected refusal confirmed separately: missing-body:' "$log" ||
             ! grep -q '^D1 PASS$' "$log"; then
            echo "D2C[missing-body] FAIL(missing journal-deletion, restart-rejection, impaired-refusal, or survivor-quorum evidence)" | tee -a "$log"
            exit 1
          fi
          ;;
        wrong-genesis)
          if ! grep -q '^D2C\[wrong-genesis\] testing alternate genesis against retained validator 1 datadir at B5$' "$log" ||
             ! grep -q '^D2C\[wrong-genesis\] retained-state reth restart refused alternate genesis (exit 1)$' "$log" ||
             ! grep -q '^D1 impaired validator 1 expected refusal confirmed separately: wrong-genesis:' "$log" ||
             ! grep -q '^D1 PASS$' "$log"; then
            echo "D2C[wrong-genesis] FAIL(missing alternate-genesis refusal, impaired-refusal, or survivor-quorum evidence)" | tee -a "$log"
            exit 1
          fi
          ;;
      esac
      echo "D2C[${scenario}] PASS" | tee -a "$log"
      exit 0
    fi
    echo "D2C[${scenario}] FAIL(lane exited ${lane_status}; see diagnostics above)" | tee -a "$log"
    exit "$lane_status"
    ;;
  proof-outage|proof-corrupt)
    D2C_FAULT_SCENARIO="$scenario" SIGNING=authority ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$log"
    lane_status=${PIPESTATUS[0]}
    retain_run_logs
    if [ "$lane_status" -eq 0 ]; then
      if [ "$scenario" = proof-corrupt ]; then
        if ! grep -Eq '^D2C\[proof-corrupt\] invalid-proof rejection confirmed for parent=.*invalid peer candidate:.*registrywitness:.*header hash mismatch.*snapshotIDs=\[\]; dependentSignedRequests=0$' "$log" ||
           ! grep -Eq '^D2C\[proof-corrupt\] recovery measured after pass: firstAssociation=B[0-9]+; furtherCertifiedHeights=([3-9]|[1-9][0-9]+); signedRequests=[1-9][0-9]*; head=B[0-9]+; liveHeadAgreement=true$' "$log" ||
           ! grep -q '^D2C\[proof-corrupt\] EXPECTED-FAIL(mutated uncached proof parent=.*rejected as invalid; no derived snapshot or signed request used its snapshotID; validator 1 recovered after pass with .* positive-height admissions and .* signed requests)$' "$log"; then
          echo "D2C[proof-corrupt] FAIL(missing parent-specific invalid-proof rejection, safe dependency check, or bounded recovery evidence)" | tee -a "$log"
          exit 1
        fi
        verdict=$(grep '^D2C\[proof-corrupt\] EXPECTED-FAIL(' "$log" | tail -1)
        echo "$verdict" | tee -a "$log"
      else
        echo "D2C[${scenario}] PASS" | tee -a "$log"
      fi
      exit 0
    fi
    echo "D2C[${scenario}] FAIL(lane exited ${lane_status}; see diagnostics above)" | tee -a "$log"
    exit "$lane_status"
    ;;
esac
