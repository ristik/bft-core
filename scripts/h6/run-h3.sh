#!/usr/bin/env bash
# Run from a disposable pinned BFT clone on a dedicated host or under the optional H6 lock.
# The pinned paired launcher waits for children but only stops auth1..4 and
# the standard restore home. H3 adds authorities/restores; drain those after
# the final H3 PASS marker so launcher cleanup can finish. No scenario changes.
set -eo pipefail
: "${H3_EVIDENCE_DIR:?set a fresh absolute evidence directory}"
: "${H3_LANE_LOCKED:?set H3_LANE_LOCKED=1 on a dedicated host or under scripts/h6/devnet-lock.sh}"
[ "$H3_LANE_LOCKED" = 1 ] || exit 2
[ ! -e "$H3_EVIDENCE_DIR" ] || { echo 'STOP: evidence directory already exists'; exit 2; }
[ ! -e test-nodes ] || { echo 'STOP: H3 requires a fresh clone without test-nodes'; exit 2; }
source helper.sh
runner=
cleanup() {
  local pid n remaining
  # All matches must also have this disposable clone as their working directory.
  for pid in $(owned_pids 'ubft (root-node|shard-node|signing-authority)|reth.* node|aggregator'); do
    kill -INT "$pid" 2>/dev/null || true
  done
  for n in $(seq 1 60); do
    remaining=$(owned_pids 'ubft (root-node|shard-node|signing-authority)|reth.* node|aggregator')
    [ -z "$remaining" ] && return 0
    sleep 1
  done
  echo "STOP: owned processes remain: $remaining; keep this session open (and any lock held) and inspect logs" >&2
  return 1
}
on_exit() {
  local status=$?
  trap - EXIT
  if [ -n "$runner" ] && kill -0 "$runner" 2>/dev/null; then
    kill -TERM "$runner" 2>/dev/null || true
  fi
  if ! cleanup; then
    # Keep the parent command alive (and any outer lock held) until the operator resolves this.
    # No automatic SIGKILL of authorities or unrelated process sweeps.
    while ! cleanup; do sleep 5; done
    status=1
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'STEP: H3 lane; evidence %s\n' "$H3_EVIDENCE_DIR"
bash scripts/h3-assignment-lane.sh &
runner=$!
deadline=$((SECONDS + 1800))
while kill -0 "$runner" 2>/dev/null; do
  if [ -f "$H3_EVIDENCE_DIR/lane.log" ] && \
    grep -q '^H3 acceptance lane: all steps PASSED$' "$H3_EVIDENCE_DIR/lane.log"; then
    echo 'STEP: final scenario checks passed; drain H3 authority and restore children'
    cleanup
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo 'STOP: H3 exceeded the 1800 s supervisor budget' >&2
    exit 1
  fi
  sleep 1
done
wait "$runner"
runner=
grep -q '^H3 acceptance lane: all steps PASSED$' "$H3_EVIDENCE_DIR/lane.log"
if grep -q '^ *FAIL:' "$H3_EVIDENCE_DIR/lane.log"; then exit 1; fi
echo 'PASS: H3 runner exited successfully and owned processes stopped'
