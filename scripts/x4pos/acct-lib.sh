# X4 B6: the accounting snapshots of the PoS campaign, taken by the lane (scripts/x4pos/collect.py) and judged at the end (scripts/x4pos/accounting.py). Definitions only: sourcing this
# file starts nothing. Lane steps (p85_step): x4a_snapshot between phases, x4a_final last.
#
# One line per snapshot in $H3_DIR/x4pos/snapshots.jsonl, the file `driver.py report` reads. t is whole seconds since the first snapshot of the run and strictly increases (a snapshot
# is refused if the clock did not move). The pool's funding in the P85 lanes is a genesis alloc (deployment.json rewardFunding), which emits no Funded log: it is passed explicitly.
# NOTE for the reader of a pack: the collector's decoding of the contracts' events had only run against a stub `cast` before the first lane run that includes this file.

X4A_DIR=${X4A_DIR:-$H3_DIR/x4pos}

x4a_snapshot() {
  local now t0 t last
  mkdir -p "$X4A_DIR"
  now=$(date +%s)
  [ -s "$X4A_DIR/t0" ] || echo "$now" >"$X4A_DIR/t0"
  t0=$(cat "$X4A_DIR/t0"); t=$((now - t0))
  last=$(tail -n 1 "$X4A_DIR/snapshots.jsonl" 2>/dev/null | jq -r '.t // -1'); [ -n "$last" ] || last=-1
  if [ "$t" -le "$last" ]; then sleep 1; t=$(($(date +%s) - t0)); fi
  python3 scripts/x4pos/collect.py snapshot --rpc "$(p85_eth)" --cast "$P85_CAST" --custody "$(p85_custody)" --pool "$(rw_pool)" --from-block 0 \
    --genesis-funding "$(jq -r .rewardFunding "$P85_DIR/genesis/deployment.json")" --t "$t" --out "$X4A_DIR/snapshots.jsonl" >>"$X4A_DIR/collect.log" || { cat "$X4A_DIR/collect.log" >&2; return 1; }
  echo "PASS: x4a: accounting snapshot at t=$t s"
}

# the last snapshot, then the checker over all of them: PASS needs at least two snapshots and every invariant (exit 0 only)
x4a_final() {
  x4a_snapshot || return 1
  python3 scripts/x4pos/accounting.py check "$X4A_DIR/snapshots.jsonl" >"$X4A_DIR/accounting.txt"; local rc=$?
  cat "$X4A_DIR/accounting.txt"
  [ "$rc" = 0 ] || { echo "x4a: the accounting check did not pass (exit $rc)" >&2; return 1; }
  echo "PASS: x4a: accounting over $(wc -l <"$X4A_DIR/snapshots.jsonl" | tr -d ' ') snapshots"
}
