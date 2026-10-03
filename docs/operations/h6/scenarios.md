# Rehearsal procedures

Start with the [manual network](network.md). Read the existing runbook sections
linked from [README](README.md) before each scenario. Capture source pins,
genesis hashes, authority status and certified tip before/after each operation.
A skipped check or unavailable field is incomplete evidence. Before scenario 1,
open [evidence.md](evidence.md): define `save_history` and start its observer in
the manual shell; return here to take the baseline and perform the upgrade.

## 1. Coordinated Ureth execution-version upgrade

Rehearse **5f3bb7e4ee9f82e70630e5c4b73783e7a392a7d3 →
b4e7cb0ace07eee70e753241e0139c4d42b516d4**, keeping BFT fixed. The first is the
H3 implementation commit; the second is its later merged form. They are not a
claimed ancestor/descendant release series. Git comparison shows only three
changed files: execution `lib.rs`, `wire.rs`, and payload tests. Runtime changes
are a const annotation and a distinct oversized-supersession refusal diagnostic;
the same bound was already enforced. DB/schema, Cargo.lock, Engine methods and
layout-2 genesis artifacts are unchanged. This is a narrow state-compatible
**candidate**, not evidence that an upgrade was already rehearsed.

Before authorizing the swap, run both revisions' execution/payload tests and
record the exact diff:

```sh
git -C "$H6_RUN/ureth-$H6_NEW" diff "$H6_OLD" "$H6_NEW" > "$H6_RUN/ureth-pair.diff"
for pin in "$H6_OLD" "$H6_NEW"; do
  (cd "$H6_RUN/ureth-$pin" && cargo test --locked -p reth-unicity-execution -p reth-unicity-payload) \
    2>&1 | tee "$H6_RUN/pair-tests-$pin.log"
done
shasum -a 256 -c "$H6_RUN/artifacts.sha256"
snapshot upgrade-before
# Define save_history from evidence.md and start its observer before proceeding.
save_history history-before-upgrade
```

Stop if the diff differs from that description, either test suite fails, the
registry hash/chain/genesis changes, or certification/authority checks fail.
Perform the complete swap once on disposable state before treating the pair as
approved. The first independent run is this compatibility experiment, not a
production change. A layout-1 client cannot be used as the older side.

Quiesce clients, save the last certified monetary receipt and its block roots,
and stop all shard producers. Keep **every authority alive**; keep root nodes on
the same BFT pin. Then stop all four Ureth instances and wait for clean exit:

```sh
printf 'upgrade stop requested %s\n' "$(date -u +%FT%TZ)" | tee "$H6_RUN/upgrade-boundary.txt"
for i in 1 2 3 4; do
  old=$(cat "test-nodes/evm$i/pid")
  stop_one_evm_validator "$i"
  for n in $(seq 1 60); do kill -0 "$old" 2>/dev/null || break; sleep 1; done
  if kill -0 "$old" 2>/dev/null; then echo 'STOP: shard did not exit'; exit 1; fi
done
for i in 1 2 3 4; do
  old=$(cat "test-nodes/reth$i/pid")
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
  for n in $(seq 1 60); do kill -0 "$old" 2>/dev/null || break; sleep 1; done
  if kill -0 "$old" 2>/dev/null; then echo 'STOP: EL did not exit cleanly'; exit 1; fi
done
cp test-nodes/registry-layout "$H6_RUN/registry-layout-before-upgrade"
# No chain files or databases change here. Record the approved client pin change.
export URETH_PIN_COMMIT="$H6_NEW" URETH_BIN="$H6_RUN/bin/ureth-$H6_NEW"
registry_layout_init
shasum -a 256 -c "$H6_RUN/genesis.sha256"
for i in 1 2 3 4; do start_reth "$i"; done
peer_reth
```

Before restarting shards, query `eth_getBlockByNumber` at every saved certified
height on all four new ELs; require identical hash/stateRoot/receiptsRoot and
receipt contents. New ELs must open the same datadirs without migration/refusal.
There is no mixed-version certification window because all shard producers are
stopped throughout the binary swap.

```sh
start_evm_validators 4 8 "$(m2_root_addr 1)" engine-api rpc
m2_send_paid 1 "$M2_NEXT_NONCE" || { echo "STOP: paid certification check failed"; exit 1; }
snapshot upgrade-after
# Re-run evidence.md's fixed-height/receipt comparison after resumed certification.
```

Require journal restore and new certificate admissions from the new processes;
compare saved receipts/blocks, authority PID/fingerprint/generation and high-water
values. Measure the interruption as specified in evidence.md. Use at least three
post-resume certified observations, not just a listener opening. No automatic
halt-height feature is claimed: this is an operator-coordinated halt and exact-pin
restart on unchanged chain state.

**Rollback rule:** before any new binary opens persisted state, cancel the swap
and restart the old ELs on the untouched datadirs. After any new EL opens state,
this guide offers no downgrade. Keep producers stopped and preserve all files;
fix forward or restore from authenticated archive history at the current
certified tip using an approved reader. Never restore an earlier database snapshot
to resume signing, reset nonces, erase a certificate or reorganize a certified
monetary transaction. A failed/unknown outcome is a stopped incident, not permission
to choose a convenient old tip. BFT and authority binary upgrades remain outside
this procedure.

## 2. Abort before H, retry, then refuse abort after H

Use the manual network at root epoch 1, with no other handoff operator. This
scenario advances the same committee to epoch 2; it is not the key-rotation test.
The helper below exists because `root handoff propose` normally endorses the
whole quorum. It uses the same loopback plan/intent/endorse routes but deliberately
endorses only one root. It never invents a frozen parent or changes root state files.

The helper is shipped alongside this guide. Copy `scripts/h6/prepare-handoff.py`
from the guide checkout into `$H6_RUN/bin/prepare-handoff.py` before using the
baseline clone; record its SHA-256 with the documentation revision. The baseline
pin predates this documentation/helper, so it does not contain the new file.

```sh
ROOT_RPCS=http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25869
m2_same_members_trust_base 2 '1 2 3 4' trust-base-epoch2.json
build/ubft trust-base verify --trust-base test-nodes/trust-base-epoch1.json \
  --trust-base test-nodes/trust-base-epoch2.json
abort_target() {
  local target=$1
  build/ubft root handoff abort \
    --network "$(jq -er '.network' "$target")" \
    --old-epoch "$(jq -er '.oldEpoch' "$target")" \
    --predecessor-body-id "$(jq -er '.predecessorBodyId' "$target")" \
    --attempt "$(jq -er '.attempt' "$target")" \
    --next-body-id "$(jq -er '.nextBodyId' "$target")" \
    --root-rpc "$ROOT_RPCS" --timeout 2m
}
snapshot abort-before
python3 "$H6_RUN/bin/prepare-handoff.py" \
  --next-trust-base test-nodes/trust-base-epoch2.json \
  --root-rpc "$ROOT_RPCS" --out "$H6_RUN/abort-before-H"
# Run immediately in the same block: the Prepare lapse window is only 24 rounds.
abort_target "$H6_RUN/abort-before-H/target.json" | tee "$H6_RUN/abort-before-H/abort.txt"
m2_send_paid 1 "$M2_NEXT_NONCE" || { echo "STOP: paid certification check failed"; exit 1; }
snapshot abort-resumed
```

Require `committed Abort record` or `Abort already committed`, its ordered round
and committed root block, and `phase=aborted` for that exact epoch/attempt in root
logs. Require a paid receipt **after** Abort under epoch 1. A lapse, bad target,
HTTP timeout or CLI failure is not this acceptance result. If Prepare lapses,
save the failed attempt and inspect its terminal outcome; repeat with a new output
directory only after the documented lapse/abort recovery rules allow it.

The helper's `context.json` records the predecessor and attempt; `plan.json`
records canonical Body bytes; `target.json` uses SHA-256 of those bytes for
`nextBodyId`. The server authenticates all target fields. `target-wire.json`
contains the byte fields in Go's base64 JSON encoding for the status route.
Sources: `cli/ubft/cmd/root_handoff.go:56`, `:399`,
`rootchain/consensus/handoff_operator.go:1239`, `evmroot/d3weights.go:363`.

Retry using fresh context at attempt+1, now allowing all endorsements. Preserve
this new target: it is the target of the required late-abort check.

```sh
python3 "$H6_RUN/bin/prepare-handoff.py" --endorse-all \
  --next-trust-base test-nodes/trust-base-epoch2.json \
  --root-rpc "$ROOT_RPCS" --out "$H6_RUN/committed-H"
test "$(jq -r '.attempt' "$H6_RUN/committed-H/target.json")" -eq \
  "$(( $(jq -r '.attempt' "$H6_RUN/abort-before-H/target.json") + 1 ))"
# Deliberate negative: nonzero is required, with the exact too-late diagnostic.
if abort_target "$H6_RUN/committed-H/target.json" > "$H6_RUN/late-abort.txt" 2>&1; then
  echo 'STOP: Abort unexpectedly succeeded after H'; exit 1
fi
grep 'too late' "$H6_RUN/late-abort.txt"
grep 'phase=committed' test-nodes/root1/debug.log
```

The helper waits for authenticated `too_late` status, rather than treating
submitted endorsements as committed H. This check must precede root installation
while the old-epoch control is still served. It establishes a live refusal after
H; it does not claim exhaustive race scheduling coverage.

Complete installation and authority advancement using the existing library's
same-members sequence (do not submit another proposal):

```sh
for i in 1 2 3 4; do
  prev=1; [ "$i" = 1 ] && prev=2
  boot=$(m2_root_addr "$prev")
  old=$(cat "test-nodes/root$i/pid")
  stop_pidfile "test-nodes/root$i/pid" 'ubft root-node'
  for n in $(seq 1 60); do kill -0 "$old" 2>/dev/null || break; sleep 1; done
  if kill -0 "$old" 2>/dev/null; then echo 'STOP: root did not exit'; exit 1; fi
  m2_archive_root_state "$i" 2
  m2_start_root "$i" 2 "$boot"
done
m2_wait_root_epoch 1 2
# Require handoff activated at epoch 2 on all shards before advancing authorities.
for i in 1 2 3 4; do
  for n in $(seq 1 90); do
    grep -q 'msg="handoff activated" rootEpoch=2' "test-nodes/evm$i/debug.log" && break
    sleep 1
  done
  grep -q 'msg="handoff activated" rootEpoch=2' "test-nodes/evm$i/debug.log"
done
m2_advance_authorities 2 trust-base-epoch2.json
m2_send_paid 2 "$M2_NEXT_NONCE" || { echo "STOP: paid certification check failed"; exit 1; }
snapshot handoff-after
m2_measure_pause 1 2 | tee "$H6_RUN/handoff-pause.txt"
```

`m2_archive_root_state` is the lane's successor-install step and preserves prior
root DBs in a named directory; it must never be used to revert H or as a general
restart recipe (`scripts/lib/m2-handoff-lib.sh:82`). Authority advancement fences
the previous sessions; verify increased generation, unchanged fingerprint and
nondecreasing reserved round. Stop and escalate on partial advancement; do not
hand-edit trust files or restart authorities. Finish with network.md's teardown.

## 3. Coupled key rotation, stalled successors and archive-backed restore

Run H3 from an ordinary shell after exiting the manual-network shell (and
releasing its lock, if used). Use a **new clone** of the same BFT pin (replace the fresh name if it already exists). This lane creates
its own genesis; it is not a continuation of scenario 2.

```sh
git clone https://github.com/ristik/bft-core.git "$H6_RUN/h3-source"
git -C "$H6_RUN/h3-source" checkout --detach "$H6_BFT"
cd "$H6_RUN/h3-source"
make build
export H3_URETH_BIN="$H6_RUN/bin/ureth-$H6_NEW" H3_URETH_COMMIT="$H6_NEW"
export H3_EVIDENCE_DIR="$H6_RUN/h3"
H6_LOCK=()
if [ "$H6_SHARED_HOST" = 1 ]; then
  H6_LOCK=(bash "$H6_GUIDE/scripts/h6/devnet-lock.sh" 'H6 H3 independent rehearsal')
fi
"${H6_LOCK[@]}" env H3_LANE_LOCKED=1 bash "$H6_RUN/bin/run-h3.sh"
```

The pinned `scripts/h3-assignment-lane.sh:14–28` computes its repository's
parent and, by default, looks for `briefs/devnet-lock.sh` under that parent.
That is an optional developer-workspace convention; the file is not in this
repository. `H3_LANE_LOCKED=1` already bypasses that lookup, so no lane edit is
needed. Set it both on a dedicated host and under the optional outer lock, as
above. `H3_EVIDENCE_DIR` overrides the lane's developer-workspace evidence default.

Inputs: the pinned Ureth and `RUGREGATOR_BIN`/`RUGREGATOR_SOURCE` from build.md.
The thin `run-h3.sh` supervisor drains owned H3 children after the final scenario
PASS marker and checks the lane exit status. The pinned paired launcher otherwise
only stops the original four authorities and standard restore home before `wait`;
H3 creates extra authority/restore children. It uses a 1,800 s outer budget,
preserves failures and keeps the supervisor alive (and any outer lock held) if
an owned process will not stop. This teardown is final disposal, never a recoverable authority restart.
Outputs: `$H3_EVIDENCE_DIR/lane.log`, `heads.txt`, `h3/`, `nodes/`, `f8/`, plus
private node state in this fresh clone. This entry point exits nonzero on the
first failed step and requires `H3 acceptance lane: all steps PASSED`
(`scripts/h3-assignment-lane.sh:35`). Save node state privately before reuse.

Read [H3 sections 1–4](../h3-evm-assignment-runbook.md#1-read-the-context) alongside
the lane output. Its steps generate node identities and successor authority keys,
collect authority-backed PoPs, bind each root to an EVM delegate, assemble the
assignment, commit H, install roots, advance surviving authorities and restore
joiners. These are real key changes, not just a same-members epoch increment.

| Lane stage (`scripts/h3-assignment-steps.sh`) | Require in evidence |
|---|---|
| Baseline and config-only boundary, line 425 | EVM and all three aggregators progress; root epoch 2, shard epoch 0. |
| Bad PoP and coupled rotation, lines 450–491 | Bad proposal refused; root4→root5 and evm4→evm5 committed with acknowledgement held. |
| Root restart / retired key, lines 493–549 | Root/aggregator progress during EVM pause; retired evm4 requests rejected, no accepted request set from it. |
| Acknowledgement and proof, lines 552–621 | Authority advance, joiner restore, paid mint under epoch 3; offline F7 verification with epoch trust base and PDR. |
| Disk-loss restore, lines 623–640 | Retained validator loses BFT/EL state, same authority survives; epoch-3 replay, equal roots, resumed signing. |
| Unavailable successors and supersession, lines 642–700 | EVM stalls after committed H; fresh coupled successor extends that history, folded acknowledgement succeeds; late superseded ack refused. |

Use [M2 restore before/after checks](../m2-runbook.md#3-replace-a-validator-after-complete-disk-loss)
to inspect the archive pin, genesis epoch-1 anchor, current BodyID, empty restore
paths and two replicas. `shard-node restore` must include `--registry-layout 2`
for this fixture as well as `--trust-history-profile-2`; do not inherit the CLI's
layout-1 default when adapting the older runbook command. Archive restore replays
certified UC/TR/header history and missed handoffs; generic EL sync is refused.
A failed partial restore needs new empty paths, never deleted safety records in
a running node. No authority process may be cloned or restarted for this test.

The H3 lane does **not** establish the explicit operator Abort tests in scenario 2.
Its “late acknowledgement refused” is a different assertion from “abort after H
refused”. Keep separate evidence rows.

## 4. T6 monetary history and fresh-build cross-check

T6 builds a clean isolated BFT/Ureth/contracts toolchain, compiles the fixture
allocation, exercises claims, WUCT deposit/withdrawal and treasury withdrawal,
performs configuration-only handoffs and cross-epoch restore, and watches wallet
finality. Its parameters are placeholders, not production allocations.

From the original pinned clone, after exiting the manual-network shell:

```sh
cd "$H6_SRC"
export T6_EVIDENCE_DIR="$H6_RUN/t6"
H6_LOCK=()
if [ "$H6_SHARED_HOST" = 1 ]; then
  H6_LOCK=(bash "$H6_GUIDE/scripts/h6/devnet-lock.sh" 'H6 T6 independent rehearsal')
fi
"${H6_LOCK[@]}" env T6_LOCKED=1 \
  T6_BFT_COMMIT="$H6_BFT" T6_BFT_REF=integration/enshrined-evm \
  T6_URETH_COMMIT="$H6_NEW" T6_CONTRACTS_COMMIT="$H6_ALLOC" \
  T6_REGISTRY_CONTRACTS_COMMIT="$H6_REGISTRY" T6_RUST_TOOLCHAIN=1.97.1 \
  bash scripts/t6-rehearsal.sh
```

The pinned `scripts/t6-rehearsal.sh:5–28` likewise looks for
`briefs/devnet-lock.sh` under its repository's parent by default. This is the
same optional developer-workspace convention, not a required file. `T6_LOCKED=1`
skips the lookup; `T6_EVIDENCE_DIR` replaces the workspace-specific output default.
The command above works on a dedicated host without creating any lock, or inside
the optional repository lock on a shared host. Do not invoke either lane without
these overrides outside the original developer workspace.

Outputs include `t6-rehearsal.log`, `paired-lane.log`, build/contract comparison
logs, `source-pin.txt`, `compiler-toolchains.txt`, evidence checksums and summary.
On failure T6 retains its isolated checkout and partial evidence; on success it
removes the disposable build checkout. Do not treat an exit caused by cleanup as
passing. Check its final summary and every required evidence row. See
`scripts/t6-rehearsal.sh:118`, `:153`, `:186`, `:209`, `:255`.
