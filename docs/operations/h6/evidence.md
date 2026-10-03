# Evidence, interruption and acceptance

Return to [entry point](README.md). Approval is based on the run's actual
artifacts, not this document or earlier developer PASS messages.

## Record a monetary history anchor

Before the manual upgrade, define this function in the manual shell; scenario 1
calls it at the baseline boundary.
It saves every finalized block through the baseline tip, including full
transaction receipts, and refuses RPC errors. The finalized tip must also have a
matching `certificate admitted` record in each shard log. Do not infer certification
from an Ethereum receipt alone.

```sh
save_history() {
  local label=$1 url=http://127.0.0.1:18545 height h block tx
  mkdir -p "$H6_RUN/$label"
  height=$(rpc "$url" eth_getBlockByNumber '["finalized",false]' | jq -er '.result.number')
  for h in $(seq 0 "$((height))"); do
    block=$(printf '0x%x' "$h")
    rpc "$url" eth_getBlockByNumber "[\"$block\",false]" | \
      jq -e '.result | select(.hash and .stateRoot and .receiptsRoot)' > "$H6_RUN/$label/block-$h.json"
    for tx in $(jq -r '.transactions[]' "$H6_RUN/$label/block-$h.json"); do
      rpc "$url" eth_getTransactionReceipt "[\"$tx\"]" | \
        jq -e '.result | select(.blockHash)' > "$H6_RUN/$label/receipt-$tx.json"
    done
  done
}
```

After new ELs start, before shard restart, use the fixed saved heights (do not
compare only the moving latest head):

```sh
for i in 1 2 3 4; do
  url="http://127.0.0.1:$((18545+i-1))"
  for file in "$H6_RUN/history-before-upgrade"/block-*.json; do
    height=$(jq -r '.number' "$file")
    rpc "$url" eth_getBlockByNumber "[\"$height\",false]" | \
      jq -e --slurpfile old "$file" \
      '.result | [.hash,.stateRoot,.receiptsRoot,.transactions] == ($old[0] | [.hash,.stateRoot,.receiptsRoot,.transactions])'
  done
  for file in "$H6_RUN/history-before-upgrade"/receipt-*.json; do
    tx=$(jq -r '.transactionHash' "$file")
    rpc "$url" eth_getTransactionReceipt "[\"$tx\"]" | \
      jq -e --slurpfile old "$file" '.result == $old[0]'
  done
done
```

Repeat after resumed certification and after the abort/handoff. The H3 and T6
lanes additionally extract receipt inclusion bundles from certified archive
records and verify them offline. Preserve their `.cbor`, verifier JSON, expected
claim, PDR, genesis configuration and every epoch trust base. H3's verifier command
is shown in `scripts/h3-assignment-steps.sh:603`; its output lives under
`h3/f7-<root-epoch>-<shard-epoch>/`. T6 preserves its proof under `paired-evidence/`
and at the evidence root. Re-run the included verifier with those exact inputs
in a network-denied `sandbox-exec` invocation, as the H3 lane does. An archive
file listing or equal RPC roots alone is not a cryptographic history check.
For the H3 epoch-3 locked-42-wei fixture, independently repeat the offline check:

```sh
contract=$(sed -n 's/^locked 42 wei: .* contract=//p' "$H3_EVIDENCE_DIR/lane.log" | head -1)
test -n "$contract"
sandbox-exec -p '(version 1) (allow default) (deny network*)' \
  "$H6_SRC/build/f7-mintproof-verify" \
  --bundle "$H3_EVIDENCE_DIR/h3/f7-3-1/locked.cbor" \
  --trust-base "$H6_RUN/h3-source/test-nodes/trust-base-epoch3.json" \
  --genesis-conf "$H6_RUN/h3-source/test-nodes/evm-full-shard-conf-v2.json" \
  --lock-contract "$contract" --mode locked > "$H6_RUN/independent-f7-epoch3.json"
```

Preserve those public trust/genesis inputs beside the proof before disposing of
the clone. The verifier's `locked` mode is the fixed demonstration predicate;
it is not a general arbitrary monetary-claim verifier.

## Measuring interruption

Approve objectives before the run. Proposed **OWNER defaults**, for this host:
maximum 40 s certification pause for ordinary handoff/abort recovery; 120 s for
coordinated Ureth stop/swap/restart; 180 s to restore one validator and resume its
signing. Keep cluster service interruption and one-node restore time separate.
The latter two are provisional budgets, not measured upgrade/restore guarantees.

Measured T6 examples in the evidence workspace include 23.136 s and 24.998 s
(`briefs/devnet-runs/t6-rehearsal-20261002T033706Z/t6-rehearsal.log:1824,1837`),
22.843 s in the run4 monitor-timeout attempt (`:312`), and 31.936 s in another
failed attempt (`t6-rotation-run4-attempt2-monitor-timeout/t6-rehearsal.log:313`).
These explain the proposed 40 s headroom; failed attempts must not be presented
as successful acceptance runs. Do not set the objective by selecting only a fast
22.8–25.0 s sample. OWNER may choose stricter objectives and accept a failed run.

For each operation:

1. Save an external observer's UTC and monotonic timestamps, polling each EL's
   `finalized` block every 0.5 s and capturing shard status at boundaries. Record errors as observations;
   keep observing during planned restart. Do not skip outages or reset the clock.
2. Mark stop/proposal/Abort submission and acknowledged completion times. Save
   log offsets/PIDs so old logs cannot satisfy new checks.
3. Compute the time from the last distinct certified block before the operation
   to the first later distinct certified block afterwards on each affected
   validator; report the worst validator and the cluster's service gap. Require
   three subsequent advancing samples and a successful certified paid transaction.
4. Report also command duration, time to first successful submitted transaction,
   restore-to-ready time, observer sample gaps and 0.5 s sampling uncertainty.
   If clocks differ across hosts, use one observer's monotonic clock for duration.
5. Compare with the approved objective; missing endpoints or missing ordered
   certificates mean **unmeasured/fail**, never zero interruption.

The manual `m2_measure_pause 1 2` command and T6 pause lines calculate a narrower
old-epoch/new-epoch log gap (`scripts/lib/m2-handoff-lib.sh:144`). Keep that number
but do not substitute it for upgrade (same epoch), pre-H Abort (same epoch), or
user-visible transaction recovery. The T6 finality observer provides raw JSONL
and checks monotonic finalized history; preserve `t6-finality-monitor.jsonl`.
For manual work, use this standard-library observer in a second terminal inside
the same locked session (background child); stop it only after recovery:

```sh
python3 -u - "$H6_RUN/observations.jsonl" <<'PY' &
import datetime,json,sys,time,urllib.request
with open(sys.argv[1], 'x') as out:
    while True:
        for i in range(1,5):
            row={'validator':i,'monotonic':time.monotonic(),
                 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
            try:
                req=urllib.request.Request(f'http://127.0.0.1:{18544+i}',
                    json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_getBlockByNumber',
                                'params':['finalized',False]}).encode(),
                    {'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=0.4) as response:
                    row['rpc']=json.load(response)
            except Exception as error:
                row['error']=str(error)
            out.write(json.dumps(row)+'\n'); out.flush()
        time.sleep(0.5)
PY
H6_OBSERVER=$!
# After all manual scenarios and snapshots:
# kill "$H6_OBSERVER"
# wait "$H6_OBSERVER" || true
```

Sequential polling adds up to 1.6 s during a four-endpoint outage; use actual
per-row monotonic intervals as uncertainty, not a claimed fixed 0.5 s resolution.
Cross-check sampled hashes against certificate logs. Idle unchanged tips are not
new certifications. Keep baseline load/transaction cadence in the record so an
idle chain is not mistaken for downtime.

## Acceptance map

| H6 requirement | Scenario and required evidence |
|---|---|
| Fresh reproducible setup | build.md + network.md; source/toolchain pins, build hashes, genesis identities, empty-home check, topology and authority enrollment. |
| Key rotation | H3 coupled root/EVM replacement; successor PoPs and bindings, committed H, authority advancements, retired-key refusal, new-epoch paid certificate. A config-only boundary is insufficient. |
| Execution-version activation | Manual old→new Ureth pair; source diff and both test logs, same-state reopen, all-new binary hashes, old monetary anchors unchanged, post-resume paid certification and timing. |
| Archive-backed restore | H3 retained-node loss + T6 cross-epoch restore; pin UC/TR, genesis anchor, bundles, replay log, equal block/state/receipt roots, same authority lifetime, greater reserved round. |
| Abort before H | Exact saved target, committed Abort record/round/root proof location, phase=aborted, paid receipt after Abort and attempt+1 retry. Lapse does not substitute. |
| Abort after H | Same committed target yields nonzero CLI and `too late`; committed H remains installed; subsequent certification follows that history. Supersession/late-ack evidence is a separate row. |
| Interrupted handoff | H3 unavailable successor set stalls EVM, keeps roots/aggregators moving; authorized supersession extends H and refuses late old acknowledgement. |
| Interruption objective | Raw observer JSONL, boundaries/PIDs, per-node and cluster durations, uncertainty, preapproved OWNER objectives and pass/fail for every scenario. |
| Certified history verifiable | Saved monetary receipts/roots unchanged; archived UC/TR and handoff chain; independent offline F7 proof verification and full archive restore replay. |
| No certified monetary reorg | Fixed-height/hash/receipt comparisons, monotonic finalized observer, no older-state downgrade or snapshot rollback; preserve the stopped failure if recovery cannot be proved. |
| Execution by non-author | Named human second operator, documentation revision, transcript, defects and actual result; author's source checks are not independent acceptance. |
| Added authority-loss/freshness scope in issue discussion | Explicit unsupported/refused same-key resurrection; separate evidence needed for certified replacement, clone/fencing, expired receipts and storage faults. Do not mark all of issue 23 complete from these lanes alone. |

## Troubleshooting: stop at the first unexplained refusal

| Exact diagnostic or record | Action |
|---|---|
| `invalid epoch transition encoding` | Check client pin and registry layout; no initialized layout-1 migration. Recreate only a disposable fresh network, never rewrite live genesis. |
| `registry layout: resolved for ureth` | Compare approved upgrade record with saved layout file; only the reviewed same-layout upgrade may update its client pin. |
| `signing-unsupported-version` | Client/service protocol mismatch; stop the client, restore matching artifacts without killing the live authority. |
| `restore trust anchor is not the genesis root epoch` | Supply epoch-1 anchor; keep current BodyID separately. |
| `archive wiring: archive peer is not allowed` | Wait for retained validators to install/replay assignment; bounded retry can expire. Retry restore on fresh paths only after context is correct. |
| `frontier: wrong context or configured replicas` | Preserve frontier/journal; change only one replica, retain the acknowledged peer and ordering. |
| `candidate lacks its retained authorizing or resulting certificate`, `no certified association` | Compare prune frontier with local archive tip; beyond-window recovery requires archive restore. |
| `root handoff: the Prepare lapsed before it was endorsed`, `phase=lapsed` | Attempt is dead; preserve evidence, wait for terminal state and read fresh context. Not committed Abort evidence. |
| `too late` | Matching H already committed; no cancellation/rollback. Install successor or use the authorized supersession procedure. |
| `local operator access required` | Use loopback/control tunnel; do not weaken endpoint access checks. |
| `application/json without Origin required` | Use the provided CLI/helper, with JSON and no browser Origin header. |
| `archive publication waiting`, `archive replica waiting`, `certified frontier waiting` | Inspect both replicas and status errors; no second-replica maintenance or pruning bypass. |
| `authority ... exited during startup`, `keyLost`, `faulted` | Preserve logs, fence affected shard, escalate. No authority restart or key import can restore the old signing permission. |

Also see [bootstrap failure handling](../bootstrap-trust-pin.md#failure-handling)
and [M2 stop conditions](../m2-runbook.md#6-checks-and-stop-conditions). Support
escalation records must include artifact pins, run ID, last certified tip and
exact refusal, without credentials. OWNER supplies the contact before rehearsal.

## Evidence checklist and independent execution

Retain: approved objectives; operator identity/date; documentation/helper SHA;
source SHAs and clean-tree state; binary hashes/toolchain versions; configuration
hashes and generated genesis identities; public node infos and epoch trust bases;
all command outputs/exit codes; PID/start boundaries; authority status before/after;
per-node logs; observer JSONL; monetary receipts and fixed-height roots; archive
pin/UC/TR and handoff bundles; offline proof inputs/results; per-scenario pass/fail
and unsupported items. Build a SHA-256 inventory after collection. Publish only
an allowlisted evidence copy: omit `keys.json`, JWTs, client/operator credentials,
private state and raw environment dumps. Hashes do not redact secrets.

A fresh agent with no repository context may follow only this guide, the linked
operations sections, documented `--help`, command output and generated run
artifacts under the shared devnet lock. It may execute the named lane/library
calls but must not read their source, previous private notes or developer
transcripts to fill gaps. Missing variables, unexplained flags, hidden files,
manual source edits, undocumented recovery choices, stale evidence passing checks,
or author intervention are **documentation defects**. Stop the affected scenario,
record the defect, fix the guide, and repeat on a fresh disposable fixture. A fresh
agent is a usability test; the OWNER-appointed human second operator is still
needed for the stated acceptance record.

Validation of this documentation change: build ubft and inspect command help,
syntax-check all shell blocks, check Markdown links and helper behavior with mock
HTTP responses. Do not claim those checks as a devnet rehearsal. The implementation
fits one documentation PR plus a small operator adapter; no protocol changes or
additional PR series is required. Independent live acceptance remains a later run.
