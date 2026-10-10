# Q4 #51: weighted adversarial gate, acceptance machinery

Refs [#51](https://github.com/ristik/bft-core/issues/51). This is the Q4-C slice: the export and independent replay checker, the
timing and query-cost gates, the focused CI job and the acceptance-report generator. It does not close #51 (see "What is not covered").

## What each piece does

| Piece | Where | What it is |
|---|---|---|
| Replay bundle and checker | `rootchain/consensus/q4replay`, `cmd/q4replay` | Every deterministic Q4-A/Q4-B row ends by exporting its run (epoch membership with keys and weights, the full serialized message trace, the committed chains, the progress and stall windows with the frozen deadline) and handing the file to the checker. The checker recomputes class, epoch, round, author and signed statement of every message from its bytes, verifies every signature (scheme 1 and the scheme 2 domain-bound statements), weighs the QCs a proposal carries, derives the equivocator set, checks chain agreement across nodes and recomputes the progress and stall windows against the frozen deadline. It reads no live counter and does not use the production quorum accumulator or the selector. `Q4_EXPORT_DIR=<dir>` keeps the bundles; `go run ./cmd/q4replay check [-equivocators a,b] <bundle.json>` re-checks one. |
| Leader-lookup call-site audit | `TestQ4LookupCallSites` | Every production call of `GetLeaderForRound` is in an audited table with the source of its round (own pacemaker round, a constant, or a message). A round a message supplies must be justified by authenticated evidence before the lookup; the two such routes (vote, proposal) name their prerequisite and the tests that exercise it. A new caller fails the test until it is audited. |
| Query-cost gate | `rootchain/consensus/leader/q4_cost_gate_test.go` | Frozen envelope and budgets (below); every mandatory row is asserted, in CI too (the rows take seconds). `Q4_COST_OUT=cost.json` keeps the measurements. |
| T2 boundary | `TestQ4T2Gate` | Eligible exactly at `elapsed >= uint64(T2/(BlockRate/2))+1`, one round below not, three shards with T2 2.5/5/7.5 s independent. |
| CI | `.github/workflows/q4-gates.yml` | Tagged build and vet, the deterministic rows above, the race run of shim/checker/report, the matrix consistency check, the cost gate CI profile and the live lane's `--dry-run`. The live lane is not run in CI. |
| Acceptance report | `cmd/q4report`, `docs/pos/q4-acceptance-matrix.json` | Maps every mandatory matrix row to evidence that passed or to an explicit gap. |

## Query-cost envelope (bounded lookup)

The weighted leader schedule is periodic with period W/gcd(weights), so with the total committed weight bounded by one profile constant
**B = 65,536** (`internal/weightcap`, enforced at every admission point before a weight commits) the selector holds one immutable period
table of at most 64 KiB, built once from verified context in at most n*B steps; a lookup is O(1), read-only and allocation-free.

Supported: committees of up to 100 members, total weight up to B, every round from the epoch start to `math.MaxUint64`.
Budget: constructor plus lookup at most **2 s**, no concurrent caller waits longer, at most 512 KiB and 2,048 allocations. These are the
budgets frozen before the change and are not widened. `TestQ4QueryCostGate` asserts every mandatory row (n=100 at d=10^6, d~6x10^5, near
MaxUint64, worst-period inputs; cold restart, old query, eight synchronized concurrent callers, rebuild after cache eviction); none is
measured-only. The before-change baseline (the replaying selector: 2.0 s on the Q4-C host and 4.0 s on the #489 host at n=100, d=10^6,
growing with d, blocking every concurrent caller; its test weights exceeded the committed-weight cap that now applies) is kept as a
recorded constant, not re-run.

## Producing the acceptance report

```sh
mkdir -p out/bundles
export Q4_EXPORT_DIR=$PWD/out/bundles   # absolute: go test runs in each package directory
go test -json -count=1 ./rootchain/... ./cli/ubft/cmd/ ./cmd/... -timeout 60m \
  -run '^(TestQ4|TestQ3|TestMessageRounds|TestWeighted|TestSkewedWeight|TestTwoRestarted|TestProductionBuild|TestT2|TestPartitionTimeout|TestPacemaker|TestVoteRegister|TestOldForm|TestInstallVerified|TestNoSignature|TestCheck|TestLeaderAfter|TestTableCache|TestAJoinerRoot)' > out/tests.json
Q4_COST_OUT="$PWD/out/cost.json" go test -count=1 ./rootchain/consensus/leader/ -run Q4
go run ./cmd/q4report -matrix docs/pos/q4-acceptance-matrix.json -tests out/tests.json -bundles out/bundles -cost out/cost.json \
  -lane <scenario A evidence dir> -lanes b=<scenario B evidence dir>,a2=<heavy on root 2>,a3=<heavy on root 3>,a4=<heavy on root 4>,q3=<Q3 weight-activation lane evidence dir> \
  -out out/report.md -json out/report.json
```

Exit status: 0 consistent (gaps are listed, not hidden), 1 a failed, not-run, stale or unaccounted row, 3 with `-require-complete` while any
gap remains (that is the #51 closure check), 2 a read error. A row can claim a coverage label (`IN-PROCESS`, `REAL-PROCESS`,
`ORACLE-ONLY`, `MEASURED`, `STATIC`) only through passed evidence carrying it; a required label with neither evidence nor a reasoned gap
fails the run. Outcome (pass/fail) stays separate from the assumption class (`IN-BOUND`, `OUTSIDE-ASSUMPTIONS`): an outside-the-assumptions
row passes when the injection happened and was classified, and proves no safety guarantee.

## The live lane run

```sh
# Q4_SCENARIO=A (default, weights 6,1,1,1) or B (weights 3,3,2,1): two runs, two evidence directories
Q4_SCENARIO=B Q4_BFT_COMMIT=$(git rev-parse HEAD) Q4_URETH_COMMIT=<merged ureth commit> RUGREGATOR_BIN=<F8 pin binary> RUGREGATOR_SOURCE=<F8 pin checkout> scripts/q4-live-lane.sh
# a ureth built beforehand from a fresh private target at exactly that commit: Q4_URETH_BIN=<it> Q4_URETH_FRESH_BUILD=1 (anything else is a development override and no evidence)
# the other heavy placements of A (F1): Q4_HEAVY_AT=2, 3 or 4 puts the weight-6 identity on that root; such a run carries the placement rows only
Q4_SCENARIO=A Q4_HEAVY_AT=3 ... scripts/q4-live-lane.sh
```

The roots run the q4shim build, which carries two seams: the consensus shim (per-peer pass/drop/hold/duplicate and ordered release of proposals, votes and timeouts,
the Byzantine equivocation adapter, and the forgery adapter for the authentication-refusal rows) and the shard gate (q4shim.ShardGate: hold or drop one partition's
certification requests, handshakes and certification responses, optionally of named shard nodes only, released in order). Both are driven by control files in the
root's shim directory (`control.json`, `shard-control.json`) and leave traces (`trace.jsonl`, `shard-trace.jsonl`).

The rows of scenario A after the original fault rows: the T2 record during root quorum loss (`q4/t2-quorum-loss.jsonl` and `.txt`), the EVM-only outage of the heavy and of
a light entity's EVM pair (shard node and Ureth stopped while every root runs; request Q=5), the EVM-only partition of the same pairs through the roots' shard gates (healed
without rollback: the pre-cut EVM block keeps its hash), the delay of the EVM shard's requests, duplication of the lights' traffic while the heavy is held (no replayed
weight), a last-in-first-out release of the heavy's held traffic (reorder), the authentication-refusal representatives (`q4/auth-refusals.txt`), a quorum-wide SIGKILL
and restart, and then the second handoff A to B on the same running chain with the first successor proposal held (`q4/first-successor-proposal.txt`), B in effect
(`q4/b-in-effect.txt`) and the EVM request-Q=5 rows under B. Scenario B adds its T2 record, EVM cuts, authentication refusals and quorum-wide restart. Every progress
assertion exports its latencies (`q4/timing.jsonl`, `q4/timing-summary.txt`: first and n-th increment, the largest gap, the TCs in the window), next to a no-fault
control window at the same load.

One devnet run per scenario (queued on `briefs/devnet-lock.sh`): the Q3 weight-activation flow on the fresh-B1 stack (unit PoA to mirrored weights 6,1,1,1 or 3,3,2,1, scheme 2,
root-wrr-v1), then the Q4 rows through the roots' q4shim build. The gate `Q4_WEIGHTED_CHECK` defaults to `q4_weighted_epoch_check`, a function of the Q3
flow library that reads the activated epoch from the root's own verified state; its command, output and exit status are kept in `weighted-check.txt`.
Before any fault the lane also checks that the selector in effect is the weighted one (`q3_leader_schedule` over at least 45 rounds of the epoch, and the committed tuple names `root-wrr-v1`) and that no root reports itself a follower (#515). A gate other than the default function makes the run a development override. `q4report -lane <evidence dir>` then maps the lane's PASS lines and files to the matrix rows.

## What is not covered

- **Scenarios.** The live lane runs the committees A (6,1,1,1) and B (3,3,2,1) on the four-entity paired devnet. The many-small committee (18,1x9, ten entities, row F7) and the #399
  outage control (3,2,2,2,2, five entities, row F8) cannot be built live: the devnet and the Q3 flow address exactly four entities. Both rows keep an explicit REAL-PROCESS gap.
- **Root-fault rows judge the root committed round.** Under a root fault the coupled EVM pipeline is not asserted: the EVM certified round also needs the EVM nodes' durable
  archive acknowledgements, and an EVM node whose paired root is cut off cannot verify the blocks it is asked to acknowledge, so the EVM round can stand still while the roots
  correctly keep their quorum (scenario A run `q4-live-20261009T062325Z`: two lights isolated, EVM round stuck at 45 while the roots kept committing). The EVM pipeline is
  judged in the baseline, in the EVM-only rows (roots intact) and in the recoveries that require certified EVM blocks (quorum-wide restart, EVM outage and cut heals).
- **The A to B handoff reweights the same four entities.** The design's A to B replaces coupled entity c by a new entity d; the four-entity devnet has no fifth entity,
  so the live handoff is (6,1,1,1) to (3,3,2,1) over the same identities and the identity turnover stays an explicit gap (F17, `REAL-PROCESS (turnover)`).
- **The EVM-only partition is a cut at the roots.** The roots' shard gates hold the pair's certification traffic both ways; the EVM nodes' peer-to-peer links among
  themselves and their RPC paths stay up. The EVM outage is an orderly stop of the pair (shard node and Ureth), not a SIGKILL.
- **Authentication refusals are representatives, one per variant, sent next to the forger's own timeouts and votes** while the heavy (A) or one weight-3 root (B) is held, so
  that the impersonated weight would complete a quorum if it were counted. A refusal is read from a receiving root's log line for that variant; the forged messages are
  traced as `forge` and never counted as an author's statement by the trace check.
- **Each Byzantine row arms exactly its own roots and clears them before it ends.** The lane records when each row armed and cleared its adapters (`q4/byz-windows.jsonl`);
  the trace check holds every equivocation in the traces to the window of its own root and requires every armed root to have equivocated inside its window, so the heavy
  equivocator (F3, F4) runs alone and the in-bound row's equivocators (F5, F6) are not running during it.
- **Heavy equivocators (F3, F4)** are outside the assumptions: the live rows show that the equivocation happened (the root's own adapter counted its conflicting signed votes)
  and that the independent checker classifies exactly the declared roots as equivocators; they claim no liveness or safety.
- **G2** is evidenced by the Q3 lane's paired authentication (`-lanes q3=<dir>`): a second pair restored through the archive path reaching equal commitments, the five pair
  controls, retention and restart. Rollback below the finalized pair head is not exercised live.
- Every in-process row is root consensus only: no EVM, no aggregator shard, restarts are close/reopen of fsynced stores (not SIGKILL, not
  power loss). The checker does not re-verify the signatures inside a carried QC (it weighs the QC's signers under their epoch); carried TCs and the HighQC inside a timeout are not weighed; equivocation is detected for votes and timeouts only, not proposals.
- **The F8 EVM stop/resume callbacks are evidenced only in the lane preamble, in the unit epoch.** In the weighted epoch the lane shows that the aggregator shards stay served (their authorized TR rounds advance and the aggregators answer) and that each of the three shards certifies a new state root whose non-empty `aggregator_rsmt_v1` proof the root that receives the certification request verifies (row T1; one root, not each root in consensus: the step name and its record say "the roots"; the proof of a non-first block was empty before #539/#541 and #532). The lane does not stop the EVM in the weighted epoch.
- No non-member or removed-validator root runs in the live lane (all four roots stay members): the follower signing nothing and catching up on a real network is an explicit gap (row L5), blocked on the P85 slice 7 joiner run or an A to B removal handoff.
- Mixed-HighQC TC is covered only by the unit-weight unit test, not weighted.
