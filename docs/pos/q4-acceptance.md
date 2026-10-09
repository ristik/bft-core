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
  -run '^(TestQ4|TestQ3|TestMessageRounds|TestWeighted|TestSkewedWeight|TestTwoRestarted|TestProductionBuild|TestT2|TestPartitionTimeout|TestPacemaker|TestVoteRegister|TestOldForm|TestInstallVerified|TestNoSignature|TestCheck)' > out/tests.json
Q4_COST_OUT="$PWD/out/cost.json" go test -count=1 ./rootchain/consensus/leader/ -run Q4
go run ./cmd/q4report -matrix docs/pos/q4-acceptance-matrix.json -tests out/tests.json -bundles out/bundles -cost out/cost.json -out out/report.md -json out/report.json
```

Exit status: 0 consistent (gaps are listed, not hidden), 1 a failed, not-run, stale or unaccounted row, 3 with `-require-complete` while any
gap remains (that is the #51 closure check), 2 a read error. A row can claim a coverage label (`IN-PROCESS`, `REAL-PROCESS`,
`ORACLE-ONLY`, `MEASURED`, `STATIC`) only through passed evidence carrying it; a required label with neither evidence nor a reasoned gap
fails the run. Outcome (pass/fail) stays separate from the assumption class (`IN-BOUND`, `OUTSIDE-ASSUMPTIONS`): an outside-the-assumptions
row passes when the injection happened and was classified, and proves no safety guarantee.

## The live lane run

```sh
Q4_BFT_COMMIT=$(git rev-parse HEAD) Q4_URETH_COMMIT=<merged ureth commit> RUGREGATOR_BIN=<F8 pin binary> RUGREGATOR_SOURCE=<F8 pin checkout> scripts/q4-live-lane.sh
# a ureth built beforehand from a fresh private target at exactly that commit: Q4_URETH_BIN=<it> Q4_URETH_FRESH_BUILD=1 (anything else is a development override and no evidence)
```

One devnet run (queued on `briefs/devnet-lock.sh`): the Q3 weight-activation flow on the fresh-B1 stack (unit PoA to mirrored weights 6,1,1,1, scheme 2,
root-wrr-v1), then the Q4 rows through the roots' q4shim build. The gate `Q4_WEIGHTED_CHECK` defaults to `q4_weighted_epoch_check`, a function of the Q3
flow library that reads the activated epoch from the root's own verified state; its command, output and exit status are kept in `weighted-check.txt`.
Before any fault the lane also checks that the selector in effect is the weighted one (`q3_leader_schedule` over at least 45 rounds of the epoch, and the committed tuple names `root-wrr-v1`) and that no root reports itself a follower (#515). A gate other than the default function makes the run a development override. `q4report -lane <evidence dir>` then maps the lane's PASS lines and files to the matrix rows.

## What is not covered

- **The live lane has not been run.** Every REAL-PROCESS label in the matrix is an explicit gap blocked on #50 (the devnet lock and an
  activated weighted epoch). Closure of #51 needs those rows.
- Every in-process row is root consensus only: no EVM, no aggregator shard, restarts are close/reopen of fsynced stores (not SIGKILL, not
  power loss). The checker does not re-verify the signatures inside a carried QC (it weighs the QC's signers under their epoch); carried TCs and the HighQC inside a timeout are not weighed; equivocation is detected for votes and timeouts only, not proposals.
- **The F8 callbacks (EVM stop/resume, aggregators certifying new state roots) are evidenced only in the lane preamble, in the unit epoch.** They cannot be repeated in the weighted epoch with the pinned rugregator: the second block of an aggregator shard carries an empty RSMT proof ("missing leaf_count") and the roots reject it as ProofInvalid. In the weighted epoch the lane shows only that the aggregator shards stay served (their authorized TR rounds advance and the aggregators answer). Row T1 carries the explicit gap.
- No non-member or removed-validator root runs in the live lane (all four roots stay members): the follower signing nothing and catching up on a real network is an explicit gap (row L5), blocked on the P85 slice 7 joiner run or an A to B removal handoff.
- Mixed-HighQC TC is covered only by the unit-weight unit test, not weighted.
- The execution-entry-point authentication entry gate (G2) is not touched by any Q4 test.
