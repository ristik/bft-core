# Q4 #51: weighted adversarial gate, acceptance machinery

Refs [#51](https://github.com/ristik/bft-core/issues/51). This is the Q4-C slice: the export and independent replay checker, the
timing and query-cost gates, the focused CI job and the acceptance-report generator. It does not close #51 (see "What is not covered").

## What each piece does

| Piece | Where | What it is |
|---|---|---|
| Replay bundle and checker | `rootchain/consensus/q4replay`, `cmd/q4replay` | Every deterministic Q4-A/Q4-B row ends by exporting its run (epoch membership with keys and weights, the full serialized message trace, the committed chains, the progress and stall windows with the frozen deadline) and handing the file to the checker. The checker recomputes class, epoch, round, author and signed statement of every message from its bytes, verifies every signature (scheme 1 and the scheme 2 domain-bound statements), weighs the QCs a proposal carries, derives the equivocator set, checks chain agreement across nodes and recomputes the progress and stall windows against the frozen deadline. It reads no live counter and does not use the production quorum accumulator or the selector. `Q4_EXPORT_DIR=<dir>` keeps the bundles; `go run ./cmd/q4replay check [-equivocators a,b] <bundle.json>` re-checks one. |
| Leader-lookup call-site audit | `TestQ4LookupCallSites` | Every production call of `GetLeaderForRound` is in an audited table with the source of its round (own pacemaker round, a constant, or a message). A round a message supplies must be justified by authenticated evidence before the lookup; the two such routes (vote, proposal) name their prerequisite and the tests that exercise it. A new caller fails the test until it is audited. |
| Query-cost gate | `rootchain/consensus/leader/q4_cost_gate_test.go` | Frozen supported envelope and budgets (below). CI runs the cheap profile; `Q4_COST_FULL=1 Q4_COST_OUT=cost.json` runs the whole envelope and measures the distance beyond it. |
| T2 boundary | `TestQ4T2Gate` | Eligible exactly at `elapsed >= uint64(T2/(BlockRate/2))+1`, one round below not, three shards with T2 2.5/5/7.5 s independent. |
| CI | `.github/workflows/q4-gates.yml` | Tagged build and vet, the deterministic rows above, the race run of shim/checker/report, the matrix consistency check, the cost gate CI profile and the live lane's `--dry-run`. The live lane is not run in CI. |
| Acceptance report | `cmd/q4report`, `docs/pos/q4-acceptance-matrix.json` | Maps every mandatory matrix row to evidence that passed or to an explicit gap. |

## Frozen query-cost envelope (2026-10-08, before acceptance)

Supported: committee up to 100 members, weights up to 2^40, a cold restart, catch-up jump or old uncached query up to **100,000**
rounds past the epoch start or the cache (about 28 hours of epoch at 1 s rounds).

Budget: one lookup at the envelope takes at most **2 s** (the consensus loop is blocked for it), no concurrent caller waits longer behind
it, and a lookup allocates at most 512 KiB and 2,048 objects. Budgets scale linearly with the distance for smaller profiles (20 us per
round), so the CI profile (n=100, d=10,000: 200 ms) keeps the same per-round budget.

A distance beyond 100,000 rounds is not supported and is never passed: the full profile measures it and the report prints it. Nothing in
production bounds the epoch length or a jump to the envelope, and no checkpoint or accelerated lookup exists, so this is a release
prerequisite owned by separate work (#489 left it unscoped), not a waived gate.

## Producing the acceptance report

```sh
export Q4_EXPORT_DIR=$PWD/out/bundles
go test -json -count=1 ./rootchain/... ./cli/ubft/cmd/ ./cmd/... -timeout 60m \
  -run '^(TestQ4|TestQ3|TestMessageRounds|TestWeighted|TestSkewedWeight|TestTwoRestarted|TestProductionBuild|TestT2|TestPartitionTimeout|TestPacemaker|TestVoteRegister|TestOldForm|TestInstallVerified|TestNoSignature|TestCheck)' > out/tests.json
Q4_COST_FULL=1 Q4_COST_OUT=out/cost.json go test -count=1 ./rootchain/consensus/leader/ -run Q4
go run ./cmd/q4report -matrix docs/pos/q4-acceptance-matrix.json -tests out/tests.json -bundles out/bundles -cost out/cost.json -out out/report.md -json out/report.json
```

Exit status: 0 consistent (gaps are listed, not hidden), 1 a failed, not-run, stale or unaccounted row, 3 with `-require-complete` while any
gap remains (that is the #51 closure check), 2 a read error. A row can claim a coverage label (`IN-PROCESS`, `REAL-PROCESS`,
`ORACLE-ONLY`, `MEASURED`, `STATIC`) only through passed evidence carrying it; a required label with neither evidence nor a reasoned gap
fails the run. Outcome (pass/fail) stays separate from the assumption class (`IN-BOUND`, `OUTSIDE-ASSUMPTIONS`): an outside-the-assumptions
row passes when the injection happened and was classified, and proves no safety guarantee.

## What is not covered

- **The live lane has not been run.** Every REAL-PROCESS label in the matrix is an explicit gap blocked on #50 (the devnet lock and an
  activated weighted epoch). Closure of #51 needs those rows.
- Every in-process row is root consensus only: no EVM, no aggregator shard, restarts are close/reopen of fsynced stores (not SIGKILL, not
  power loss). The checker does not re-verify the signatures inside a carried QC or TC (it weighs the QC's signers under their epoch).
- Mixed-HighQC TC is covered only by the unit-weight unit test, not weighted.
- The execution-entry-point authentication entry gate (G2) is not touched by any Q4 test.
