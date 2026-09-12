# F1e (#127): why `Test_rootNetworkRunning` and `Test_recoverState` fail on macOS

**Status: diagnosed, with the cause confirmed by intervention.** On macOS every synced bbolt commit is an
`F_FULLFSYNC`. The consensus test fixtures open real bbolt stores with default options (sync on every
commit), and a node makes several synced commits on a round's critical path before its vote leaves. At
the fixtures' four nodes those commits cost ~115 ms each, so rounds take 500–600 ms where the tests were
calibrated for ~100 ms, and their fixed budgets run out. On Linux the same commits cost ~4 ms and the
tests pass. The intervention identifies disk-flush cost as sufficient to explain the measured fixture failures.
It supports decoupling these accelerated consensus tests from durable-write latency, without changing
their deadlines. It does not establish that all consensus timing defects are absent. The repair is a separate change:
the fixture opens its throwaway stores without syncing, production stores keep syncing
(§6).

Base: integration `6edcfeb5318e0ab951c02f6f97add4191d799be2`. No source change was needed to diagnose it;
the one intervention (§4) was a temporary, reverted patch.

## 1. The failures, reproduced

Host: macOS 15.7.9, Intel Core i7-8850H (darwin/amd64), 12 logical CPUs, 16 GiB, APFS on the internal
SSD. Every run `go test ./rootchain/consensus -run <pattern> -count=1 -json`, one at a time, nothing else
running on the host.

| run | test | toolchain / platform | result |
|---|---|---|---|
| 1 | `Test_rootNetworkRunning` | go1.27.1 darwin/amd64 | **FAIL** 6.54 s — "waiting for round 10 to be achieved"; the nodes reached rounds 8–9 |
| 2 | `Test_recoverState` | go1.27.1 darwin/amd64 | **FAIL** — 8 of 9 subtests; only `dead_leader` passes |
| 3 | `Test_rootNetworkRunning` | go1.24.6 darwin/amd64 | pass, 6.64 s — but only 68 messages in 5.10 s: ~600 ms per round, inside a 5.45 s budget by a margin |
| 4 | `Test_recoverState` | go1.24.6 darwin/amd64 | **FAIL** — the same 8 of 9 |
| 5 | `Test_rootNetworkRunning`, debug log | go1.27.1 darwin/amd64 | pass — rounds of 500–600 ms (§3) |
| 6 | `Test_recoverState/late_joiner_catches_up`, debug log | go1.27.1 darwin/amd64 | **FAIL** 5.54 s at `consensus_recovery_test.go:314`, "waiting for sleepy consensus manager to catch up" |
| L1 | both | go1.24.13 **linux/amd64** (`golang:1.24` image, 2 CPUs, Docker on the same Mac) | **all pass**: `Test_rootNetworkRunning` 1.41 s; `Test_recoverState` 9/9 in 0.49–5.07 s |

The reviewer's retained run on this darwin/amd64 host (`consensus.jsonl`, sha256 `f032ad1a…`) and the ledger
author's three earlier runs on this host show the same failing set. The retained Linux-container run passes; this investigation does not audit every historical CI run.

**The failure is not specific to one tested Go toolchain.** Go 1.24.6 passes `Test_rootNetworkRunning` once where Go 1.27.1
failed once, but Go 1.27.1 also passed it once (run 5), and `Test_recoverState` fails identically on
both. `Test_rootNetworkRunning` sits on a knife edge on this host whatever the toolchain;
`Test_recoverState`'s budgets are further out of reach.

**No initial progress, or failed recovery?** Both, and for the same reason. Most `Test_recoverState`
subtests fail at their *first* `Eventually` — "waiting for rounds to be processed", i.e. round ≥ 6 within
5–6 s with three or four live nodes — before any fault is injected. `late_joiner_catches_up` passes that
step (round 6 at 2.2 s) and fails the recovery step: the late node's recovery and catch-up must fit a
2 s window while each of its synced commits costs ~115 ms. With cheap commits (§4) every measured subtest passes, recovery included; no independent
recovery-logic defect was demonstrated by this investigation.

## 2. The cost, measured directly

`docs/design/f1e/fsyncprobe` opens bbolt exactly as the fixtures do (default options, so every commit
syncs) and times 512-byte commits, alone and with four stores committing concurrently (one per fixture
node), against `NoSync`:

| per-commit latency | synced (the fixtures' mode) | `NoSync` |
|---|---|---|
| macOS, 1 store, 60 commits | mean **45.1 ms**, p50 43.4, p95 65.8, max 80.9 | mean 1.15 ms |
| macOS, 4 stores concurrently, 120 commits | mean **115.3 ms**, p50 107.6, p95 195.0, max 296.1 | mean 3.83 ms |
| Linux container on the same Mac, 1 store | mean 3.03 ms | 0.32 ms |
| Linux container, 4 stores concurrently | mean **4.21 ms**, p95 8.73 | 0.68 ms |

On darwin bbolt syncs with `F_FULLFSYNC`, which requests a drive-cache flush. The concurrent probe shows higher commit latency,
consistent with contention; it does not directly trace device-level serialization. Linux `fdatasync` in the
container is ~27× cheaper here. (That container's disk is itself virtualised; the point is the ratio on
the same hardware, not an absolute Linux figure.)

## 3. Where it lands in a round

A node receiving a proposal (`ConsensusManager.onProposalMsg`) makes, in order, before it sends its vote:

1. `processQC` → `BlockStore.ProcessQc` → on a commit QC, `BlockTree.Commit` persists the new root block
   (`WriteBlock(…, true)`), a synced bbolt transaction;
2. `processTC` → `WriteTC` when the proposal carries a timeout certificate;
3. `BlockStore.Add` → `WriteBlock` of the proposed block;
4. `SafetyModule.MakeVote` → `SetHighestQcRound`;
5. `BlockStore.StoreLastVote` → `WriteVote`.

That is three or four synced commits per node per round on the path to the vote; at ~115 ms each with
four nodes flushing at once, 350–450 ms before the vote leaves. The debug trace of run 5 shows exactly
that shape: the leader broadcasts round *r*'s proposal at *t*; the nodes log "round has lasted minimum
required duration" at *t* + 250–450 ms, staggered node by node; the next proposal follows ~100 ms after
the last of them. Rounds take 500–600 ms against a `BlockRate` of 90 ms in these fixtures. Setup shows the
same cost: registering a shard configuration takes ~300 ms per node.

The warnings in the failing runs are consequences, not causes: duplicate timeout votes and "stale vote"
after rounds advance by timeout, recovery triggered by a missing block, and "database not open" from
stores closed by `t.Cleanup` while managers wind down.

## 4. The intervention

Both stores the fixture opens (`storage.NewBoltStorage` and `partitions.NewOrchestration`) were patched
temporarily to set `NoSync` — one line each, uncommitted, reverted afterwards, tree verified clean — and
both tests run twice on macOS with go1.27.1:

| sample | `Test_rootNetworkRunning` | `Test_recoverState` |
|---|---|---|
| 1 | pass, 1.11 s | **9/9 pass**, 2.81–6.57 s |
| 2 | pass, 1.09 s | **9/9 pass**, 2.67–6.37 s |

Removing only the disk flush — nothing in consensus, the budgets, the assertions or the network — turns
every failure into a pass on the same host, and brings `Test_rootNetworkRunning` from 6.5 s to the
Linux container's ~1.1–1.4 s. With the correlation in §§2–3, that makes the flush cost the cause.

## 5. What this does not claim

- **Not a production storage benchmark.** The ~4 ms figure is from one Linux container on this
  machine, not production disks. Production uses a slower configured round cadence, but that alone
  establishes no durable-throughput or tail-latency guarantee. Any write batching or production
  latency work must preserve safety-critical persistence ordering and get its own acceptance scope.
- **Not every macOS configuration.** Measured on one Intel Mac with its internal SSD. The reviewer's
  earlier test runs were on the same darwin/amd64 host, not independent ARM hardware; other disks and
  virtualization/storage stacks were not measured.
- **Not the other consensus tests.** `consensus_manager_test.go`'s own fixture also opens real bbolt
  stores; the tests using it pass here, so it is left as it is.
- **Not #100, #16 or #14.** No shared cause with discovery flakiness, mixed cadence or F6 storage was
  found or looked for beyond this.

## 6. Repair and disposition

The repair is a separate change, as #127 asks: an opt-in `WithNoSync()` on `storage.NewBoltStorage` and
`partitions.NewOrchestration`, passed only by the shared fixture `createStorage`, with negative tests
pinning that both constructors still sync by default. It changes no timeout, assertion, retry or quorum.

For #9: the "existing Go suite passes at the selected baseline" line fails on macOS hosts because of
this fixture assumption, and passes on Linux, where CI runs. With the repair merged it should pass on
both; until then the failure has a named cause rather than an anonymous exception.

## Retained evidence

`docs/design/f1e/f1e-runs.tar.gz` (sha256 `bb76bcb24db0481dffaf9d1fc9891f6a948bbe8907a50527b5e79174c7e5714a`,
17 payload files, plus macOS archive metadata entries) holds the manifest and the full JSON output of runs 1–6 and of the four intervention samples.
The probe's outputs are `docs/design/f1e/probe-macos.txt` and `probe-linux-container.txt`. No key
material: the fixtures generate their keys in memory and the logs carry node IDs only (checked for
`privateKey`, `sigKey` and PEM markers).
