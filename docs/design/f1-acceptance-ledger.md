# F1 (#9) acceptance ledger — #88, #89, #90, #100

What this is: one reconciliation of F1's acceptance list and its four children against the work
actually merged for them, at the exact revision named below. Every line is marked **met**, **met in
part** or **not met**, points at a test function, a script, a workflow or a recorded run, and — where
it is not met — says what is missing and who owns it.

What it is not: a closure of #9 or of any child. A ledger written by the party that did the work is a
proposal for somebody else to check. Nothing here closes anything, and §7 says so again at the end.

Two habits are carried over from the F6b ledger deliberately. **Evidence is named, not summarised**,
so a reader can disagree with the mapping rather than with an adjective. And **a measurement is
attributed to what it measured**: a fixture proves a property of the code, a real-client run proves
that a real client behaved a particular way once, and neither is the other.

---

## 0. The revision this was reconciled against, and how

Baseline: `fbc4d08b1a2bf7b3e8b58b5632d02053d6789535` (`integration/enshrined-evm`, the #124 merge).

Every test function, script, workflow and document cited below was located at that revision before
being cited; no citation is carried over from a PR description on trust. Three things were measured
fresh for this ledger rather than quoted, and they are marked *(measured for this ledger)* where they
appear:

| measured here | result |
|---|---|
| `./scripts/reth-chaos-selftest.sh` | **38 ok, 0 bad** (PR #108 recorded 31; the suite has grown since) |
| `go test ./rootchain/consensus -run 'Test_rootNetworkRunning\|Test_recoverState' -count=1`, 3× | **FAIL 3/3** — see §1, acceptance line 1 |
| sampled hosted CI runs listed below | **zero steps**, 2–5 s, `failure` — those jobs did not execute |
| `go build ./...`, `go vet ./...`, `go test ./cli/... ./engineapi/... ./shardnode/... ./network/... -count=1` | **all pass** in that session — identifies a failing package, not a causal isolation |

The hosted-CI observation matters to three separate lines below, so it is stated once here. Runs
34270713889, 34283525433 and 34362021522 (`real-reth-smoke`) and 34356066113 (`ci`) all report
`steps=0` and complete within seconds. That signature is consistent with the account
billing/spending condition recorded on #9 on 2026-09-08, but this ledger did not independently
diagnose it. The cited samples establish failures before any step executed; they are not an
exhaustive audit of every workflow run since that date. No CI line below establishes continuous
coverage. The last successful executed run identified in this reconciliation is `real-reth-smoke` **34161538859** (2026-09-07, head `a2e801db`, success).

---

## 1. F1 #9 itself

### Work breakdown

| item | status | evidence |
|---|---|---|
| Compare `main`/`l1` with `engine-api-adapter`, retained/missing/conflicting at exact commits | **met** | `docs/design/f1-baseline.md` §3.1 retained, §3.2 the two `l1` commits the branch never received, §3.3 fake versus real execution; pins and config hashes in §2 |
| Update stale ADR references; reproducible Go, FFI and real-reth baseline commands | **met** | §4 deviation inventory against ADR 0004; §5.1 Go lane, §5.2 FFI lane, §5.3 stock client (`scripts/reth-by-hand.sh`, `scripts/reth-baseline.sh`), §5.5 paired devnet (`scripts/reth-paired-devnet.sh`) |
| Add or repair PR-triggered CI, retaining existing checks and distinguishing fake from real | **met in part** | `.github/workflows/ci.yml` (fake executor throughout) and `.github/workflows/reth-smoke.yml` (pinned real client) are separately named, which is the distinction the item asks for. **Not currently running** — see §0 |

Performing the `l1` merge itself is not this item; §3.2 records it as outstanding under F8 (#16).

### Acceptance

**Line 1 — "the existing Go suite and paired devnet pass at the selected baseline; known protocol
gaps have ticket owners; a version/spec mismatch is detected before voting."**

**Met in part, and one clause is currently failing.**

| clause | status |
|---|---|
| paired devnet passes | **met** — `scripts/reth-paired-devnet.sh` at the pin, four validators, four clients, funded transaction executed and certified, all four agreeing (§5.5). Last exercised as its own lane during the #99 review; the F6b lanes also pair validators with clients but are not this four-validator script |
| known protocol gaps have ticket owners | **met** — §5.4 known-limitations register, one named owner per row (#10, #11, #13, #14, #16) |
| version/spec mismatch detected before voting | **met in part** — the node refuses checked capability/chain/genesis/pairing mismatches (§5.8); the complete supported profile and missing-local-configuration test still require #89 (§3) |
| **the existing Go suite passes** | **not met at this baseline** |

*(measured for this ledger)* `go test ./rootchain/consensus -run 'Test_rootNetworkRunning|Test_recoverState' -count=1`
fails 3/3 on this host at `fbc4d08b`. `Test_rootNetworkRunning` fails after ~11 s; `Test_recoverState`
fails in all eight subtests — `recovery_triggered_by_vote`, `recovery_triggered_by_timeout`,
`recovery_triggered_by_missing_proposal`, `recovery_triggered_by_missing_proposal_-_delay_proposal`,
`recover_from_different_timeout_rounds`, `late_joiner_catches_up`,
`less_than_quorum_nodes_are_live_for_a_period`, `peer_drops_out_of_network` — with unsatisfied progress/recovery assertions. The exact messages and first failed conditions
differ across subtests; preserve the JSON output rather than treating them as one diagnosis.

The #96 review recorded this test family failing on baseline `0d9c6ee6` with and without
that PR. This establishes an older occurrence, not that every later failure has the same cause
or that all F1/F6b changes are exonerated. Three failing runs are repeatable local evidence, not
proof of deterministic behavior on every schedule. The author observations are one host,
darwin/x86_64 (Intel Core i7-8850H; an earlier revision of this ledger said darwin/arm64, which was wrong); hosted corroboration is presently unavailable (§0).

**The failed-suite investigation is now #127 under #9.** Reviewer reproduction at docs-only
`6735fdd1` failed both top-level tests and all eight recovery cases once (21.135 s); JSON output
SHA-256 `f032ad1a45ae3e6f5413814c5fb879de516edfc80ee3a484fd639c800fc67c58`.
Passing other packages does not exclude shared causes. Track #127 separately until a trace
establishes any relationship to #100, #16 or #14. #16's scope includes mixed-cadence/partition
integration and consistency-proof retention, not only the recorded leader-kill stall. A named
issue is not a waiver of F1's passing-suite acceptance clause.

**Line 2 — "Merging alone is not evidence of production readiness."** Observed throughout: §7 of
`f1-baseline.md`, the "Not claimed" sections of #96, #97, #99 and #110, and §7 below.

---

## 2. F1a #88 — real-reth workload, fault and retained-data recovery evidence

Merged: **#91** (harness, `e7d36a78`), **#108** (per-scenario clusters and the first full matrix,
`d14f3bf7`), **#110** (executor-only and pair restart, `1fe7f899`).

### Staged delivery

| stage | status | evidence |
|---|---|---|
| 1 — bounded funded-transaction sequence, at least two distinct leaders producing executed certified blocks; count EVM blocks and receipts, not quiet rounds | **met** | `multi-leader` scenario in `scripts/reth-chaos.sh`; receipts correlated to authenticated anchor logs and the technical-record leader, with empty and prefix-only block-hash matches rejected (#108); recorded in `f1-baseline.md` §5.7.1 |
| 2 — independent scenarios from clean fixtures: follower restart, leader kill, reth-only restart, pair restart; one failure at a time | **met** | each scenario builds its own devnet; a scenario whose clean cluster did not execute and converge is reported `NOT RUN` rather than silently attributed to the fault (`freshCluster` gates in `scripts/reth-chaos.sh`) |
| 3 — before/after cursors, applied head, persisted UC, root round/leader, authenticated context; convergence **and** state/receipt agreement; safe abstention recorded; a missing payload never becomes VALID | **met** | per-scenario sealed archives under `evidence-runs/<runID>/`; `convergenceGate`; §5.7.2's refusal classification, where the pair-restart node abstains on `no-anchor` and then on an authenticated target whose payload is unavailable |
| 4 — preserve evidence, minimal deterministic reproduction for any failure, no silent skipping or budget raising | **met in part** | supervisor-owned collection and teardown, exercised on purpose in three abort modes (`nounset`, `kill`, `hang`+SIGTERM) in #91; a child that dies without a result is an *incomplete run*, never zero failures. Collection is established; this does not supply a deterministic reproduction for every unresolved runtime failure (#16) |

### Acceptance

| line | status | note |
|---|---|---|
| exact revisions, hashes, seed, commands recorded; wrong pin fails; fake fallback impossible | **met** | unconditional manifest written before scenario selection; `-s` with an unknown name is refused before anything starts or stops |
| positive execution before **and** after each fault; multiple leaders; unique transactions; duplicate delivery never duplicates effects; receipts/nonces/commitments agree | **met in part** | established for baseline, multi-leader, follower restart, reth-only restart and pair restart. **Leader kill is the exception** — see below |
| progress with one shard validator absent; returning node verified separately; shard leader distinguished from root leader | **met** | leader-kill scenario: the shard rotates past the killed leader and a transaction executes while it is absent |
| bounded condition-driven waits; negative subprocess tests time out and clean up; traps stop every created process | **met** | the #91 oracle repairs — an unobservable head is no longer recovery, and `assertConvergence` now returns failure and sets the sticky state |
| complete compared certificates at rejection time, configuration, root/shard/reth logs, persistent state; JWT/keys redacted | **met** | sealing happens before each cluster reset and the reset is aborted if sealing fails |
| artifact collection exercised deliberately, archive verified, preserved | **met** | *(measured for this ledger)* `./scripts/reth-chaos-selftest.sh` → **38 ok, 0 bad**, including failed startup, cancellation, archive-overwrite refusal, selection validation and real-log correlation |
| same-host retained-data recovery distinguished from disk-loss/replacement-host recovery | **met** | #110 §5.7.2 is explicit that the reth-only case retained its datadir; replacement-host recovery stays #14 |

**The two gaps under #88, stated plainly.**

1. **Leader kill has no passing measurement at a current head.** §5.7.1 records it as
   `continuity-gap`, open; the later row showing it recovering is from the #109-era run, and #110
   measured only `reth-only-restart` and `pair-restart`. So the "positive execution after each
   fault" line is unestablished for this one scenario at `fbc4d08b`.
2. **No full matrix has been run at the current merged head.** The cited full-matrix work is #108, supplemented by #110 at `d14f3bf7`.
   #111–#124 add narrower recovery measurements, not a fresh run of the entire fault matrix. Each recorded outcome is also a single run, which #110
   itself says is not a claim that the failure cannot recur.

Both are measurement, not repair: the cost is one clean `./scripts/reth-chaos.sh -t 2` run at
`fbc4d08b` with the pin and T2 ≥ 5 s. This ledger does not schedule it, because #9's next two units
are #89 and #90 by the 2026-09-11 sequencing; it records it as what #88 still needs.

---

## 3. F1b #89 — startup capability, genesis and execution-endpoint binding

Merged: **#96** (items 1 and 4, `5eb8bbe5`), **#99** (items 2 and 3, `80974c48`). Proposed: **#129**
(the three residuals this section named at `936e1237`). The verdicts below are what #129 would make
them; until it is reviewed and merged they are a proposal like the rest of this ledger.

### Delivery

| item | status | evidence |
|---|---|---|
| 1 — the real binary against a controlled JSON-RPC fixture, per missing capability, bounded nonzero exit, specific diagnostic, before any submission; exchange failure, malformed response, missing chain id | **met** (with #129) | `TestShardNodeRun_RefusesIncompatibleExecutionClient` covers each missing V3 method, a client offering nothing, HTTP 500, a malformed response, an erroring and a `null` `eth_chainId`, and a chain-id mismatch, each asserting nothing was submitted; `TestShardNodeRun_AcceptsACompatibleFixture` is the positive control. The missing *local* `chain_id` is `TestShardNodeRun_RefusesAShardConfWithNoChainID` (#129), which first asserts the generated shard conf really carries no `chain_id` |
| 2 — operator-configured expected genesis / chain-profile binding, validated before voting; same chain id with different genesis as a real-reth negative; define which fork/config parameters are additionally pinned | **met** (with #129) | genesis: `TestShardNodeRun_GenesisBinding`, `TestCheckGenesisHash_ReadsBothConnections`, `TestDecodeBlockHeaderRejectsMissingIdentity`, real-reth 3d. **Fork/config profile** (#129): `engineapi/profile.go` pins eth_config's `current` (activation at genesis, Cancun's system contract, blob schedule and precompiles, the configured chain id) and requires `next`/`last` null; `TestCheckProfile_*` enforce each field one at a time from a recorded real response; real-reth 3f refuses a client whose chain id **and genesis** match but which schedules Prague later. `f1-baseline.md` §5.8 tabulates what is pinned and why `forkId` is not |
| 3 — independently configured Engine and plain RPC: correct plain paired with wrong Engine; how the deployment binds the pair using standard interfaces | **met** | `TestShardNodeRun_EndpointPairing`; `TestCheckChainID_ReadsBothConnections`; `TestCheckEndpointsPaired`. The binding uses `eth_chainId` and `eth_getBlockByNumber` on the authenticated Engine port — no new Engine method, no reth divergence |
| 4 — remove `doctor`'s duplicate `eth_chainId` and preserve the shared `CheckChainID` error | **met** | `doctor` calls the check once and reports the check's own error; its new `execution profile` line follows the same rule |

### Acceptance

| line | status |
|---|---|
| binary refuses unsupported/malformed exchange and missing configured identity; matching endpoints still execute a funded transaction | **met** (with #129) — the missing local `chain_id` now has its own CLI test; the funded-transaction positive is the paired devnet |
| same chain id / different genesis refused before voting, against an independently configured expected value | **met** — `--expected-genesis-hash`, supplied by the operator |
| Engine/plain-RPC pairing coverage and trust assumptions explicit; no claims stronger than the checked relation | **met** (with #129) — `docs/engine-api-adapter.md` §4.1 states, for operators, that passing every check does not establish same-process wiring, and that the profile is read over `--eth-url` and binds the Engine connection only through that same assumption |
| error/timeout/JSON-RPC failure paths fail closed with accurate diagnostics; subprocesses bounded and cleaned up | **met** — including a client without `eth_config`, which is refused rather than assumed compliant |
| CLI tests, real-reth fixture commands, exact manifests and compatibility/migration guidance attached | **met** (with #129) — compatibility and migration are §4.1's last paragraph: the profile check is new and can refuse a node that previously started |

**What #89 does not cover, and should not be read to:** interoperability with a second real client
(the controlled fixture is what #89 asks for); F3's future custom profile, which will revise
`engineapi/profile.go` as a reviewed compatibility change; and authenticating the expected
`shardConfHash` on live and restored UCs, which remains **#10**.

---

## 4. F1c #90 — pinned real-reth smoke and fault evidence in CI

Merged: **#97** (stages 1, 2 and 4, `dc233fff`). Proposed: **#131** (local packaging, the fault lane,
and exercised refusal and collection paths). Verdicts marked "(with #131)" are what it would make
them. **Hosted execution remains pending**: no line below that needs a hosted run is marked met on the
strength of local evidence, however close the local run is to the workflow.

| stage | status | evidence |
|---|---|---|
| 1 — paired lane and stock control in a separately named CI job; pinned build or provenance-recorded artifact; cache key includes commit/toolchain/target/flags; revision validated on cache hits; no unpinned images, no fake fallback | **met** | `real-reth-smoke`; since #131 the cache holds the archive and re-checks its digest on every hit as well as the binary's revision, keyed from `scripts/lib/reth-pin.sh`; `f1-baseline.md` §6.4 |
| 2 — trigger on relevant PRs plus manual dispatch; keep fake checks and protection off; record budget and timings | **met in part** | triggers unchanged; budget recorded. The cache-hit path is now **tested** — by `scripts/reth-smoke-selftest.sh` and on the real Linux artifact in a container (§6.4) — but a **hosted** cache hit is still unobserved |
| 3 — add real-reth fault scenarios on a separate bounded lane | **met in part** (with #131) | `real-reth-fault`, dispatch-only, bounded default scenarios, 120-minute budget; each archive validated and selected for upload on its own — searched for every cluster's secrets, recorded before use, not just the last cluster's — a secret-bearing one quarantined rather than uploaded; its exact client, scenario and selection commands run locally (§6.4). Not yet dispatched on a hosted runner |
| 4 — exercise a deliberate controlled failure to prove collection and upload | **met in part** (with #131) | exercised locally with real processes: `--inject-failure` exits nonzero with a validated archive holding the node logs; cancellation mid-devnet likewise. Since the #131 review a failed copy fails the lane, and upload selection is exercised by the self-test, which runs each workflow's own selection step on a leaked-secret archive (quarantined) and an ordinary failed run's archive (published). The hosted **upload and download** of a failure artifact remains pending |

### Acceptance

| line | status |
|---|---|
| a PR run proves a funded transaction executed in real reth and certified by BFT; hashes/receipts agree across four instances | **met, once, hosted** — run **34161538859** (2026-09-07). The same lane now runs locally through the same script (§6.4); that is local evidence, not a hosted run |
| wrong pin, bad/missing binary and RPC failures fail visibly, never silently skip | **met** (with #131) — the packaging refusals are exercised, not read: missing, non-executable, wrong-commit, revision-less, unrunnable and hanging binaries; wrong download digest; tampered cache; archive without a binary; failed download; unsupported platform (self-test), plus the tampered real archive in a container and the real `darwin-x86_64` refusal. RPC failures are the paired devnet's own §3 negatives |
| cache-hit and fresh-build paths documented and tested; failure artifact demonstrably downloadable and useful | **met in part** (with #131) — both paths documented and tested locally, on the real artifact; a failure artifact is produced and validated locally. **Hosted**: cache hit via `actions/cache`, and downloading a failure artifact from a run, remain pending |
| smoke/fault/fake results named distinctly; analyzer findings retained with individual dispositions | **met in part** — three distinctly named workflows (`ci`, `real-reth-smoke`, `real-reth-fault`); the `analyze` findings still have no per-finding disposition, which is outside #90 |
| link the exact workflow run, BFT/reth commit and artifact provenance in #9 | **met in part** — the smoke run of 2026-09-07 is linked; the deliberate-failure and fault runs have nothing hosted to link yet |

**What #90 still needs**: hosted execution — a PR-triggered smoke run on the packaged workflow, a
hosted cache hit, a dispatched deliberate failure whose artifact is downloaded and inspected, and a
dispatched fault run. None needs further code; each needs jobs that execute.

---

## 5. F1d #100 — libp2p bootstrap/provider discovery test stability

Merged: **#101** (leak repair and diagnostics, `a424be58`), **#104** (measurement record, `3aedcd55`).

| item | status | evidence |
|---|---|---|
| 1 — capture connection, negotiation, routing-table membership, discovery events; establish which prerequisite is missing | **met in part** | `requireRoutingTable` in `network/peer_test.go` keeps the same conditions and budgets and, on failure, dumps routing-table membership, per-peer `Connectedness`, missing expected peers and peers connected but absent from the table. It has never fired on a real failure |
| 2 — scoped context and cleanup for every peer/DHT/worker; inspect `TestBootstrapNodes`'s unclosed `bootstrapNode` | **met** | the leak is fixed for every peer in `peer_test.go`, with the complete causal chain recorded in `docs/design/f1d-discovery-test-lifecycle.md`: the leaked DHT's `PeerRemoved` callback logging through a completed `testing.T` panicked the whole package |
| 3 — reproduce alone, repeated, shuffled, under representative concurrency; record counts | **met** | pristine baseline `-count=10` panics at 121.8 s; with leaks fixed, `-count=10` passes in 199.3 s and `-shuffle=on -count=3` passes; then 36 iterations at default parallelism and 20 at `GOMAXPROCS=2`, 0 failures |
| 4 — evaluate a test-scoped DHT bootstrap/refresh lifecycle only after identifying the readiness condition | **not reached** — the readiness condition was never identified, because the timeouts were never reproduced, so the evaluation this item gates was correctly not performed. No ambient production refresh loop was added, which is what the item protects against |
| 5 — keep assertions about the intended behaviour; no blanket retry, no raised timeouts | **met** | no budget was raised anywhere in #101 or #104 |

### Acceptance

| line | status |
|---|---|
| baseline, reproducer, trace and causal explanation **or explicitly unresolved boundary** recorded | **met** — the panic is explained end to end; the originally reported timeouts are recorded as unresolved |
| lifetime leak fixed with cancellation/close coverage; negative diagnostics show routing/connection/query state | **met** |
| focused, repeated and full-package runs pass with stated counts, including relevant concurrency | **met in part** — 56 post-fix iterations, 0 failures, and the review's own `GOMAXPROCS=2 -count=3`. `GOMAXPROCS` limits Go parallelism and does not emulate the CI OS, CPU quota or networking, which #104 says itself |
| small independently reviewed PR; production lifecycle changes separately explained | **met** — the one production question found (`newDHT`'s callback logging through a caller-supplied logger with no lifetime relation to the DHT) is written up and deliberately **not** changed |
| closing record links before/after runs and preserves the failure evidence | **met** |

**The residual is unresolved, but local investigation is still eligible.** The reported timeouts
(`TestBootstrapNodes` at 4.13 s, `TestProvidesAndDiscoverNodes` at 32.23 s, run 34158584395) have no
established cause or rate. A trace reproducing the missing prerequisite locally or on a
representative runner can advance the diagnosis; the original hosted hardware is not a prerequisite.
Hosted validation remains outstanding. The diagnostics are armed for the next failure. #100 stays
open, and it is a named disposition for one boundary, not a blanket CI waiver — the #96-era baseline
consensus failures in §1 are not thereby explained.

---

## 6. What remains, consolidated

| # | gap | kind | next step |
|---|---|---|---|
| **#9** | `Test_rootNetworkRunning` and all eight `Test_recoverState` subtests fail 3/3 at `fbc4d08b` | runtime or test defect | #127: trace the first missing progress prerequisite; not a baseline waiver |
| #9 | the `l1` merge (§3.2) | integration | F8 #16, unchanged |
| #9 | advisory `analyze` findings (G115, G404, G301, G306) have no per-finding disposition | hygiene | one disposition each; no blanket disablement |
| #88 | leader kill has no passing measurement at a current head | measurement | one clean matrix run at the merged head, pin, T2 ≥ 5 s |
| #88 | no full matrix at `fbc4d08b`; every recorded outcome is a single run | measurement | same run; repetition counts stated |
| #89 | missing `chain_id` partition param has no CLI test | code | proposed in #129 |
| #89 | which fork/config parameters are pinned beyond the genesis hash is undefined | code + design record | proposed in #129: eth_config profile check |
| #89 | operator configuration and compatibility guidance unwritten | operator docs | proposed in #129: `engine-api-adapter.md` §4.1 |
| #89 | differing capability-set negative | covered by controlled fixture | no second-client prerequisite; alternate-client interoperability is separate |
| **#90** | hosted smoke on the packaged workflow, hosted cache hit, hosted failure-artifact download | hosted run | #131 packages and exercises these locally; hosted lines pending until jobs execute |
| #90 | no fault lane | CI | #131 adds `real-reth-fault` (dispatch-only); a hosted dispatch is pending |
| #100 | timeout cause and rate | unresolved | local or representative-runner tracing remains eligible; hosted validation pending |
| — | expected `shardConfHash` on live and restored UCs | separate ticket | #10 |
| — | write ordering / fsync durability | separate ticket | #14 |
| — | unexplained leader-kill stall, "Too deep reorg" | separate ticket | #16 |
| — | signing re-enablement after recovery | separate ticket | #105 |

Bold rows are the ones the 2026-09-11 sequencing on #9 puts next: #89's remaining startup binding,
then #90's pinned CI and local packaging. The `#9` consensus-suite row is bold because it is an
acceptance line of the parent that currently fails, which the sequencing did not anticipate.

---

## 7. This ledger does not close anything

#9 stays open, and so do #88, #89, #90 and #100. What is written above is a mapping from acceptance
text to merged evidence, offered for checking; several lines are marked met in part precisely so
that the reader can disagree with the split rather than with a summary. No line here should be read
as a production-readiness claim, and #92's closure does not make any of these automatic — as the
2026-09-11 handoff says in as many words.
