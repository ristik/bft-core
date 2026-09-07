# F1: prototype reconciliation and regression baseline

Issue: [#9](https://github.com/ristik/bft-core/issues/9). Prerequisites D1 (#3) and D2 (#4) are
accepted; D2 merged as `7eaf842a703f48dfa8cead52d7ac8662dc32c652`.

This document is the F1 deliverable: what the baseline *is* (§1–§2), what the prototype branch
actually retained, dropped and conflicts with (§3), what deviates from the accepted design and who
owns each gap (§4), and how to reproduce all of it (§5–§6). It deliberately does not enable
anything: F1 pins a starting point and makes it measurable.

**Merging this is not evidence of production readiness.** §4 lists deviations that are open, not
closed, and §7 lists what F1 does not cover.

## 1. What "the baseline" means here

The ticket asks to reconcile `engine-api-adapter` with "the chosen main/l1 baseline without assuming
the branch is complete". There are four relevant heads, and they are not a line:

```
main ceceacd1 ──► l1 322c351b ──► engine-api-adapter 627318b5 ──► integration/enshrined-evm 7eaf842a
                       │                                                  (D1–D6 design work)
                       └──► l1 d637cbba  (two commits the adapter branch never saw — §3.2)
```

`integration/enshrined-evm` is the chosen baseline. It descends from `engine-api-adapter`, which
descends from `l1` at `322c351b` — **not** from current `l1`. The two commits `l1` gained afterwards
are a real, unmerged divergence, inventoried in §3.2.

## 2. Pinned revisions and configuration hashes

| Component | Revision | Date |
| --- | --- | --- |
| Integration baseline (`integration/enshrined-evm`) | `7eaf842a703f48dfa8cead52d7ac8662dc32c652` | 2026-09-07 |
| Prototype (`engine-api-adapter`) | `627318b5e6e0ca79e601d58b35fc9c46498f2731` | 2026-09-05 |
| Aggregation layer (`l1`) | `d637cbba441beb2b72857009cd581a0fb3eae3ab` | 2026-08-20 |
| Upstream (`main`) | `ceceacd11b7a735de74ce17884a3a45e0db1748d` | 2026-04-22 |
| Execution client (`ristik/ureth`, branch `unicity/main`) | `189c0df32617afc488e0f091dbface1bd72cceb4` | 2026-08-12 |
| `bft-go-base` | `v1.1.1-0.20260421100318-01ab63a83bf5` | — |
| Go | 1.24 | — |

The approved execution-client fork is **[`ristik/ureth`](https://github.com/ristik/ureth)**, branch
`unicity/main`, created for F3 (#11) at upstream `paradigmxyz/reth` tag `v2.5.0`. It is a private
mirror rather than a GitHub fork — GitHub forks inherit the parent's visibility, so a fork of public
reth cannot itself be private — with `upstream` configured as a remote, so fetching and rebasing onto
a later tag work normally. Its `UNICITY.md` records the fork point, the divergence budget and the
deviations below.

At this pin `unicity/main` is **byte-identical to upstream `v2.5.0`**: nothing has diverged yet, and
the first divergence will be F3's privileged system call. So every real-reth result in this document
is currently a result about stock upstream reth, which is exactly what makes §4's deviation list
meaningful — it is the delta the fork has to close, measured before any of our own code could have
influenced it.

The contract package's approved home is
**[`ristik/unicity-pos-contracts`](https://github.com/ristik/unicity-pos-contracts)** (Foundry,
solc 0.8.28, `evm_version = "cancun"` matching the shard's chain spec), recorded for F4 (#12) per
PROCESS.md's requirement that repository, toolchain and ownership be settled before implementation.
Nothing is implemented there yet.

Configuration produced by `./setup-evm-nodes.sh -r 3 -v 4` at this baseline (partition 8,
`proof_type=exec`, chainId 31337):

| Artifact | SHA-256 |
| --- | --- |
| `test-nodes/evm-genesis.json` | `efe500c5c8c036529df15b451fd50815f8bc34d1b275709eed98888ea8523ab6` |
| `test-nodes/shard-conf-8_0.json` | `8dda3ec8fb4e230043e726f819c59559f4c5fb576d3c7767258b241689d06457` |

Reth's genesis block hash for that chain spec, observed live:
`0x0598047b8adde700d2e815fe0c7436002f7c50ef32447aa4f4bf4c09e1a97789`. Genesis `baseFeePerGas` is
`0x3b9aca00` (1 gwei) and `gasLimit` is `0x1c9c380` (30,000,000) — both matter in §4.

## 3. Reconciliation: retained, missing, conflicting

### 3.1 Retained from the prototype

`engine-api-adapter` is not a throwaway. What it carries forward, and which F ticket consumes it:

| Retained | Where | Consumed by |
| --- | --- | --- |
| Executor boundary and round state machine | `shardnode/`, ADR 0001 | F2 (#10) extends `RoundParams` |
| Engine API V3 client, JWT, hex/CBOR codecs | `engineapi/` | F3 (#11) extends with the seal call |
| UC classification (valid / repeat / sync) | `shardnode/uc.go` | F4 (#12), F6 (#14) |
| Certified-head persistence and crash recovery | `shardnode/store.go`, `round_recovery_test.go` | F6 (#14) replaces the JSON store |
| Determinism harness | `shardnode/determinism_test.go` | F8 (#16) |
| Chaos + compose topologies | `scripts/chaos-evm.sh`, `docker-compose.evm.yml` | F8 (#16), F9 (#17) |
| Genesis generation | `cli/ubft/cmd/engine_api_genesis.go` | F4 (#12) authenticated genesis |

These tests are retained as required by the ticket, not rewritten: the full Go suite still runs, and
`shardnode/executortest` conformance plus the determinism harness still gate `make test`.

### 3.2 Missing: two `l1` commits the prototype branch never received

`engine-api-adapter` branched from `l1` at `322c351b`. `l1` then gained:

- `64631d23` — derive SMT leaf values from the round reference time
- `d637cbba` — expose the round reference time as a public input of the ZK consistency proof

They touch 22 files, all under `rootchain/consensus/zkverifier/` plus `rootchain/node.go`, and
introduce `rsmt/leafvalue.go` with its fixtures. **The integration branch does not have them.**

Consequence: this baseline's consistency-proof verification is the pre-`d637cbba` shape. F8 (#16) is
required to "retain l1 consistency-proof fixtures" and therefore cannot be closed against this
baseline as-is — the merge has to happen first, and it is a rebase of aggregation-layer proof code
onto a branch that has since grown the whole `evmroot/` design tree. Recorded here as an open item;
owner F8 (#16).

This is the one place where "do not assume the branch is complete" bites: the prototype is not
behind `main` (it contains everything `main` has), but it *is* behind `l1`.

### 3.3 Conflicting: fake versus real execution

The prototype's entire CI story runs `--executor fake`. `docker-compose.evm.yml` says so in its own
header comment, and `scripts/reth-by-hand.sh` carried a standing disclaimer that it had "not been
executed against a live reth".

**That disclaimer is discharged, but it buys less than it looks like.** `scripts/reth-by-hand.sh`
was run against reth `189c0df3` and passed unmodified — genesis → `forkchoiceUpdatedV3` →
`getPayloadV3` → `newPayloadV3` → canonical block 1, all `VALID`. What that establishes is that
**the client** behaves as expected against hand-written requests. It says nothing about the Go
adapter: the script constructs every request itself with `curl` and `openssl`, and executes no
Unicity code at all. The same is true of `scripts/reth-baseline.sh`. Neither can tell you whether
`engineapi/`'s JWT minting, encoding, round-params derivation or Build/Seal/Verify/Commit path
works, because neither runs any of it.

The lane that does is **`scripts/reth-paired-devnet.sh`** (§5.5): one real reth per validator, with
`ubft shard-node run --executor engine-api` driving them, certifying against a real root chain. It
is what F1's integration claims rest on. Two distinct fake-versus-real conflicts show up there and
nowhere else:

- **Header economics** (§4), which the fake models not at all.
- **An idle shard builds no EVM block whatsoever.** Every round after the first is `quiet=true` —
  unchanged state root, nil block hash — so the adapter never asks reth to build, and reth's
  canonical head stays at genesis no matter how many rounds certify. This is correct behaviour at
  this baseline, and it is easy to mistake for a broken integration. Producing blocks on idle
  rounds at the EVM cadence is F4 (#12). Proving the adapter *can* build therefore requires a real
  transaction, which requires a funded account, which the generated genesis does not have — see
  §5.5.

## 4. Deviation inventory against ADR 0004

ADR 0004 (D2) freezes the reth system-call and fee profile and constrains F1 to "bound integration
work" with its minimal-delta profile. Measured against stock reth `189c0df3`:

### 4.1 Engine API surface: zero custom methods today

`engineapi/` calls exactly `engine_exchangeCapabilities`, `engine_forkchoiceUpdatedV3`,
`engine_getPayloadV3`, `engine_newPayloadV3`, and the plain `eth_chainId` / `eth_getBlockByHash` /
`eth_getBlockByNumber`. No custom method, no extra field, no side channel. The current divergence
surface against upstream is **empty**, which is the strongest possible starting point for the owner's
minimal-divergence constraint.

ADR 0004's `engine_*WithSealV1` methods are *not* implemented here; they are F3 (#11). The client
does advertise V1–V6 of the standard methods (including `newPayloadV4/V5`, `getPayloadV4/V5/V6`,
`forkchoiceUpdatedV4`), so F3's explicit version negotiation has room to work without displacing
standard semantics.

### 4.2 D-1 — the genesis base fee is not preserved, and settles at a 7-wei artefact

For an empty block, EIP-1559's update is, in integer arithmetic,

```
next = parent - floor(parent / 8)
```

applied from the genesis base fee. Measured against reth `189c0df3` over 160 blocks, every observed
value matches that recurrence **exactly**:

| Block | 1 | 6 | 12 | 41 | 100 | 145 | 160 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `baseFeePerGas` (wei) | 875,000,000 | 448,795,319 | 201,417,240 | 4,191,124 | 1,362 | 7 | 7 |

**The sequence terminates at 7 wei and stays there**, because `floor(7/8) == 0`. It reaches 7 at
block 145 and is a fixed point from then on.

An earlier version of this document claimed it reaches 1 wei in 156 blocks, extrapolating with
repeated floating-point multiplication by 7/8. That is wrong: the floor makes the descent stop.
The earlier `reth-baseline.sh` encoded the same error as a float-ratio assertion, which then
**falsely reported `BASELINE CHANGED` on unmodified reth** at 160 blocks, once rounding began to
dominate. Both are corrected: the script now asserts the integer recurrence directly, which holds
for all 160 blocks in both controls.

What this does and does not establish for F5 (#13):

- The genesis `baseFeePerGas` is **not preserved** — 1 gwei becomes 7 wei, roughly eight orders of
  magnitude, within a few minutes of idle rounds. F5's acceptance case that "changing the initial
  genesis base fee alone is demonstrably insufficient" holds.
- The 7-wei fixed point is **not a fee floor** and must not be treated as one. It is an artefact of
  integer division: no operator can configure it, it is not derived from any policy, and it sits
  far below any plausible economic floor. A configurable protocol floor remains a distinct F5
  validity requirement.
- These are **stock empty blocks**, which are not the same object as D2's system-only blocks. A
  system-only block's `header.gasUsed` includes the mandated system work `g_sys`, while the
  ordinary-only fee feedback that drives this recurrence excludes it. The measurement above bounds
  the stock behaviour F5 starts from; it does not predict the update on a system-only block, which
  depends on decisions D2 records and F4 (#12) implements.

### 4.3 D-2 — the gas limit drifts under reth's *default* builder configuration, and a standard flag pins it

Under the default builder, `gasLimit` rises by about 1/1024 per block — 30,000,000 → 35,070,622
across 160 blocks — as the builder walks toward its own desired target, clamped per block to the
allowed adjustment range (`EthereumBuilderConfig::gas_limit_with_target` →
`calculate_block_gas_limit` at the pinned revision).

**This is a configuration default, not a client defect.** Control B of `scripts/reth-baseline.sh`
runs the same pinned binary with `--builder.gaslimit 30000000` and every block holds at exactly
30,000,000, with no client change of any kind. An earlier version of this document concluded the
growth was unbounded and used that to scope F5 work; that conclusion was wrong, and the correction
matters directly under the owner's minimal-divergence constraint — this is one less reason to touch
the execution client.

Two separable problems remain, and only the second may need a Unicity validity rule:

1. **Configuring our own builder.** Solved by a standard flag. It belongs in deployment
   configuration and in whatever `ubft engine-api genesis` emits alongside the chain spec, not in
   the fork. Owner: F5 (#13), as an operational requirement.
2. **Enforcing the chain's gas-limit and capacity policy on blocks imported from peers.** A
   flag on our own builder constrains only blocks *we* build. Nothing measured here says a
   follower rejects a peer's block that carries a different gas limit, and F5's requirement that
   "system work plus forced and ordinary capacity cannot exceed the configured total" is a
   statement about every block the shard certifies, including a malicious builder's. That is a
   validity rule, and it is the part that may justify divergence. Owner: F5 (#13), with the
   builder/follower/import/replay evidence F3 (#11) has to carry for any retained hook.

Both controls are asserted by `scripts/reth-baseline.sh` in their present form, so a change in
either flips an assertion and forces this document and F5 to be updated together.

### 4.4 Not enabled, by design

Nothing in F1 turns on a protocol path. The canonical root input is still unauthenticated at the
executor boundary (F2, #10), there is no privileged call (F3, #11), no SealRegistry (F4, #12), and
PoS, inbox and bridge features remain disabled behind their own gates. D2's "before F1 enables the
path" wording forbids enabling an unauthenticated path; F1 enables none.

## 5. Reproducible baseline commands and results

### 5.1 Go lane

```bash
make build          # cd ./cli/ubft && go build -o ../../build/ubft
go vet ./...
make test           # go test ./... -count=1 with coverage
```

Result at `7eaf842a` + this branch: `make build` and `go vet ./...` clean. `make test` — see §5.4 for
the two environment-sensitive packages.

### 5.2 FFI lane

```bash
make build-rust-ffi
go vet -tags zkverifier_ffi ./...
make test ZKVERIFIER_FFI=1
```

Disabled in CI (`if: false` on `build-with-ffi` and `test-with-ffi`) at the prototype and kept
disabled here — enabling it is coupled to the §3.2 `l1` merge, since the FFI crates are exactly what
those two commits change. Owner: F8 (#16).

### 5.3 Stock-client lane (no Go adapter involved)

Requires a `reth` binary at the pinned revision. A wrong revision **fails** the baseline gate;
`F1_ALLOW_UNPINNED_RETH=1` runs anyway and labels the output as not evidence.

```bash
./setup-evm-nodes.sh -r 3 -v 4          # generates test-nodes/evm-genesis.json

# one round, by hand, no Unicity code involved
reth node --chain test-nodes/evm-genesis.json --datadir <dir> \
  --authrpc.jwtsecret <jwt.hex> --authrpc.port 8551 \
  --http --http.port 8545 --disable-discovery --port 30399 &
./scripts/reth-by-hand.sh <jwt.hex>

# header economics: two controls (default builder, and --builder.gaslimit), 160 blocks each
./scripts/reth-baseline.sh 160
```

Recorded results against reth `189c0df3`:

- `reth-by-hand.sh`: passes unmodified. All four Engine API steps `VALID`; canonical block 1 at
  `0xeaad90ed02b1e654726166541e071f3107aa25a1b77f9fe0fbff43d32588b5a8`.
- `reth-baseline.sh 160`: passes, 10/10 assertions across both controls. The integer fee
  recurrence matches exactly for all 320 measured blocks; the gas limit drifts under the default
  builder and holds at 30,000,000 under `--builder.gaslimit`.
- Pin enforcement verified: with a deliberately wrong `pinnedRethCommit` the script exits 1 having
  started nothing, and exits 0 under `F1_ALLOW_UNPINNED_RETH=1` with both the header and footer
  labelling the run as not evidence.

Neither script executes any Unicity code. See §3.3 — they are evidence about the client only.

### 5.5 Paired real-reth devnet (the Go adapter integration lane)

This is the lane F1's integration claims rest on: one real reth per validator, driven by
`ubft shard-node run --executor engine-api`, certifying against a real 3-node root chain.

```bash
./scripts/reth-paired-devnet.sh 4 5     # 4 validators, wait for 5 certified rounds
```

It fails on a client revision mismatch by default, the same way the baseline does. Recorded results
against reth `189c0df3` — all checks pass:

| Check | Result |
| --- | --- |
| 4 reth instances on the generated chain spec, statically peered (§5 of `docs/engine-api-adapter.md`) | up |
| **Negative:** chainId mismatch refused before voting | `execution client reports chainId=31338, shard conf says 31337` |
| **Negative:** unreachable Engine API refused before voting | refused |
| Shard certifies with `--executor engine-api` against real reth | `partitionRound=14 rootRound=67` |
| Idle rounds are `quiet=true` and reth stays at block 0 | as expected — see §3.3 |
| A funded transaction is executed and certified | reth block 1, `status=0x1`, `gasUsed=0x5208` |
| All 4 reth instances converge on the same canonical head | `0x760b0bf9…` on all four |
| No validator logs divergence or equivocation | clean |

Two things about this lane are worth stating plainly:

- **The transaction is what makes it meaningful.** Without one the shard only certifies quiet
  rounds, which never call the adapter's build path at all; the run would pass while proving very
  little. The generated genesis has an empty `alloc`, so the script derives
  `test-nodes/evm-genesis-funded.json` from it and funds one well-known test account via
  `scripts/evmtx`. That is **test-only**; real genesis funding is T1 (#28). The chainId and fork
  schedule still come from the shard conf.
- **`scripts/evmtx` deliberately avoids go-ethereum.** It is only an indirect dependency here, and
  promoting it pulls in gnark-crypto, blst, c-kzg-4844 and go-verkle — a lot of new cryptographic
  surface for a consensus repository to carry for one test helper. The transaction is assembled
  from RLP, Keccak-256 and a recoverable secp256k1 signature using packages already in the module
  graph; `go.sum` is unchanged and no new module is added.

### 5.6 What this lane still does not cover

It exercises one transaction through one leader. It is not a load test, not a fault-injection
exercise against real reth (`scripts/chaos-evm.sh` remains fake-executor only), and it does not
exercise mixed cadence or multiple partitions — F8 (#16). The mismatch negatives cover chainId and
an unreachable Engine API; they do not cover a client that speaks a *different* Engine API version
set, which needs a second reth build to test against and belongs with F3 (#11)'s version
negotiation.

### 5.4 Known-limitations register

| Limitation | Evidence | Owner |
| --- | --- | --- |
| Genesis base fee is not preserved; no *configurable* floor exists (the 7-wei fixed point is an integer-division artefact, not a policy) (D-1) | §4.2, `reth-baseline.sh` | F5 (#13) |
| Our own builder's gas limit needs `--builder.gaslimit` in deployment config (D-2, part 1 — a standard flag, no client change) | §4.3, `reth-baseline.sh` control B | F5 (#13) |
| No evidence that a follower rejects a peer block carrying a different gas limit / over-capacity (D-2, part 2 — the part that may need a validity rule) | §4.3 | F5 (#13), F3 (#11) |
| Adapter integration is exercised by one transaction through one leader; no load, fault injection or mixed cadence against real reth | §5.6 | F8 (#16) |
| Mismatch negatives cover chainId and an unreachable endpoint, not a differing Engine API version set | §5.6 | F3 (#11) |
| Two `l1` commits unmerged; consistency-proof fixtures not retained | §3.2 | F8 (#16) |
| FFI CI lane disabled (`if: false`) | §5.2 | F8 (#16) |
| `rootchain/consensus` `Test_recoverState`, `Test_rootNetworkRunning`, `Test_ConsensusManager_messages` fail on a slow/loaded host: they assert round progress against wall-clock deadlines and reach only rounds 2–3 within them. Pass in CI (run 34102642015 attempt 2) and fail reproducibly on the F1 development host, in isolation as well as in the full suite. Not a protocol defect; a test-harness timing assumption. | §5.1 | F1 records; retest under F8 (#16)'s fixture work |
| `scripts/chaos-evm.sh`'s `cold-restart` verdict came from a 15s race while its reported number came from a measurement 5s later, so the two contradicted each other in CI ("no progress" alongside "a 7-round outage"). **Fixed:** the verdict now comes from the measurement, and the wait is 45s rather than 5×T2. | §6.3 | F1 fixed |
| `gosec` reports 28 findings (analyzer job is `continue-on-error`) | §6.3 | F1 records; see §6.3 |
| Certified head still in latest-only JSON persistence | `shardnode/store.go` | F6 (#14) |
| Canonical root input unauthenticated at the executor boundary | §4.4 | F2 (#10) |

## 6. CI

### 6.1 PR triggers

The prototype's workflow was `on: [push]` only, so no check ran on a pull request — the ticket
requires PR-triggered CI for the integration branch. It now triggers on `pull_request` against
`integration/enshrined-evm` and `main` as well as on push. Per the owner's 2026-09-06 decision this
does **not** enable branch protection or required-check rules; the checks run and are visible, and
merging remains a human decision.

### 6.2 Retained checks

`build`, `test` (vet + `make test` + coverage artifact), `analyze`, `evm-shard-chaos` and
`evm-shard-compose-e2e` are unchanged. The two FFI jobs stay `if: false` (§5.2).

### 6.3 Recorded CI failures from run 34102642015 attempt 1

The D2 handoff requires these be recorded or fixed rather than waived.

- **`test` job — fixed.** It did not flake; it panicked:
  `Log in goroutine after Test_Subscriptions/send,_not_subscribed has completed`.
  `Subscriptions.Send` hands logging, sending and metering to a goroutine that nothing tracked, so
  the subtest returned while that goroutine was still writing to its `testing.T`. Fixed by giving
  those goroutines a lifetime — a `sync.WaitGroup` and `Subscriptions.Wait()`, drained by
  `Node.Run` at shutdown and by `t.Cleanup` in the tests. `Test_Subscriptions_Wait` pins the
  contract.

  **Scope of that claim, precisely:** `Subscriptions.Wait()` joins the goroutines `Send` itself
  starts. It does **not** join everything those goroutines hand off to — `LibP2PNetwork.Send`
  starts its own per-peer goroutines and returns — so this is not proof that all node network
  goroutines have stopped when `Run` returns. It fixes the specific unbounded leak in
  `Subscriptions` and makes the test deterministic. Draining the transport is F9 (#17) work.
- **`analyze` job — recorded, not fixed.** 28 gosec findings over 158 files: mostly G115 integer
  conversions in `evmroot/` (`cbor.go`, `d2import.go`, `d5inbox.go`), G301/G306 file permissions in
  the `evmroot/cmd/d*vectors` generators, and one G404 weak RNG in `shardnode/rootnodes.go`. The job
  is `continue-on-error: true`, so it does not gate. The `evmroot/` findings are in D-ticket
  reference-model code, not production paths; the G404 in `rootnodes.go` is root-node selection
  shuffling and wants a look from whoever owns F9 (#17)'s transport work. No blanket waiver is
  claimed — the findings are listed so the next ticket inherits them explicitly.
- **Discovery timeout — fixed.** `network.TestProvidesAndDiscoverNodes` waits for `peer1` and
  `peer2` to learn about `peer3`, which joined after both were already up, so it reaches them only
  through the bootstrap node's gossip. At `2*test.WaitDuration` that was an 8s coin flip: it failed
  again on this branch (run 34105234592) while the identical job on the same commit passed. The
  budget is now 8×. Raising it rather than forcing the lookup is deliberate —
  `dht.RefreshRoutingTable` does force it, but the queries it spawns outlive the test and log
  through `newDHT`'s routing-table callback after completion, panicking the package exactly the way
  the untracked `Subscriptions` goroutines did. The test asserts *that* discovery converges, not how
  fast, so a longer budget costs a slow machine seconds and a fast one nothing.
- **`evm-shard-chaos` — a broken assertion, now fixed; plus one unexplained observation.**

  This was first recorded here as "environment-sensitive", which was a hypothesis stated as a
  diagnosis. Instrumenting it produced an actual answer.

  **The failure was the test contradicting itself.** `cold-restart` took its verdict from whether a
  15-second `wait_for_progress` won its race, but took the number it *reported* from a measurement
  five seconds later. So CI runs 101730435909 and 101730449401 both printed `shard made no progress
  during validator N's outage` immediately followed by `resumed certifying after a 7-round outage`.
  The shard had progressed; only the race had been lost. 15s was too tight for what the scenario
  deliberately provokes: `wait_for_progress`'s own comment notes that a round assigned to a
  currently-dead leader recovers only after the root chain's T2 timeout reissues it to the next
  leader, "a few multiples of T2" — and T2 is 3000ms here, so 15s allowed five, with nothing spare
  for a loaded runner. The verdict now comes from the measurement and the wait is 45s.

  **One observation remains unexplained.** Job 101727627944 additionally reported a
  divergence/equivocation match on the cold-restart path, which is a more serious class of signal
  than a timing assertion. At the time the check was a flat `grep -i 'diverges\|equivocat'` that
  matched three very different messages and then discarded the log, so which one fired cannot be
  recovered. It has not recurred in the runs since, and it did not reproduce locally.
  `check_divergence` now prints the matching lines and separates the benign recovery warning
  (`round.go:317`, followed by a successful certification) from the fatal `cannot safely build
  round N` (`round.go:326`) and from `ErrEquivocatingUC`. **This does not explain that run** — it
  makes the next one explicable. Flagged to F6 (#14), which owns crash recovery: if that warning
  fires on the cold-restart path, the reconcile-after-outage behaviour deserves deliberate
  examination rather than an inference from a passing catch-up assertion.

### 6.4 Real-reth in CI

Neither `scripts/reth-baseline.sh` nor `scripts/reth-paired-devnet.sh` is wired into the GitHub
workflow. Both need a reth binary at the pinned revision; the approved fork now exists
(`ristik/ureth`, §2), so the remaining obstacle is the Rust build and cache cost, which belongs with
the change that first makes the fork differ from upstream. Wiring them in is F3 (#11)'s job. Until
then they are documented local gates, run and recorded here (§5.3, §5.5).

## 7. What F1 does not cover

**This PR is a partial deliverable against #9.** It does not close the ticket, and the acceptance
obligations below stay open on #9 with named owners rather than being reassigned away from it.

- **Paired devnet:** §5.5 delivers one — four validators, four reth instances, a real transaction
  executed and certified. What it does *not* deliver is the ticket's fuller intent: no load, no
  fault injection against real reth (`scripts/chaos-evm.sh` is still fake-executor only), and only
  one transaction through one leader (§5.6). Mixed cadence and multiple partitions are F8 (#16);
  the rest stays open on #9.
- **Mismatch detection before voting:** §5.5 demonstrates two real negatives (chainId mismatch, an
  unreachable Engine API), both refused by `shard-node doctor` before the node votes. F1 adds no
  *new* detection mechanism — it exercises what already exists. A client speaking a different
  Engine API version set is untested and needs F3 (#11)'s version negotiation to be meaningful.
- **The `l1` merge** (§3.2) is not done; F8 (#16) owns it.
- **Cross-client execution fixtures** go to their implementation owners, and real UC / config / TR /
  transition derivation fixtures go to F2 (#10), per the D2 handoff.
