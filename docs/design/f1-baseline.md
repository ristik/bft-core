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

**That disclaimer is now discharged.** `scripts/reth-by-hand.sh` was run against reth
`189c0df3` at this baseline and passed unmodified — genesis → `forkchoiceUpdatedV3` →
`getPayloadV3` → `newPayloadV3` → canonical block 1, all `VALID` (§5.3). The request and response
shapes the script asserts do match what a real client accepts, so `engineapi/`'s encoding is
sound on that path.

What the fake executor still hides is *header economics*, which the fake does not model at all —
see §4. That is the substantive fake-versus-real conflict, and it is why F1 adds a real-reth lane
rather than declaring the compose job sufficient.

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

### 4.2 D-1 — the base fee has no floor, and genesis cannot give it one

Driving empty blocks through real reth, `baseFeePerGas` falls by exactly 7/8 per block:

| Block | 1 | 6 | 12 | 24 | 41 |
| --- | --- | --- | --- | --- | --- |
| `baseFeePerGas` (wei) | 875,000,000 | 448,795,319 | 201,417,240 | 40,568,907 | 4,191,124 |

Measured ratio is 0.875 to within 6×10⁻⁹ every block. From the genesis 1 gwei, the base fee reaches
1 wei in **156 empty blocks** — at the shard's idle cadence that is minutes, and system-only blocks
(F4, #12) are empty by construction, so the idle path drives it there continuously.

This measures the claim F5 (#13) has to satisfy — "the fee floor persists after many empty/system-only
blocks; changing the initial genesis base fee alone is demonstrably insufficient" — and confirms it
on a live client rather than by argument. Genesis `baseFeePerGas` is a starting point, not a floor.
Owner: F5 (#13).

### 4.3 D-2 — the gas limit is not pinned by configuration

Over the same run, `gasLimit` rises by exactly 1/1024 per block (30,000,000 → 31,224,868 across 41
blocks), the builder walking toward its own default target. It doubles in ~711 blocks and has no
upper bound from our chain spec.

F5 (#13) must hold "system work plus forced and ordinary capacity cannot exceed the configured
total". At this baseline the configured total is not configured: it drifts upward every block, so any
capacity split computed from it silently inflates. Owner: F5 (#13).

Both deviations are asserted by `scripts/reth-baseline.sh` **in their current broken form**, so that
a fix flips the assertion and forces this document and F5 to be updated together.

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

### 5.3 Real-reth lane

Requires a `reth` binary at the pinned revision. This lane did not exist before F1.

```bash
./setup-evm-nodes.sh -r 3 -v 4          # generates test-nodes/evm-genesis.json

# one round, by hand, no Unicity code involved
reth node --chain test-nodes/evm-genesis.json --datadir <dir> \
  --authrpc.jwtsecret <jwt.hex> --authrpc.port 8551 \
  --http --http.port 8545 --disable-discovery --port 30399 &
./scripts/reth-by-hand.sh <jwt.hex>

# the regression baseline: starts its own reth, drives N empty blocks, asserts §4
./scripts/reth-baseline.sh 40
```

Recorded results against reth `189c0df3`:

- `reth-by-hand.sh`: passes unmodified. All four Engine API steps `VALID`; canonical block 1 at
  `0xeaad90ed02b1e654726166541e071f3107aa25a1b77f9fe0fbff43d32588b5a8`.
- `reth-baseline.sh 40`: passes. Both "behaviour we want" assertions hold; both §4 deviation
  assertions confirm the deviation is still present.

### 5.4 Known-limitations register

| Limitation | Evidence | Owner |
| --- | --- | --- |
| No base-fee floor (D-1) | §4.2, `reth-baseline.sh` | F5 (#13) |
| Gas limit not pinned (D-2) | §4.3, `reth-baseline.sh` | F5 (#13) |
| Two `l1` commits unmerged; consistency-proof fixtures not retained | §3.2 | F8 (#16) |
| FFI CI lane disabled (`if: false`) | §5.2 | F8 (#16) |
| `rootchain/consensus` `Test_recoverState`, `Test_rootNetworkRunning`, `Test_ConsensusManager_messages` fail on a slow/loaded host: they assert round progress against wall-clock deadlines and reach only rounds 2–3 within them. Pass in CI (run 34102642015 attempt 2) and fail reproducibly on the F1 development host, in isolation as well as in the full suite. Not a protocol defect; a test-harness timing assumption. | §5.1 | F1 records; retest under F8 (#16)'s fixture work |
| `scripts/chaos-evm.sh`'s `cold-restart` scenario asserts round progress within 15s of killing a validator; fails on a loaded runner (`evm-shard-chaos`, run 34105234592). Same wall-clock assumption as the row above. | §6.3 | F1 records; retest under F8 (#16) |
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
  contract. This also removes an unbounded goroutine leak at node shutdown, which F9 (#17) cares
  about independently.
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
- **`evm-shard-chaos` — environment-sensitive, see §5.4.** Its `cold-restart` scenario asserts the
  surviving validators advance a round within 15s of a validator being killed. Same family as the
  `rootchain/consensus` failures: a wall-clock progress assertion on a loaded runner.

### 6.4 Real-reth in CI

`scripts/reth-baseline.sh` is the lane, but it is **not** wired into the GitHub workflow: it needs a
reth binary built at the pinned revision, and building `ureth` in CI is a Rust job whose cost and
caching belong with the change that first makes the fork differ from upstream. Wiring it is F3
(#11)'s job, when it has an artifact worth installing. Until then it is a documented local gate, run
and recorded here (§5.3).

## 7. What F1 does not cover

A version/spec mismatch is detected before voting only to the extent the existing shard-conf and
trust-base checks already do it; F1 adds no new mismatch detection. There is no paired real-reth
devnet run (four validators each driving their own reth) in this deliverable — §5.3 exercises one
reth through the Engine API directly, which is what bounds §4. The paired topology is F8 (#16).
Cross-client execution fixtures go to their implementation owners, and real UC / config / TR /
transition derivation fixtures go to F2 (#10), per the D2 handoff.
