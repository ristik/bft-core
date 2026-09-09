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
| **Doctor preflight negative:** chainId mismatch rejected | `execution client reports chainId=31338, shard conf says 31337` |
| **Doctor preflight negative:** unreachable Engine API rejected | refused |
| **Startup negative, the node itself:** `shard-node run` against chainId 31338 | refused, exit 1, before voting |
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

### 5.8 Configured execution identity

F1b (#89) binds what the node can actually verify before it votes, and records what it cannot.

> **Correction.** An earlier revision of this section claimed the Engine endpoint could not be
> identity-checked because "standard interfaces cannot close this: the Engine API has no
> chain-identity read." That was **false**, and review caught it. The Engine API specification's
> [underlying protocol](https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#underlying-protocol)
> section requires an execution client to serve a named subset of `eth_*` on the same authenticated
> port as `engine_*`, and `eth_chainId` and `eth_getBlockByNumber` are both in it. The pinned client
> implements them: `EngineEthApi`, `crates/rpc/rpc-api/src/engine.rs`. Closing the gap needed no new
> Engine method and no divergence from upstream reth, and it is closed below.

**What is enforced at startup**, all before any certification request is submitted:

| Check | Source of truth | Refuses on |
| --- | --- | --- |
| Engine capability set | `engine_exchangeCapabilities` | any required V3 method missing, exchange failure, malformed response |
| Chain id | `eth_chainId` **on both the authenticated Engine connection and the plain one**, vs the shard conf's `chain_id` param | mismatch on either connection, the id being unreadable, a `null` id, or the two connections disagreeing |
| **Endpoint pairing** | `eth_getBlockByNumber("0x0")` on both connections, compared to each other | the two connections reporting different genesis blocks. Runs unconditionally — no operator configuration needed |
| **Genesis identity** | `eth_getBlockByNumber("0x0")` **on both connections**, vs `--expected-genesis-hash` | mismatch, unreadable genesis, a `null` result, malformed expected value |

Why both connections. `--engine-url` and `--eth-url` are separate flags, so nothing structurally
stops an operator from pointing them at two different execution clients — and the Engine connection
is the one that decides what this node votes for: `Build`, `Seal` and `Commit` all go over it, while
the plain connection only answers header lookups. Checking the plain endpoint alone verifies the
chain of a client that does not produce our blocks.

The pairing check is deliberately unconditional and runs *before* the genesis check, so an operator
who has mispaired two endpoints is told they disagree rather than being told one of them mismatches
an expected value and left to work out which. `cli/ubft/cmd/shard_node_startup_test.go`'s
`TestShardNodeRun_EndpointPairing` pins that ordering.

`--expected-genesis-hash` is **operator-configured**. It is deliberately not derived from the client
under test, which would compare a value with itself and prove nothing, and it is not derivable from
the shard conf either — `ubft engine-api genesis` builds the chain spec from the shard conf but the
allocation is not part of it, and the allocation changes the genesis hash. A same-chain-id
/different-genesis client is therefore a real deployment mistake, and it is refused: proven against
real reth in `scripts/reth-paired-devnet.sh` §3d, with a client on chainId 31337 differing only in
its allocation. §3e proves the pairing check on the same two real clients, with `--eth-url` on the
correct one and `--engine-url` on the other and no `--expected-genesis-hash` configured — the case
an earlier revision of this section recorded as accepted.

Both negatives assert the **specific** diagnostic carrying both hashes rather than merely "a startup
check failed", and establish their premise first (two clients that really are up, really share a
chain id and really differ in genesis), so neither can pass on an unreadable fixture or an
unreachable client. Both `shard-node run` invocations are time-bounded: every section-3 case asserts
a refusal, so a regression that lets startup proceed must be a failure rather than a hang.

**What none of this establishes**, kept narrow deliberately:

- **Not same-process identity.** Agreement on chain id and genesis across the two connections rules
  out the mispairing that actually happens in deployment — an endpoint left pointing at another
  shard's client, or at a client started from a different genesis. It does *not* prove the two URLs
  address the same client **process**: two clients started from the same genesis agree on both
  values and only diverge once they build different blocks. Requiring the two URLs to share a
  host/authority would not help either — that is a string comparison, not a check on the client.
- **Not fork-schedule agreement.** A matching genesis hash binds the genesis *block*; it says
  nothing about a fork scheduled by timestamp later in the chain's life.

**The fork schedule is an operator constraint, not a verified guarantee.** An earlier revision of
this section credited `ubft engine-api genesis` plus the capability check with a fork-schedule
guarantee. That is also wrong, for two reasons: generating the intended chain spec file locally is
no evidence that the remote endpoint *loaded* it, and two specs with identical genesis state and
identical current capabilities can still schedule different future forks —
`engine_exchangeCapabilities` reports what a client *build* supports, not what its loaded spec has
scheduled. So the pinned deployment profile records it as a constraint an operator must satisfy:

> The execution client must be started from a chain spec that activates shanghai and cancun at
> genesis and schedules nothing after. No startup check verifies this; a spec that activates a later
> fork by timestamp will pass every check above and then require Engine methods this adapter does
> not call.

Closing *that* would need a fork-schedule read the Engine API does not offer — unlike the endpoint
pairing above, which the standard already supported all along.

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
| Startup binds chain id and genesis on both connections, but cross-validator genesis comparison is still an operator step: each node checks its own client against its own configured value, and nothing compares the value across validators | §5.8 | F1 records; operator procedure |
| Startup cannot verify the execution client's **fork schedule**. The capability set reports what a client build supports, not what its loaded spec scheduled, and generating the chain spec locally is no evidence the endpoint loaded it. Recorded as an operator constraint of the pinned deployment profile | §5.8, ADR 0001 decision 3 | F3 (#11) |
| Startup cannot establish that `--engine-url` and `--eth-url` address the same client **process** — only that they agree on chain id and genesis. Two clients from the same genesis agree until they build different blocks | §5.8 | Accepted limitation |
| No negative for a client speaking a differing Engine API capability set (needs a second reth build) | §5.6 | F3 (#11) |
| Two `l1` commits unmerged; consistency-proof fixtures not retained | §3.2 | F8 (#16) |
| FFI CI lane disabled (`if: false`) | §5.2 | F8 (#16) |
| `rootchain/consensus` `Test_recoverState`, `Test_rootNetworkRunning`, `Test_ConsensusManager_messages` fail on a slow/loaded host: they assert round progress against wall-clock deadlines and reach only rounds 2–3 within them. Pass in CI (run 34102642015 attempt 2) and fail reproducibly on the F1 development host, in isolation as well as in the full suite. Not a protocol defect; a test-harness timing assumption. | §5.1 | F1 records; retest under F8 (#16)'s fixture work |
| `evm-shard-chaos` still stalls intermittently in CI after the leader is killed (`round stuck at 4 for 30s`) with a 3-of-4 quorum live. **Unexplained.** Three test bugs that were masking and partly causing it are fixed; the budget was deliberately not raised again, and the stall paths now dump per-validator round/submit/error evidence so the next occurrence is decidable. May belong to root-chain leader rotation rather than the shard. | §6.3 | Open, F8 (#16) |
| A stale certification response is classified as `ErrEquivocatingUC` at ERROR, indistinguishable from genuine equivocation; and a wedged node escapes only via an unchecked non-consecutive round | §6.3.1 | F2 (#10), F6 (#14) |
| `gosec` reports 28 findings (analyzer job is `continue-on-error`) | §6.3 | F1 records; see §6.3 |
| Certified head is still a single latest-only file with no history; the encoding is now lossless CBOR (#86) but durable write ordering is unproven — a rename is not an fsync | `shardnode/store.go` | F6 (#14) |
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

  **Three test bugs were found and fixed, in the same masking family.**

  1. *The verdict contradicted the number.* `cold-restart` decided from whether a 15s
     `wait_for_progress` won its race, but reported a measurement taken five seconds later. CI runs
     101730435909 and 101730449401 both printed `shard made no progress during validator N's
     outage` immediately followed by `resumed certifying after a 7-round outage`. The verdict now
     comes from the measurement, and the wait is 45s — 15s allowed only five multiples of the
     3000ms T2, and `wait_for_progress`'s own comment says a round assigned to a dead leader needs
     "a few multiples of T2" to be reissued.
  2. *Restart checks passed on pre-kill log lines.* Logs are opened with `>>`, so
     `wait_for 'accepted certificate'` after a restart matched a certificate from **before** the
     kill and returned instantly. Every "rejoined and resumed certifying" assertion was vacuous —
     and worse, it let the script stop the next validator while the previous one had not actually
     rejoined, leaving two of four live, below the 3-of-4 quorum. That produced a real stall caused
     by the test itself. `wait_for_after` now requires a certificate logged past a marker captured
     before the restart.
  3. *The divergence check scanned the whole log.* See below.

  **After all three, an intermittent stall still reproduces in CI, and it is not explained.** On
  `c16d4fbf` one check set reported `quorum stalled after killing leader 2 (round stuck at 4 for
  30s)`, with the subsequent cold-restart failure following from it. Killing one of four validators
  should not stall a 3-of-4 quorum for 30 seconds. Two explanations remain open and the pass/fail
  line cannot separate them: the shard genuinely wedged, or 30s (10×T2) is still too short for the
  root chain to reissue the dead leader's round to the next leader in rotation.

  **I deliberately did not tune the budget again**, because raising it is exactly what would hide
  the first explanation. Instead the three stall paths now call `dump_stall_evidence`, which prints
  each live validator's recent rounds, its recent `submitting block certification request` lines
  (with `round=`, `quiet=`, `leader=`) and its last error. Rising round numbers there mean the
  shard was working and the budget was tight; their absence means it was genuinely stuck. The next
  CI occurrence will say which. **Open, owner F8 (#16)**, with the caveat that it may belong to
  root-chain leader rotation rather than to the shard.

  **The instrumentation then caught the message the original check had hidden.** On `b9c1ae53`:

  ```
  ERROR shardnode/bftclient.go:227 msg="processing certification response"
    err="classifying certificate: shardnode: equivocating unicity certificate:
         new certificate is from older root round 52 than previous certificate 59"
  ```

  Two separate things follow, and they should not be confused.

  *The scenario attribution was wrong, and that was my check's fault.* It reported this "during
  outage-and-catchup", but the line is **line 8** of the log — the node's very first startup,
  minutes before any validator was killed. `check_divergence` was scanning the whole appended log
  rather than the window under test, the same masking bug already fixed twice on this branch. It
  now takes a line marker and only considers lines after it. Verified against synthetic logs:
  a historical equivocation before the marker is ignored, one after it is fatal.

  *The message itself is real and is not a cold-restart issue.* A shard node received a
  certification response carrying a UC from an **older root round than one it had already
  accepted** (52 after 59) and rejected it. Rejecting it is correct — the node must not regress —
  but two things are worth a decision rather than an assumption:

  - A late or re-sent response from a lagging root node is a routine occurrence in a 3-root
    topology, and `types.CheckNonEquivocatingCertificates` classifies it under the same
    `ErrEquivocatingUC` as genuine equivocation, which is a far more serious condition (two
    conflicting certificates for the *same* round). Same error, same ERROR log level, very
    different meanings.
  - It is logged at ERROR and dropped. Nothing measured here says the node then fails to catch up,
    and in this run it did resume certifying.

  Owner: F2 (#10), which owns certificate verification and classification, with F6 (#14) for the
  recovery-path implications. Recorded as an observation needing a decision, **not** as a
  diagnosed defect — I have not established whether the response was genuinely stale or whether
  something produced it that should not have.

### 6.3.1 The leader-kill stall and the same-round certificate conflict — investigation state

Reproduced on `8a9a7603` in push run 34127020349 (chaos job 101757978534) while the paired PR job
passed. **Not resolved. Not waived.** This section records what the evidence does and does not
establish, so the next occurrence starts from here rather than from scratch.

**What the stall evidence actually showed.** The dump added for exactly this purpose answered the
question it was added for. During the leader-kill stall, `evm2`/`evm3`/`evm4` were **not idle**:

```
evm2 last rounds:  partitionRound=4 partitionRound=4
evm2 last submits: round=4 quiet=true leader=false   round=5 quiet=true leader=false
evm2 last error:   "producing round 6 block: awaiting round 6 ..."
```

and in the later cold-restart window, submissions had run to `round=30` while accepted certificates
were still at `partitionRound=4`. So the shard nodes kept advancing their round counter from each
`TechnicalRecord` and kept submitting — what stopped was **certificate acceptance**, not shard
liveness. That rules out "the budget was too short" as a complete explanation: 50 seconds is not the
issue when a node has submitted 26 further rounds without accepting one.

**What the conflict is.** Validator 2, after its restart, repeatedly logged

```
classifying certificate: shardnode: equivocating unicity certificate:
  equivocating UC, different input records for same partition round 4
```

`CheckNonEquivocatingCertificates` compares **whole InputRecord bytes** for a shared partition
round. `NewRepeatIR` copies every field including `Timestamp`, so an ordinary repeat UC is
byte-identical and cannot produce this.

**Cause: found, reproduced locally, and fixed (issue #86).** The checkpoint encoding was lossy.
`FileStore` used `encoding/json`, and `hex.Bytes` marshals nil and empty alike to an empty string
and unmarshals that back to **nil**, while canonical CBOR distinguishes empty bytes (`0x40`) from
null (`0xf6`). `BuildInputRecord` deliberately emits a non-nil empty `SummaryValue`, so every
save/load round trip silently rewrote it to nil and changed `InputRecord.Bytes()` — the very bytes
the signatures cover:

```
original IR CBOR = ...5820<32 bytes>4001f600f6     (0x40 = empty byte string)
restored IR CBOR = ...5820<32 bytes>f601f600f6     (0xf6 = null)
```

The consequences follow directly. A restarted node's restored certificate fails its own
`UC.Verify` with "summary value is nil"; because that restored certificate is the authority the
non-equivocation check compares against, the node then rejects the genuine, correctly signed
certificate for that round as `different input records for same partition round N`, and — since
`c.luc` is left unchanged on a classification error — refuses everything after it. **No root
equivocation and no disk tampering are required.** This is a purely local defect, reproducible in a
unit test with one signer.

An earlier revision of this section offered a timestamp-based hypothesis for the conflict. It was
wrong, and its causal claim has been removed rather than left standing beside the real cause.

**The fix.** The checkpoint is now a versioned envelope encoded with `types.Cbor` — the same codec
that computes the signed bytes — so signatures, inclusion paths, config/TR commitments and the
nil/empty distinction all survive. `EqualIR` is unchanged, signed-byte semantics are unchanged, and
no certificate arriving from the network is normalised to make a comparison pass. Legacy JSON stores
fail startup with a migration message and are left on disk; a damaged file is reported as damaged
rather than as a migration, and neither is ever treated as a fresh store, which would mean voting
from genesis. Regression coverage is in `shardnode/store_roundtrip_test.go` and
`shardnode/restore_auth_test.go`.

**The diagnostic was also wrong, and is fixed.** `DescribeUCConflict` compared fields with
`bytes.Equal`, and `bytes.Equal(nil, []byte{})` is true — so for this exact conflict it reported
`none (input records are equal)`. It now decides equality from canonical `InputRecord.Bytes()`,
renders every byte field as `nil`/`empty`/hex, and spells out the timestamp that
`InputRecord.String` omits.

**Restored certificates are now authenticated before they become authoritative.** `New` verifies the
loaded certificate against the trust base from the *configured* store — never from the checkpoint,
whose own epoch is the thing in question — for signatures, quorum, inclusion paths and this node's
partition and shard, before `SeedLUC`. It does **not** check the expected shard configuration hash:
`UC.Verify` takes that argument and both this path and the live network path pass `nil`, which
accepts the certificate's own `ShardConfHash` without comparison. Plumbing the configured hash in
requires a `New` interface change and is split to F2 (#10); nothing here should be described as
enforcing it.

**What this does not close.** It establishes a local mechanism sufficient to produce the observed
rejection. It does **not** establish that every recorded leader-kill stall had this cause — the
stall investigation stays open under F8 (#16) and root consensus, with the evidence capture below
retained. A green chaos run does not close it.

**Why the node never recovers, which is a separate finding.** On a classification error `c.luc` is
deliberately left unchanged, so the comparison repeats against the same stored certificate.
`TestUCConflictDisposition` records the consequence: the conflicting same-round certificate is
rejected, *and* the next consecutive round on that branch is rejected too ("does not extend previous
state hash"). A node in this state rejects everything the shard produces — which is what
"validator 2 did not resume within its restart budget" was. It escapes only when a **non-consecutive**
round arrives, because `CheckNonEquivocatingCertificates` draws no conclusion across a gap and
accepts it unchecked. So the recovery path is the least-verified one available. That disposition
deserves a deliberate decision from F2 (#10) regardless of what caused the conflict.

**Evidence capture.** The chaos job now runs with `-k` and, on failure, uploads
`chaos-failure-evidence` — every root and shard node's `debug.log`, the persisted
`shard-node-luc.json` (the stored half of every conflict comparison, unavailable from logs alone),
and the root chain's databases. Signing keys are deliberately excluded. Retention 14 days.

**A second mechanism, measured, and now fixed: the leader-await budget exceeded the shard's T2.**

`Round.awaitTimeout` bounds how long a follower waits for the round leader's disseminated block.
The wait is **synchronous** — `HandleCertificate` runs on `BFTClient`'s single message loop — so
that budget is also an upper bound on how fast the node can consume certificates. The root chain
issues one certificate per T2 while a shard is not reaching quorum, which is exactly what a dead or
silent leader produces. A budget longer than T2 therefore does not cost the node one round; it costs
it every round after that one as well.

`DefaultAwaitTimeout` is 5s. The historical chaos lanes generated `t2timeout = 3000ms`. And nothing chose the
value: `SetAwaitTimeout` had no caller outside tests, so every deployment ran at 5s whatever its T2
was — including the deployments whose own source comment says to set it below T2.

The measurement, from a retained real-reth run (`evidence/evm2-debug.log`, PR #91's archive), with
the leader silent:

```
19:50:38.366  accepted certificate
19:50:43.409  ERROR producing round 34 block: awaiting round 34: context deadline exceeded
19:50:43.414  accepted certificate          <- the next one, already queued
19:50:48.416  ERROR ... awaiting round 34: context deadline exceeded
19:50:48.428  accepted certificate
19:50:53.450  ERROR ...
```

One certificate every **5.00s** — the await budget, not the round rate — while the root chain issued
them every 3s. The node was not idle and not stuck on any single certificate; it was consuming them
at a fixed rate slower than they arrived, and the gap widened for as long as the leader stayed
silent.

**Fix.** `shardnode.AwaitTimeoutForT2` derives the budget from the shard conf's `T2Timeout` (half of
it, floored at 200ms and capped at the 5s default), and `ubft shard-node run` applies it, logging
both values at startup. `TestAwaitTimeoutForT2` asserts the property the value exists for — shorter
than T2 across the range of real configurations — rather than the arithmetic.

**What this does and does not claim.** It establishes a mechanism, with a measurement, by which a
validator whose leader has gone quiet falls progressively behind and stops contributing to quorum
in time; that is sufficient to produce a stall of the recorded shape, and the 30s and 50s budgets in
the chaos lanes were never the issue. It does **not** establish that every recorded leader-kill
stall had this cause. The disseminator does buffer a block published before `Await` is called (a
per-round channel of capacity one, `NetDisseminator.deliver`), so "the follower arrived after the
publish and missed it" was considered and ruled out.

**A third mechanism, traced and now removed: certificate delivery depended on continuing to vote.**

Root-chain subscriptions carry a quota of `responsesPerSubscription` (2), refilled only by
`Subscribe` — which `rootchain/node.go` calls from exactly two places, the handshake handler and the
block certification request handler. A validator that submits every round therefore renews itself as
a side effect of voting. One that does not submit renewed only when its own `InactivityTimeout`
(30s) provoked a handshake.

That became reachable when F6b stage 3 made a node resumed from a persisted certificate non-voting
until #105. Traced on a real devnet: such a node received three certificates after restarting, then
nothing for 34 seconds, then a certificate six partition rounds later —

```
09:01:37  extended    partitionRound=15 assignedNext=16
── 34 seconds, no certificate delivered ──
09:02:11  WARN  inactivity timeout exceeded, re-sending handshake
09:02:11  invalidated partitionRound=22 assignedNext=24
          reason: "round 22 arrived where 16 was assigned: at least one certificate was missed"
```

— and the assignments lost in that window are what invalidate its continuity state and leave it
refusing with `no-anchor` or `continuity-gap`. The refusals are a **missing-evidence** condition,
not a missing payload: with no anchor for the current state there is nothing to ask a payload for.

`BFTClient.renewSubscriptionIfIdle` decouples renewal from voting: after a certificate this node did
not submit for, it asks for a subscription again, using the same handshake the root chain already
authorizes and expires. Nothing is refilled on delivery, and no vote is fabricated to provoke a
refill. A submitted request still counts — the credit is consumed one round at a time, matching the
quota's own accounting — so a voting node adds no traffic, and a node that stops entirely still
stops renewing and still expires.

**Renewal is driven by certified progress, not by retries.** A duplicate of a certificate whose
application FAILED is deliberately re-delivered to the driver — that is how a transient executor
failure recovers — and the root chain answers a handshake immediately with its current certificate,
outside the subscription quota. Renewing on those re-deliveries closes a circle that needs neither a
new certificate nor a timer to keep spinning: failed application, handshake, the same certificate
back, failed application. So an already-observed certificate never renews, renewal is coalesced per
certificate, and a failing handshake backs off (1s doubling to 30s) instead of being retried per
delivery. A node whose executor is failing still renews on every NEW certificate, so it does not
have to succeed at anything to keep its feed.

**This does not recover evidence already missed.** A node disconnected long enough to miss an
assignment still has to re-establish continuity by some other route; preventing the starvation stops
the hole being dug, it does not fill one in.

**Open, and blocking.** Owner: F2 (#10) for classification, F8 (#16) and root consensus for whatever
remains of the stall after the await budget is bounded by T2 and the subscription renewal no longer
depends on voting. Per the review, budgets were not
raised and no diagnostic was suppressed.

### 5.7 Real-reth workload and fault harness (F1a #88) — evidence pending isolated reruns

`scripts/reth-chaos.sh` is the real-execution counterpart to `scripts/chaos-evm.sh`: four pinned
reth instances, one per validator, driven by the actual Go adapter, with a funded transaction
workload so recovery is judged by executed blocks and receipts rather than by round counters that
advance whether or not anything ran. No fake fallback; a wrong client revision fails.

```bash
./scripts/reth-chaos.sh -v 4 -t 2      # -F injects a failure to exercise evidence collection
./scripts/reth-chaos-selftest.sh       # the assertion oracle's own regression tests, no devnet
```

**A previous revision of this section drew a conclusion this harness could not support, and it is
withdrawn.** It claimed three independent scenarios showed an executor that "never catches up", and
attributed it to blocks never being gossiped over devp2p. Review 5134687869 found two defects that
invalidate that reading:

- **Scenarios continued after a failed recovery**, so each later fault was injected into an already
  degraded cluster. The retained `convergence.txt` shows node 1 stuck at block 4 while others
  reached 6 and 7 — the later scenarios were measuring the earlier unrecovered state, not the fault
  they named.
- **A failed observation could satisfy an assertion.** With every block and receipt RPC returning a
  JSON-RPC error, all four nodes produced the same empty observation, so "all clients agree on the
  canonical head", "…on the sender nonce" and "…on every receipt" all passed with zero failures.

The devp2p attribution was also asserted without tracing it, and is withdrawn on that ground alone.

**What the harness now guarantees.** Every observation goes through `rpcField`, which fails on a
transport error, a JSON-RPC error, a null result or a missing field, so an unobservable client is a
failure rather than a value that matches other failures. `assertConvergence` additionally requires
every live participant to answer and every recorded transaction to have a receipt matching the
block and status it was recorded with. `scripts/reth-chaos-selftest.sh` pins all of this, including
the reviewer's exact reproduction, and runs without a devnet. After any failed recovery the
remaining scenarios are reported **NOT RUN** rather than producing contaminated evidence. The
leader-kill target is taken from the authenticated technical record (the leader named for the next
round by the latest accepted certificate) and that boundary is recorded; if it cannot be read the
run says so and labels the scenario a shard-process restart. Evidence collection and teardown run
on success, failure and cancellation, and the archive is verified before it is claimed.

**A failure to retain the evidence fails the run.** Evidence collection happens in the supervisor
process, so it reports through the same `fail()` the scenarios use, while the child writes its own
count to a file. Those are two independent counts and `superviseResult` adds them; an earlier
revision assigned the child's over the supervisor's, so a successful run whose archive could not be
written printed the FAIL line and then exited 0 saying "evidence complete" (review 5144079322).
Since the evidence *is* the deliverable of this lane, that direction is the one that matters, and
the summary now attributes each side — `N from the run, M from evidence collection`.
`scripts/reth-chaos-selftest.sh` executes the real `superviseResult` and the real `collectEvidence`
against a fabricated tree, provoking a failed archive, a failed copy and a planted secret file with
a **successful** child, plus a clean positive control.

**The concrete runtime lead**, which is more specific than anything this harness had concluded, came
from the retained `evm1` log: a divergent state with `certifiedBlockHash=""` followed by
`engineapi: commit: expected a 32-byte hash, got 0 bytes` — `Round.reconcile` passing a quiet
certificate's nil `BlockHash` into `Commit`. That is **#92**, with its own deterministic regression
and local-payload-present versus absent cases. The stale-certificate-versus-equivocation taxonomy is
**#93**. Neither is claimed here.

**First isolated run, at an exact committed revision.** bft `f1d8a1c3c0a97bbb5d17bb3213479b213984335b`,
reth `189c0df32617afc488e0f091dbface1bd72cceb4`, clean tree, genesis
`efe500c5…`, funded genesis `f68ca0e5…`, evidence archive sha256 `98eed1d3f13e980e…`.
Result: 12 pass, 3 fail, 5 NOT RUN.

The isolation changed the finding, and not in my favour. The **follower restart with its reth
retained** — the one case the previous revision reported as recovering fully — now **fails**:

```
PASS: follower-restart: validator 2 accepted a new certificate after returning
FAIL: follower-restart: validator 2's executor did not apply the new block (still 2:0x8655ef86…)
FAIL: post-follower-restart: validator 2 has no receipt for 0xcbed4193… (executed and recorded earlier)
FAIL: post-follower-restart: 1 of 4 live clients could not be observed; convergence NOT established
```

It passed before because the weak oracle accepted an unobservable client as agreement. So the
correct statement is narrower than either previous version: **one fault, the mildest of the four,
already leaves a returning node's executor behind**, and scenarios 3 to 6 are honestly NOT RUN
rather than reported. Nothing here says the other three faults behave the same way; that needs
per-scenario clean fixtures.

**Status.** The harness is corrected and its oracle is regression-tested; this single isolated run
is the only scenario evidence, and it covers exactly one fault. #88 stays open. The likely runtime
cause is #92 (`Round.reconcile` passing a quiet certificate's nil `BlockHash` into `Commit`), which
fits a node that accepts certificates but never applies a block. Owners: F6 (#14) for the executor
recovery contract, F2 (#10) for what a returning node should do about a certified head it cannot
reach, F8 (#16) — which should not treat this as an explanation for the unexplained stall.

### 6.4 Real-reth in CI

`.github/workflows/reth-smoke.yml` runs the adapter against the **approved pinned execution client**
on every PR to `integration/enshrined-evm`, and on manual dispatch (F1c, #90). It is a separate
workflow with a distinct name on purpose: a green `ci` run must never be read as real-execution
evidence, because every job there uses `--executor fake`.

**Provenance instead of a 40-minute Rust build.** The pin `189c0df3` *is* upstream tag `v2.5.0` —
verified: `git/refs/tags/v2.5.0` resolves to that commit — and `ristik/ureth`'s `unicity/main` is
byte-identical to it (§2), so the upstream release artifact is a legitimate source for it today.
The workflow records the source URL, the exact asset name and its SHA-256
(`6719ec67…`, GitHub's own reported asset digest), verifies the archive against it, and then
**verifies the extracted binary reports the pinned commit — on cache hits as well as fresh
downloads**. A cache is a convenience, never an authority.

That choice is only valid while the fork has not diverged. **The moment `ureth` carries its own
commits, this lane must build from source** (or publish its own artifact with equivalent provenance),
and the digest and tag pins here stop being meaningful. F3 (#11) extends this workflow rather than
starting a second one.

Budget, measured against the artifact path rather than estimated:

| Step | Cost |
| --- | --- |
| Artifact download + digest verify (cache miss) | ~52 MB, well under a minute |
| Cache hit | negligible; the revision check still runs |
| Rust build | **none** — avoided entirely by the artifact path |
| `reth-baseline.sh 20` (stock control) | ~1 minute |
| `reth-paired-devnet.sh 4 5` (4 validators, 4 clients, funded transaction) | several minutes |
| Job timeout | 45 minutes |

The 160-block baseline run stays a local gate (§5.3); CI runs 20 blocks, which still exercises both
controls. Longer repeat and fault runs belong on a separate bounded lane (#90 stage 3) so that a
green PR check never implies fault coverage that did not run.

Evidence: collection and teardown run on success, failure **and cancellation**. The archive carries
root, shard and reth logs, shard conf, trust base, both genesis files and a provenance record
(BFT commit, reth commit/tag/asset/digest, run id and attempt). Signing keys and JWT secrets are
never copied and their absence is asserted, failing the job if one appears. Retention 14 days. The
upload path can be exercised deliberately via the `inject_failure` dispatch input rather than
waiting for a real failure to discover it does not work.

## 7. What F1 does not cover

**This PR is a partial deliverable against #9.** It does not close the ticket, and the acceptance
obligations below stay open on #9 with named owners rather than being reassigned away from it.

- **Paired devnet:** §5.5 delivers one — four validators, four reth instances, a real transaction
  executed and certified. What it does *not* deliver is the ticket's fuller intent: no load, no
  fault injection against real reth (`scripts/chaos-evm.sh` is still fake-executor only), and only
  one transaction through one leader (§5.6). Mixed cadence and multiple partitions are F8 (#16);
  the rest stays open on #9.
- **Mismatch detection before voting:** now enforced by the node itself, not only by preflight.
  `shard-node run` calls `Adapter.CheckChainID` alongside `CheckCapabilities` and refuses to start
  when the execution client's `eth_chainId` disagrees with the shard conf's `chain_id` param. This
  closes the gap the previous revision recorded honestly: capability exchange cannot tell one chain
  from another — the V3 method set is identical — so a node pointed at the wrong client used to
  start and certify against the wrong state, with only the optional `doctor` able to catch it.
  `doctor` now calls the same method, so the two cannot drift. §5.5 records all three negatives,
  including a live run of the real binary exiting 1.
  **Still open on #9:** a differing Engine API *capability set* negative, which needs a second reth
  build to test against and is meaningful only alongside F3 (#11)'s version negotiation; and
  matching genesis *state* across validators, which chain id does not establish — two chain specs
  can share an id and differ elsewhere, so comparing genesis hashes remains an operator step.
- **The `l1` merge** (§3.2) is not done; F8 (#16) owns it.
- **Cross-client execution fixtures** go to their implementation owners, and real UC / config / TR /
  transition derivation fixtures go to F2 (#10), per the D2 handoff.


### Review validation clarification

The paired negative assertions require a nonzero doctor exit and the specific failing
`chain identity` / `engine link` diagnostic. An unrelated framework failure cannot satisfy them.
The chaos divergence filter includes `cannot safely build round` explicitly: a fatal recovery
error must fail even without the words `diverges` or `equivocat`. These checks were tightened
during review; they do not change runtime protocol behavior or resolve the open leader stall.


### T2 policy clarification (2026-09-09 review)

T2 is the inactivity timeout after which BFT Core instructs a partition/shard to retry a round; it
is not the normal BFT or shard round interval. The EVM setup default and fake-chaos fixture now use
**5000 ms**, the minimum for these test lanes. Production T2 should be substantially longer than
both normal round durations: approximately 10x is a starting sizing rule, not a hard-coded protocol
ratio, and must account for execution and network latency. Do not lower T2 to make a recovery test
finish sooner. Explicit older values remain available for reproducing historical failures only.

The #107 helper chooses the local missing-leader wait, not T2; at test T2=5s it waits up to 2.5s.
That improves the silent-leader timeout path but does not bound total per-certificate processing
(Build, Verify, RPC, signing, send and persistence), nor prove the cause of every observed stall.
A healthy shard may deliver certificates much faster than T2. The historical 3s evidence above is
retained as historical evidence; new recovery acceptance runs must record T2 >= 5s and both normal
round durations. #16 remains open.
