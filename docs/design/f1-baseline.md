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
| **Execution profile** | `eth_config` (EIP-7910) on the plain connection, vs the pinned profile in `engineapi/profile.go` | a fork scheduled after the current one (`next`/`last` not null, or absent), a current fork activated after genesis, system contracts, blob schedule or precompiles other than Cancun's, a chain id other than the shard conf's, or no `eth_config` at all. Unconditional |

The configured-identity input itself is also refused when absent: a shard conf with no `chain_id`
partition param stops startup with "requires a chain_id partition param in the shard conf, which has
none" (`TestShardNodeRun_RefusesAShardConfWithNoChainID`). That is a local configuration failure, and
it is tested separately from every client-side chain-id failure because an unavailable RPC cannot
stand in for it.

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
- **Not fork-schedule agreement from genesis alone.** A matching genesis hash binds the genesis
  *block*; a fork that has not activated changes no genesis header field. Measured on the pinned
  client: the generated spec with and without `pragueTime: 4102444800` gives the same chain id and
  the same block-0 hash. The execution-profile check below is what binds the schedule.

**The fork schedule is verified, not assumed — a second correction.** Earlier revisions of this
section first credited `ubft engine-api genesis` plus the capability check with a fork-schedule
guarantee, which was wrong (generating a file locally is no evidence the remote client loaded it, and
`engine_exchangeCapabilities` reports what a *build* supports, not what a loaded spec schedules), and
then recorded the schedule as an operator constraint that "would need a fork-schedule read the Engine
API does not offer". The second statement was true of the Engine API and wrong as a conclusion, the
same way the endpoint-pairing gap was: the standard `eth_*` namespace has had the read since EIP-7910.
`eth_config` reports the loaded spec's current fork and the next and last scheduled ones, and the
pinned client implements it (`EthConfigApi`, `crates/rpc/rpc-eth-api/src/helpers/config.rs`).

**The pinned profile** — what this adapter can drive, and so what startup now requires eth_config to
report (`engineapi/profile.go`):

| field of `eth_config` | pinned value | why |
|---|---|---|
| `next`, `last` | present and `null` | nothing scheduled after the current fork; absence is refused, not read as "nothing" |
| `current.activationTime` | `0` | every timestamp fork active from genesis |
| `current.systemContracts` | exactly `BEACON_ROOTS_ADDRESS` = `0x000f3df6…beac02` | Cancun's, and none of Prague's |
| `current.blobSchedule` | target 3, max 6, update fraction 3338477 | Cancun's |
| `current.precompiles` | exactly the ten Cancun precompiles, `0x01`–`0x0a` | no BLS12 set (Prague), nothing custom |
| `current.chainId` | the shard conf's `chain_id` | a third, independent chain-identity read |
| `current.forkId` | **not pinned** — reported | a checksum over the genesis hash and activated forks, so it varies per deployment; the genesis checks bind only its genesis contribution, not the full checksum |

Refused on the real client in `scripts/reth-paired-devnet.sh` §3f: a client started from the funded
spec plus a future `pragueTime`, whose chain id **and genesis hash** both equal the configured ones —
the premise is asserted before the refusal — is refused at the execution-profile check, and not at the
genesis check. `engineapi/testdata/` holds both clients' recorded `eth_config` results, which the unit
and CLI fixtures replay.

**Which connection, and what that leaves.** `eth_config` is not in the `eth_*` subset the Engine API
requires on the authenticated port, and the pinned client answers `Method not found` there
(measured). So the profile is read over `--eth-url`, and it binds the Engine connection's schedule only
through the pairing checks — which is the same-process assumption in the first bullet above, not a
new one. What remains an operator constraint is therefore narrower than before: configure the two
URLs for one client. Operator-facing guidance, including compatibility for existing deployments, is
`docs/engine-api-adapter.md` §4.1.

### 5.6 What this lane still does not cover

It exercises one transaction through one leader. It is not a load test, not a fault-injection
exercise against real reth (`scripts/chaos-evm.sh` remains fake-executor only), and it does not
exercise mixed cadence or multiple partitions — F8 (#16). The mismatch negatives against real reth
cover chain id, an unreachable Engine API, a different genesis, a mispaired Engine endpoint and a
later scheduled fork (§5.8). A client offering a different Engine API *capability set* is covered by
the controlled fixture in `TestShardNodeRun_RefusesIncompatibleExecutionClient`, which is what #89
asks for; interoperability with another real client is a separate question, and F3 (#11)'s future
custom profile is another.

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

### 5.7.1 Per-scenario matrix, on independent clusters (#88 stages 1-3)

The harness now runs **each fault scenario on its own devnet** — fresh keys, fresh reth datadirs,
fresh chain — which is what #88 stage 2 means by "independent scenarios from clean fixtures". Two
things forced it, and both were learned by running the thing:

- a node that failed to recover in scenario 2 was still broken in scenarios 3-5, so the harness had
  to refuse to run them (`NOT RUN`) and four of six scenarios produced no evidence at all;
- since F6b stage 3 a resumed shard node is non-voting for the rest of its process (#105). Shard
  quorum is `n/2+1`, so on a shared cluster each restart permanently spends part of the fault budget
  and a later scenario stalls because of the scenario before it, not because of its own fault.

`-s <names>` runs any subset. Because every scenario builds its own cluster, a subset is a complete
run of those scenarios rather than a partial run of all of them, and re-running one is minutes
instead of half an hour. A name that is not a scenario is refused **before** anything is started or
stopped, and a run that executes no scenario fails: an unknown selection used to skip everything,
write no failures, archive an empty directory and exit 0 saying the evidence was complete.

**Where the evidence lives, and why not under `test-nodes/`.** `setup-evm-nodes.sh` runs `make
clean`, which deletes that directory whole — and with a cluster per scenario, that happens at every
scenario boundary. An earlier revision stashed only `test-nodes/evidence` across the reset and lost
everything else with it: the full shard, root and reth logs, the trust base, the identities and the
chain configuration, which are exactly what a `continuity-gap` or a `Too deep reorg` has to be
explained from. The surviving summaries cannot reconstruct a certificate history.

Each run therefore writes to `evidence-runs/<runID>/`, outside the blast radius and unique per
invocation, so a run can neither lose its own evidence nor inherit a previous run's:

```
evidence-runs/<runID>/manifest.txt          revisions, dirty-tree status, invocation, T2, selection
evidence-runs/<runID>/scenarios/<label>/    that scenario's FULL logs and configuration, sealed
                                            before its cluster was destroyed
evidence-runs/<runID>/snapshots/<label>/    the per-validator summaries
evidence-runs/<runID>/workload.txt, multi-leader.txt, convergence.txt
evidence-runs/<runID>.tar.gz                the archive, every scenario in it
```

Sealing happens **before** each reset and the reset is **aborted** if it fails: losing the evidence
is worse than not running the next scenario. The manifest is written unconditionally, before any
scenario is selected, so a subset run records the revisions it measured rather than leaving them to
a report written afterwards.

```bash
./scripts/reth-chaos.sh -v 4 -t 2                      # all six
./scripts/reth-chaos.sh -s multi-leader -t 2           # just this one, on its own cluster
```

**Results.** bft `bba665a7` + the F6b corrections (`ea608abc`), reth `189c0df3`, four validators,
two transactions per burst.

| Scenario | Outcome |
| --- | --- |
| baseline workload | **pass** — 2/2 executed and certified, all four clients agree on head, nonce and every receipt |
| shard follower restart, reth retained | **recovers** — accepted a new certificate *and executed new work* (`2:0xca7d5744… → 4:0x20fce7f9…`), and all four clients converged on head, nonce and every receipt. **Requires the T2-bounded await budget** (#107): with the 5s default this scenario fails with `continuity-gap` |
| shard leader kill, quorum live | shard rotates past the killed leader and a transaction executes while it is absent; the returning node accepts a certificate but **its executor does not apply the new block**, with `lastRecoveryDiagnostic=continuity-gap`. Open |
| reth-only restart, datadir retained | measured separately below — **passes** on clean `d14f3bf7` |
| complete shard+reth pair restart | measured separately below — **passes** on clean `d14f3bf7` |
| *(both, as first measured)* | **failed** — safe abstention was observed and the rest of the shard kept certifying, but the recovery transaction never executed within 120s. Superseded by §5.7.2 |
| multi-leader execution | **pass** — see below |

The follower-restart row is new. Every previous revision of this lane reported it as failing
("validator 2's executor did not apply the new block") and scenarios 3-6 as `NOT RUN`.

**What makes the difference is measurable, and it is not the harness.** Three runs, same scenarios:

| runtime | follower restart | leader restart |
| --- | --- | --- |
| F6b stage 3 at `ea608abc` | recovers | recovers |
| plus the certified-commit binding (`8e2599ca`) | `continuity-gap`, no recovery | `continuity-gap`, no recovery |
| plus the T2-bounded await budget (#107) | **recovers**, converged | `continuity-gap`, no recovery |
| plus the replay/leadership gates (`b20eaf4f`), T2 still 3s | `no-anchor`, no recovery | `continuity-gap`, no recovery |
| merged integration (#106 + #107), **T2 5s** | **intermittent** — recovers and converges in one run, `continuity-gap` in another | **intermittent** — same |
| plus subscription renewal decoupled from voting (#109) | **recovers**, converged | **recovers**, converged |

The middle row is the stricter commit rule doing what it should: a returning node used to advance
its executor by committing its own pending proposal on any certificate, which is precisely the
finalization of uncertified blocks that #106 closes. With that route gone, catching up depends on
the recovery path, which needs an unbroken chain of observed certificates — and a node running with
an await budget longer than the shard's T2 consumes certificates more slowly than they arrive, misses
one, and reports `continuity-gap`. Bounding the budget by T2 restores the follower case.

**What the last row rests on.** The restarted validator in that run received **12 certificates after
its restart with a maximum gap of 2.3 seconds** and **no gap over 10s**, while submitting **nothing**
— and its continuity state was invalidated **zero** times. Compare the traced run before the fix: a
34-second gap, six missed partition rounds, and an invalidation. That is the mechanism removed, in
the terms it was traced in, rather than a scenario that happened to pass.

It is one run of an intermittent symptom, so it is evidence about the mechanism and not proof that
no path to `continuity-gap` remains. Preventing the starvation also does not recover evidence a node
already missed while disconnected; that is a separate question and #16 stays open.

**The row before it was intermittent, and that is why the fix is measured this way.** On merged
integration with T2 at 5s, a two-scenario run had both the follower restart and the leader restart
recover, execute new work and converge on all four clients; an earlier run at the same T2 had the
leader restart refuse with `continuity-gap`. Nothing about the runtime differs between them. That is
what #109's trace predicts: whether a restarted node loses its certificate feed at a moment that
costs it an assignment is a timing question, so the same scenario can pass and fail without anything
changing. The row is not "fixed" and must not be reported as such.

The fourth row is worse than the third and is recorded rather than smoothed over. Both restarted nodes now end with a *named* refusal — `no-anchor` on the follower,
`continuity-gap` on the leader — so neither is a mystery about what the node decided; what is not
traced is the certificate history that led each one there. Two things changed under it at once (the
replay/leadership gates and T2 moving to 5 seconds), so nothing here attributes the difference to
either.

The leader case does not recover in any revision after the commit binding, and is not explained here. Its snapshot records
`continuity-gap` on the returning node as well, so it is the same shape at a different scale — the
node was the round leader when it was killed, so it has more to catch up on. Owner: #92 stage 4 and
F6 (#14), with #105 for what a restored node may then do.

**The two failures, stated as what was observed rather than as a diagnosis.** Both end the same way
— the transaction submitted to prove the returning node does new work is never executed — and the
retained snapshots say more than the failure line does:

- `04b-after-reth-restart`: all four validators at `certifiedRound=5` and the *same* execution head
  (`2:0xa3f7ca9c…`), and all four reporting `lastRecoveryDiagnostic=unavailable in the executor
  (status syncing)`. So the shard is not split: it certified a round whose block no executor
  reports holding, and every node is retrying for it.
- `05b-after-pair-restart`: `certifiedRound=21` on all four; the restarted node at execution head
  `2:0xa148fb21…` while the other three are at `3:0x851a7bd3…`, with no recovery diagnostic
  recorded and the restart gate active on it (`nonVotingAfterRestart=1`).

Neither is claimed to be understood here. They are the missing-payload-acquisition case (#92 stage
4) as far as the diagnostics go, and they belong to F6 (#14) and #92 rather than to this harness.

**One further observation, retained because it is not explained.** In the six-scenario run's last
cluster, every validator logged, repeatedly, `engine_forkchoiceUpdatedV3: engine API error -38006:
Too deep reorg` from a recovery `Commit`, and the cluster stopped executing transactions. The same
scenario run again on its own cluster (`-s multi-leader`) passed completely, so it is intermittent.
The adapter pins head, safe and finalized to the same hash on every commit, so a commit that asks
reth to move to any block that is not a descendant of what it has already finalised is refused and
cannot succeed on retry — that is a plausible shape for it, and it is **not** established. Owner:
#92 with F6 (#14); the archive is retained.

#### 5.7.2 Executor-only and pair restart, and what the first refusal actually was

Measured from clean `integration/enshrined-evm` at `d14f3bf7` (manifest `bftDirty=no`), pinned reth
`189c0df3`, T2 5000ms, four validators, `./scripts/reth-chaos.sh -s reth-only-restart,pair-restart
-t 2`. **No recovery behaviour was changed to obtain this**; the build is the merged one.

**Both scenarios pass.** The returning node accepted a new certificate, executed new work, and all
four clients agreed on the canonical head, the sender nonce and every recorded receipt:

- reth-only restart: `2:0xb5d81acd… → 3:0xacd97b81…`
- pair restart: `2:0x537f2536… → 4:0xef9abe3b…`, with the shard certifying throughout and a
  transaction executing while the whole pair was absent.

Both previously failed with the recovery transaction never executing. Two things changed underneath
between then and now — T2 moved from 3s to 5s, and subscription renewal was decoupled from voting —
so this is not attributed to either on its own, and one run of each is not a claim that the failure
cannot recur.

**The first refusal, classified.** This is the part worth having, and it differs per scenario:

| scenario | first refusal | what it was |
| --- | --- | --- |
| reth-only restart | `reading executor head: … connection refused` (×29) | the executor is **not reachable at all** |
| pair restart | `no-anchor` (×12, ~11s) | **missing authenticated evidence** |
| pair restart, then | `certified block ef9abe3b… is unavailable in the executor (status syncing)` (×1) | **authenticated target, payload unavailable** |
| either | — | **a rejected forkchoice did not occur**, in any validator's log, at any point |

The reth-only case does not fit the three-way split, and that is the finding rather than a gap in
the measurement. Its node never asks any of the three questions: with its client down it cannot read
a head, so it abstains before evidence, payload or forkchoice can come into it. Nor did it need
recovery afterwards — the shard process never died, so it kept its in-process anchor and its
certificate feed, and when the client returned with its retained datadir the node simply resumed.
Not one recovery `Commit` was attempted in that scenario.

The pair-restart case is the three-stage progression the design predicts, and the trace dates each
step:

```
15:24:40.19  no-anchor ×12          the in-process anchor died with the process
15:24:51.27  transition=installed   a non-quiet certificate for round 23 supplies an authenticated target
15:24:51.31  unavailable ×1         the executor does not have THAT block yet
             ...                     and then it does, and the node recovers to 0xef9abe3b…
```

So the two refusals are different in kind and neither is a forkchoice rejection: one is a node
without an executor, the other a node without evidence and then, briefly, without a payload. The
`Too deep reorg` investigation is untouched by this and stays open under #16.

#### 5.7.3 The quiet-tail control: recovery depends on fresh non-quiet evidence

#110 established that a returning pair recovers *after* a non-quiet round supplies it with an
anchor. It could not establish what happens when the shard stays quiet, because the harness's own
recovery transaction **was** that non-quiet round. This scenario separates the two: observe first
with nothing injected, then inject one transaction as a separately labelled control.

`observeQuietRecovery` exists precisely so the observation does not run through
`recoveredAndWorking`, which submits a transaction as part of its check — measuring recovery with a
helper that supplies the missing evidence cannot distinguish "it recovered" from "it was given what
it lacked". It reports three outcomes, not two: recovered, observable-but-behind, and **invalid
observation**, the last being a failure of the run rather than the negative result. An executor that
cannot be read says nothing about recovery, and the control that follows can bring the client back
and leave the run green having measured nothing.

**Provenance.** `bft=bba34435`, `bftDirty=no`, pinned reth `189c0df3`, T2 5000ms, run
`20260909T130136Z-28752` (archive sha256 `c581fc0c…`). An earlier exploratory run of this scenario
(`20260909T124228Z-18571`) was made from a **dirty** tree — its manifest says so — and is retained
as exploratory evidence rather than rewritten; the numbers below are from the clean run.

**The observation window: 120 seconds, quiet rounds only, nothing injected, 40 valid samples and 0
failed.**

```
deliveries:               168        accepted-certificate lines
distinctPartitionRounds:   20        what the shard actually certified
distinctRootRounds:        28
retriedDeliveries:        140        duplicates re-delivered after a failed application
anchorDecisions:          168 x transition=unchanged
nonQuietCertificates:       0        not one certificate named a block
firstRefusal:             no-anchor  168 occurrences
certificationRequests:      0        it signed nothing while behind
executor head:            2:0xb8412b5f…        the shard's head: 3:0xc4942523…
```

**Deliveries are not rounds**, and the difference is large here: 168 deliveries over **20** distinct
certified partition rounds, because a refusal marks the certificate unapplied and every
retransmission of it is re-delivered — 140 of the 168. The shard's progress in that window is 20
rounds, not 168.

**The quiet precondition is established, not assumed:** the survivor's canonical head did not move
for the whole window, every certificate the returning node verified was quiet, and 20 distinct
rounds were certified — so the shard was live, quiet, and the node was watching it.

**The node is not short of certificates. It is short of the one kind of certificate that names a
block.** Its feed is healthy — the renewal fix working — and every certificate it received left the
anchor `unchanged`, so it kept refusing `no-anchor`. It never even reached the P-sign gate; the
identity refusal comes first, which is why no "will NOT vote" line appears until after it recovers.

**The positive control: one transaction.** Block 4 was certified and the node reached
`4:0xfe3e6308…` on the first poll after it. The dependency is causal, not incidental.

The recovery sequence, from the earlier run's logs (the clean run reproduces the outcome; this trace
is the one with the reth side aligned):

```
15:46:01.40  shard  transition=installed  partitionRound=45   an authenticated target at last
15:46:01.44  shard  executor head diverges — attempting recovery via Commit
15:46:01.46  shard  certified block 14d5db02… is unavailable in the executor (status syncing)
12:46:01.467 reth   Received forkchoice updated message when syncing  head=0x14d5db02
12:46:01.486 reth   Block added to canonical chain  number=3  hash=0x8ead20d7
12:46:01.506 reth   Block added to canonical chain  number=4  hash=0x14d5db02
12:46:01.507 reth   Canonical chain committed       number=4
15:46:01.50  shard  accepted certificate class=duplicate retryOfFailedApply=true → the retry applies it
```

**What these logs do not show is where block 3 came from.** As in #110 they record that reth acquired
it, not how. That is the payload/ancestor acquisition path to trace before any custom mechanism is
designed, and it is **not** traced here.

**What this establishes, and what it does not.** It establishes that a node returning behind a
certified block does not recover from quiet certificates alone, and that a single non-quiet round is
sufficient — so the missing capability is **authenticated evidence that names a block**. It does not
establish how the executor obtained the ancestor, it does not show that payload acquisition is
solved in general, and it is one run of each phase. The three categories the evidence supports —
RPC unavailable, missing authenticated target, and target `SYNCING` — remain distinct.

**Multi-leader execution (#88 stage 1) — satisfied.** The requirement is two distinct shard leaders
each producing an *executed, certified* block, and counting submissions does not answer it. The
harness now joins three independently recorded facts:

```
receipt      tx            -> EVM block hash        (eth_getTransactionReceipt, the execution client)
anchor line  EVM block hash -> partition round      (shard node, logged after UC.Verify)
submit line  partition round -> leader              (shard node, from the technical record)
```

and drives the workload, bounded, until two distinct leaders have each produced one. The middle step
is why this lane runs its validators at debug: `execution anchor installed` is the only line carrying
a partition round and a certified EVM block hash together. If it is absent the assertion **fails**
rather than quietly finding nothing, and any executed transaction that cannot be correlated is
reported as a skip with its reason — the first version of that function passed the wrong argument
shape to `rpcField`, correlated nothing, and reported "0 leaders", which is a broken harness rather
than a shard result.

Result (`evidence/multi-leader.txt`, tx / block hash / partition round / leader validator / leader
peer / certifying root round):

```
0x7ea8b9b5… 0x76ad3e85…  9 1 16Uiu2HAkvFP8rKKxa9NTp5y5h5AqD2LApSvamcReywt9Zn89pWCQ  51
0x7126d65f… 0x17dc9f88… 12 1 16Uiu2HAkvFP8rKKxa9NTp5y5h5AqD2LApSvamcReywt9Zn89pWCQ  60
0xcbed4193… 0x161dc4c9… 19 1 16Uiu2HAkvFP8rKKxa9NTp5y5h5AqD2LApSvamcReywt9Zn89pWCQ  81
0xc66546da… 0xacefa193… 22 1 16Uiu2HAkvFP8rKKxa9NTp5y5h5AqD2LApSvamcReywt9Zn89pWCQ  90
0xf65b2d22… 0x3b0eb5c0… 32 1 16Uiu2HAkvFP8rKKxa9NTp5y5h5AqD2LApSvamcReywt9Zn89pWCQ 120
0x311b2ed3… 0xa16dcec5… 36 4 16Uiu2HAmPSun6d1PyGjghD7t7QzAF9KaE11dPa4jsk1iukoPp3uR 132
```

Six transactions, six EVM blocks, two distinct leaders, each block tied to the round that certified
it and the certificate that did so.

**Status.** The harness is corrected, its oracle and its supervisor are regression-tested, and every
scenario now produces a per-scenario result instead of four `NOT RUN`s. #88 stays open. The likely runtime
cause is #92 (`Round.reconcile` passing a quiet certificate's nil `BlockHash` into `Commit`), which
fits a node that accepts certificates but never applies a block. Owners: F6 (#14) for the executor
recovery contract, F2 (#10) for what a returning node should do about a certified head it cannot
reach, F8 (#16) — which should not treat this as an explanation for the unexplained stall.

### 6.4 Real-reth in CI, and the same lane locally

Two workflows run the adapter against the **approved pinned execution client**, each named for what it
proves, because a green `ci` run (every job `--executor fake`) must never be read as real-execution
evidence and a green smoke run must never be read as fault coverage:

| workflow | runs | trigger |
| --- | --- | --- |
| `real-reth-smoke` (`.github/workflows/reth-smoke.yml`) | stock-client control (20 blocks) and the paired funded-transaction devnet | every PR to `integration/enshrined-evm`; manual dispatch, optionally with a deliberate failure |
| `real-reth-fault` (`.github/workflows/reth-fault.yml`) | bounded `scripts/reth-chaos.sh` scenarios, each on its own cluster (default `reth-only-restart,pair-restart`) | **manual dispatch only** — before accepting a change to the executor, adapter or recovery paths, or when a fault result is needed; never on PRs |

**One implementation, locally and in CI (#90).** Everything the lanes do beyond the scenarios —
obtaining and verifying the client, the cache, evidence collection, archive validation and teardown —
is `scripts/lib/reth-pin.sh` (definitions only), behind two entry points: `scripts/reth-smoke.sh`, the
supervised smoke lane, and `scripts/reth-pin.sh`, the same functions for workflow steps. The workflows
are thin wrappers, so the refusal and collection paths are exercised locally and by
`scripts/reth-smoke-selftest.sh` rather than only ever read in YAML. An earlier revision had them inline
in the workflow, where they could run only on a hosted runner, and had never run.

**Provenance instead of a 40-minute Rust build.** The pin `189c0df3` *is* upstream tag `v2.5.0` —
`git/refs/tags/v2.5.0` resolves to that commit — and `ristik/ureth`'s `unicity/main` is byte-identical
to it (§2), so the upstream release artifact is a legitimate source for it today. The library records
each platform's asset and GitHub's own reported digest:

| platform | asset | sha256 (GitHub-reported) |
| --- | --- | --- |
| linux-x86_64 (hosted runners) | `reth-v2.5.0-x86_64-unknown-linux-gnu.tar.gz` | `6719ec67…f48f47f` |
| linux-aarch64 | `reth-v2.5.0-aarch64-unknown-linux-gnu.tar.gz` | `47fcc389…6625c3d` |
| darwin-arm64 | `reth-v2.5.0-aarch64-apple-darwin.tar.gz` | `0a43ae85…067cf202` |

Upstream publishes **no x86_64 macOS asset**, so on such a host `--fetch` refuses and names the
alternative: `--reth-bin` with a binary built from the pinned commit, which is accepted only if it
reports that commit and is recorded in the provenance as an operator-supplied binary, verified by
revision rather than by a release digest.

**The cache is a convenience, never an authority.** It holds the release *archive*, not an extracted
binary, keyed from the library (commit, asset, digest, platform) so the key cannot drift from the pin.
On every use — hit or miss — the archive's sha256 is re-checked, and the extracted binary must report
the pinned commit. A cached archive whose digest no longer matches is **refused and left in place**
rather than silently refetched, so whatever changed it is seen. That check on the binary itself runs on
every path, including an operator-supplied binary; a cache, a tag or a file name never substitutes for it.

**Evidence and teardown.** The smoke lane runs its scenarios in a child process in its own process
group, and the supervising parent collects, tears down, archives and validates **however the child
ended** — success, failure, a SIGKILL, or cancellation (SIGINT/SIGTERM to the supervisor).

*Collection is complete or the lane fails.* Every copy the collector attempts is required: a node
directory it cannot create or a file it cannot copy is named, and fails the lane, while the archive —
with whatever could be copied — is still produced for inspection. A minimum node-log count is not a
completeness check: one revision reported success for a collection that had dropped a node's log,
because another node's log met the minimum.

*Teardown is by ownership, including every cleanup nested beneath the lane.* A process is this run's
if it is in the child's process group, or is a `ubft`/`reth` process whose working directory is this
checkout — never because of its name, and never because a pid file holds its number (a stale integer
may by now be anything, another checkout's node included). The same rule is in `helper.sh`
("ownership") and so in `stop-evm.sh -a`, which `reth-paired-devnet.sh`'s cleanup calls from inside the
lane: it stops this checkout's validators and root nodes, recorded or not, and nothing else. A pid
file is acted on only if its process is still a node or client running from this checkout — in the
lane's own sweep too, which until the second #131 review checked the working directory but not the
command, and so stopped an unrelated process started from the same checkout. Until the
#131 review it stopped every `build/ubft root-node` on the machine, which the lane's own sweep could not
undo. Root nodes now record pids; the paired devnet's cleanup, `reth-chaos-lib.sh`'s `stopReth` and the
lane's sweep act on a pid file only when its process is still this checkout's. (The hosted workflows
add a broad sweep afterwards, which is safe only on a disposable runner.) Teardown is then verified: a
process of the run still alive fails the lane.

*Validation, then a separate decision to publish.* The archive is validated independently of the
collector: required files (`provenance.txt`, `run.log` for smoke; `manifest.txt` for fault), node logs
present when scenarios ran, and no secret — by name (`keys.json`, `jwt.hex`, `*.key`), by content (any
`"privateKey"` field), and by value (every JWT and private key under `test-nodes/`, searched verbatim, so
a secret leaked into a log line fails the lane). Validation answers two questions separately: exit 0
validated, 1 incomplete but secret-free, 2 **not publishable** (a secret, or an archive that cannot be
read and so cannot be vouched for, or whose secrets cannot all be known). Publication is
`reth-pin.sh select-upload`, per archive: a
publishable archive is copied, with its validation report, into `evidence-upload/` — **the only path
either workflow uploads** — and a rejected one is moved to `evidence-quarantine/`, never uploaded, with
only a diagnostic naming what was found where (never the value) published in its place.
`evidence-upload/MANIFEST.txt` records every verdict with its sha256, and the upload directory is
scanned once more for every secret value. Until the #131 review a rejected archive stayed at the path
the workflow uploaded with `always()`. The fault workflow selects each archive on its own, so one run's
leak does not withhold another run's evidence. Retention 14 days.

*Every cluster's secrets are searched for, not just the last one's (scan inputs).* The by-value check
can only search for secrets it knows, and both lanes replace a cluster while keeping its logs: the
fault lane rebuilds one per scenario, and the smoke lane's stock control runs before the paired
devnet's setup wipes `test-nodes/` (its JWTs live in a temporary directory besides). Until the second
#131 review, selection searched only the secrets left at the end, so a first cluster's JWT in an
ordinary log line was published as "validated". Now every secret is **recorded before any process
can use it** — `reth-chaos-lib.sh`'s `bringUpCluster` after generating a cluster's JWTs and before
starting its clients, `reth-baseline.sh` after generating each control's JWT, the smoke lane between
its two scenarios and again at the end — into a private scan-inputs file beside the archive and never
in it: `<archive dir>/.scan-inputs/<archive>.scan` (directory 700, file 600, git-ignored, never under
the upload directory). A value that cannot be recorded is never used: the cluster or control is not
started. A failed capture is written into the file, and the supervisor seals it (`#sealed` as the last
line) only if nothing failed. Selection with `--require-scan-inputs`, which both workflows pass,
searches each archive — aggregate logs included — for every value in its own sealed scan inputs, and
an archive whose scan inputs are missing, unsealed or record a failure is **not publishable**. The
bytes validated are the bytes published: each archive is copied into the private quarantine
directory, that copy is validated, and it is that copy which is renamed into `evidence-upload/`.

*The version check is bounded as a whole.* `reth --version` runs as the leader of its own process
group with its output going to a file; the budget kills the group. An earlier revision killed only the
direct child and let it inherit the caller's pipe, so a shell whose child hung held the lane for as long
as the child did.

**Local commands**, from the repository root:

```bash
./scripts/reth-smoke-selftest.sh                                   # every refusal and collection path; no reth, no network
./scripts/reth-smoke.sh --reth-bin "$(command -v reth)"            # the smoke lane with a source build of the pin
./scripts/reth-smoke.sh --fetch                                    # the release artifact (linux-x86_64/aarch64, darwin-arm64)
./scripts/reth-smoke.sh --reth-bin "$(command -v reth)" --inject-failure   # the deliberate-failure path
./scripts/reth-pin.sh obtain --cache-dir ~/.cache/reth-pin --dest /tmp/reth-bin   # the fault workflow's client step
./scripts/reth-chaos.sh -s reth-only-restart,pair-restart -t 2     # the fault workflow's scenario step
./scripts/reth-pin.sh validate-archive evidence-runs/<run>.tar.gz --require manifest.txt --min-node-logs 1
./scripts/reth-pin.sh select-upload --out evidence-upload --quarantine evidence-quarantine \
    --nodes test-nodes --require manifest.txt --min-node-logs 1 evidence-runs/*.tar.gz   # the workflows' publication step
```

Budget, measured against the artifact path rather than estimated: artifact download plus digest check
~52 MB, well under a minute; cache hit negligible, with the digest and revision checks still running;
no Rust build; `reth-baseline.sh 20` ~1 minute; `reth-paired-devnet.sh 4 5` several minutes; smoke job
timeout 45 minutes, fault job 120.

That choice of source is valid only while the fork has not diverged. **The moment `ureth` carries its
own commits, these lanes must build from source** (or publish their own artifact with equivalent
provenance), and the asset and digest pins stop being meaningful. F3 (#11) extends these workflows
rather than starting new ones.

**Evidence recorded for #131** — all local; nothing here ran on a hosted runner. Host: macOS on
Intel (darwin/x86_64); reth `189c0df3` built from source for the host, and the upstream Linux artifact
for the container. The review of `af2a6159` found four defects (§6.4 above: collection completeness,
publication, nested teardown ownership, the version-check bound), repaired in `8f0c52e9`, `bd2a50b0`,
`77daaf11` and `b7d4ed3c`. Running the self-test in a Linux container then found two self-test defects
(`c611b38e`) and one production one (`fdc3dd43`: after an interrupt, teardown signalled the run's
group a second time, which could cut the paired devnet's own cleanup short), and a mutation of that fix
survived until the self-test's stand-in cleanup was made to take time (`3f3e01c1`). The second
review, of `a02899ba`, found two more — an earlier cluster's leaked JWT passing selection, and the
supervisor's pid-file sweep lacking the command check — repaired in `a1f50d5b` and `88a00c2d` (scan
inputs, above), with `d6e46f6b` adding a self-test for the seal's own refusal. **Only the rows at
`a1f50d5b`–`d6e46f6b` describe the head** (`023fcacb` differs from them in docs only, `d6e46f6b` in the
self-test only); the earlier rows are kept as the history they are, at the revisions they name.

| # | what | revision | result |
|---|---|---|---|
| — | `scripts/reth-smoke-selftest.sh` on this host | `d6e46f6b` | **125 ok, 0 bad**, no stand-in left |
| L′ | the smoke and chaos self-tests in `ubuntu:24.04` as a **non-root** user (as root, chmod-based fixtures cannot fail; hosted runners are not root), checkout mounted read-only | `d6e46f6b` | smoke **125 ok, 0 bad** twice with nothing else running; chaos **52 ok, 0 bad**. One earlier run, concurrent with two other self-test suites on the same machine, gave 124 ok, 1 bad: the nested cancellation cleanup (a 2 s stand-in plus a nested `stop-evm.sh -a`) did not finish inside teardown's bounded 10 s drain before the KILL. No process leaked — the KILL and the ownership sweep still stopped only the run's own — and it did not recur unloaded; recorded, not tuned |
| — | `scripts/reth-chaos-selftest.sh` on this host, no reth on `PATH` | `a1f50d5b` | **52 ok, 0 bad** |
| B‴ | `--reth-bin`, clean detached worktree, `ubft` built once for this row and the next; two harmless sentinels in another directory | `023fcacb` (production code = `a1f50d5b`) | PASS, 171 s, devnet **20 PASS / 0 FAIL**; archive `bc66d349…` validated against **34 recorded scan-input values**, 16 of which no longer existed anywhere under `test-nodes/` (the stock control's JWTs and the first cluster's keys); scan inputs sealed, file 600 / directory 700, not in the archive; the workflow's selection step with `--require-scan-inputs` published it; both sentinels survived |
| E‴ | the same, SIGTERM to the supervisor with 4 shard, 3 root and 4 reth running | `023fcacb` | exit 1, "run interrupted"; **16 processes in the run's group at the interrupt**, none left; 34 scan inputs sealed; archive `58950e55…` validated and published by the selection step; both sentinels survived; nothing left on the host |
| — | `scripts/reth-smoke-selftest.sh` on this host | `3f3e01c1` | **102 ok, 0 bad**, no stand-in process left; the bounded version check took 1118 ms against a 1 s budget. At `af2a6159` it was 58 ok and missed all four review findings |
| L | the same self-test in `ubuntu:24.04` (bash 5.2, perl 5.38; `/proc`, not `lsof`, for working directories), the checkout mounted read-only; then the real Linux artifact cold and warm, and a hanging binary whose child holds the output | `3f3e01c1` | **102 ok, 0 bad**; artifact miss then hit, digest and revision verified both times; the hang refused (exit 124) in 1050 ms with its child gone. At `b7d4ed3c` the same run gave 99 ok, 2 bad and a vacuous "0ms" — the self-test defects fixed in `c611b38e` — and at `c611b38e` 101 ok, 1 bad: the second-TERM race fixed in `fdc3dd43` |
| — | `scripts/reth-chaos-selftest.sh` (its library's `stopReth` changed), with no reth on `PATH` | `b7d4ed3c` | 38 ok, 0 bad (chaos files unchanged since) |
| B″ | `--reth-bin`, from a clean detached worktree at the fixed head, `ubft` built once for this row and the next; two harmless sentinels in another directory whose command lines match `build/ubft root-node` and `reth node` | `3f3e01c1` | PASS, exit 0, 193 s; stock control passed; devnet **20 PASS / 0 FAIL**; 51 files collected; archive `aea9f274…` validated, 15 node logs; **both sentinels survived**; no `ubft`/`reth` of the run left. The workflow's selection step on it: published (validated), exit 0 |
| E′ | the same binary and sentinels; SIGTERM to the supervisor once the paired devnet was waiting for certification, with 4 shard nodes, 3 root nodes and 4 reth running | `3f3e01c1` | exit 1, "run interrupted", "incomplete run (status 143)"; **16 processes in the run's group at the interrupt**, 0 left for the ownership sweep, none left; archive `0bcb12be…` validated, 15 node logs; **both sentinels survived**; the selection step published it (validated), exit 0. No `ubft`/`reth` process on the host after both rows |
| B′ | `--reth-bin`, from a clean detached worktree at the review-repair head, `ubft` built once; two harmless sentinels running in another directory whose command lines match `build/ubft root-node` and `reth node` | `b7d4ed3c` | PASS, exit 0, 144 s; stock control passed; devnet **20 PASS / 0 FAIL**; 51 files collected; archive `8605288c…` validated, 15 node logs; **both sentinels survived**; no `ubft`/`reth` process left on the host. The workflow's selection step on that archive: published (validated), exit 0 |
| K | real Linux artifact in a container (`ubuntu:24.04`, Docker 29.5.2): cold cache, then warm, then a tampered copy | library `d8f45a70…` (before the review repairs; the Linux artifact path is re-run at the head in row L) | miss: fetched, sha256 `6719ec67…` verified, binary reports `189c0df3`; hit: digest **re-verified**, revision re-verified; tampered: **refused**, nothing left at the destination |
| A | `--fetch` on this host | `d2fb721b` | **refused** — "no pinned release artifact for platform 'darwin-x86_64'" — exit 1, archive validated |
| B | `--reth-bin` | `d2fb721b`, `146ef80e` | PASS, exit 0; devnet 20 PASS / 0 FAIL; archive 15 node logs |
| B | `--reth-bin`, at the head | `99fa36a3` | PASS, exit 0; devnet 20 PASS / 0 FAIL; archive `eda6501d…` validated, 15 node logs. Teardown reports 0 in the run's group at teardown — correctly: the devnet had stopped its own processes |
| C | `--inject-failure` | `d2fb721b`, `146ef80e` | exit 1 as intended; archive validated with 15 node logs and the injection in `run.log` |
| E | SIGTERM to the supervisor with 7 `ubft` + 4 `reth` running | `146ef80e` | exit 1, "run interrupted", "incomplete run"; archive validated, 15 node logs; **no process left** |
| E | the same cancellation, at the head | `99fa36a3` | exit 1, "run interrupted"; **16 processes in the run's group at the interrupt** (the 11 clients among them), 0 left for the ownership sweep, none left at all; archive `98e8ac3e…` validated, 15 node logs. At `146ef80e` and `618c86af` the same run had reported 0, the count being taken after the interrupt's own signal had stopped them — fixed at `99fa36a3`, and pinned by a deterministic cancellation case in the self-test |
| D | fault lane, the workflow's own commands: `reth-pin.sh verify`, `make build`, `reth-chaos.sh -s reth-only-restart -t 2`, `validate-archive --require manifest.txt --min-node-logs 1` | `d2fb721b` | chaos exit 0; archive validated, 11 node logs |

No `ubft` or `reth` process was left after any run. Production mutations, each alone, against the
self-test: skipping the digest re-check on a cache hit, skipping the verbatim secret scan, treating an
incomplete run as complete, not comparing the reported revision, copying `jwt.hex`, not checking a
download's digest, removing every teardown kill, removing the child's process group, and counting
the group only at teardown — **all caught**. Two mutations survived and are recorded as such: one removed only the polite TERM (the KILL
fallback still stopped everything, so it tested nothing), and one removed only the group kills (the
group-aware ownership sweep still stopped the orphan — redundancy, confirmed by removing both).

**Mutations of the #131 review repairs**, each alone, against the self-test (in a throwaway worktree,
serially): a supervisor that ignores the collector's status, and a collector that swallows copy
failures (at `8f0c52e9`); a paired-devnet cleanup that kills by pid file alone, a `stop_pidfile` that
trusts any live pid, a supervisor sweep that trusts a pid file alone, a version check that kills only
its pid, the version check as it was (the caller's pipe and no group), a secret classed as merely
incomplete, a selection that publishes every archive, a smoke workflow uploading the raw archive path,
and a selection that leaves a rejected archive in place (at `b7d4ed3c`) — **all caught**. Two first
survived and were caught only after the self-test was fixed, and are recorded as such: the
supervisor sweep trusting a pid file alone (the nested cleanups had removed every stale pid file before
the sweep; caught at `c611b38e`), and restoring teardown's second TERM after an interrupt (the stand-in
cleanup finished first; survived two Linux runs at `fdc3dd43`, caught on both platforms at `3f3e01c1`).
**Not run as a live mutation, deliberately:** restoring the machine-wide `build/ubft root-node` sweep
in `stop-evm.sh`, which on this shared host could stop another session's real root nodes. The self-test
shows instead that a name-based sweep would match every sentinel.

**Mutations of the second-review repairs** (at `a1f50d5b`, each alone, both self-tests): the supervisor's
pid-file sweep without the command check; the chaos bring-up recording nothing; the smoke child
recording nothing between scenarios; validation ignoring the scan-inputs check; selection never
requiring scan inputs; the check accepting unsealed inputs; each workflow without
`--require-scan-inputs` — **all caught**. Sealing despite a failed capture **survived** — validation
rejects a `#failed` record on its own, so the seal's refusal was untested — and is caught since
`d6e46f6b`.

**Driver stall**, kept labelled: after row B‴ had finished, my local driver's own inspection step
grepped each recorded value through `test-nodes/` including the reth datadirs, whose sparse `mdbx.dat`
files have an apparent size of 4 GiB each; it ran for over 50 minutes and was stopped by pid, and the
remainder (the inspection with datadirs excluded, the selection, row E‴ and the mutations) was rerun
from that point with the same binary. The lanes never search datadirs.

**Invalidated attempt**, kept labelled: a real-run batch at `fdc3dd43` stopped at a syntax error in
the local driver script (a function named `select`, a bash keyword) after starting its sentinels and
before any lane ran; the sentinels were stopped by pid. No evidence was produced.

**What remains hosted-only, and pending until jobs execute:** a PR-triggered run of the packaged
smoke workflow; a cache hit through `actions/cache`; a dispatched deliberate failure whose artifact is
downloaded and inspected; and a dispatched fault run. The local runs above exercise the same scripts
and do not substitute for any of them.

## 7. What F1 does not cover

**The line-by-line reconciliation of #9 and its children (#88, #89, #90, #100) against merged
evidence lives in [`f1-acceptance-ledger.md`](f1-acceptance-ledger.md).** This section records what
*this* document's own lanes do not cover; the ledger is the wider accounting, including the items
that are met in part and the ones with no owner yet.

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
