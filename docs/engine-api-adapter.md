# The Engine API adapter

`engineapi` implements `shardnode.Executor` by driving an Ethereum execution client (reth) over the
standard Engine API. This document is specific to that adapter — flags, the params-derivation table,
version/chain-spec requirements, and the operational decisions that came out of building it. For the
interface it implements and what any `Executor` owes the framework, see `docs/shard-node.md`. For the
wire protocol between the shard node and the root chain, see `docs/shard-protocol.md`.

## Contents

1. [Flags](#1-flags)
2. [Round-params derivation](#2-round-params-derivation)
3. [Status policy](#3-status-policy)
4. [Reth version and chain-spec requirements](#4-reth-version-and-chain-spec-requirements)
5. [The devp2p decision](#5-the-devp2p-decision)
6. [Gas limit versus T2](#6-gas-limit-versus-t2)

---

## 1. Flags

`ubft shard-node run --executor engine-api`:

| Flag | Default | Meaning |
|------|---------|---------|
| `--engine-url` | `http://127.0.0.1:8551` | The execution client's authenticated Engine API endpoint (`engine_*` methods) |
| `--eth-url` | `http://127.0.0.1:8545` | The execution client's plain JSON-RPC endpoint (`eth_*` methods) |
| `--jwt-secret` | `$UBFT_HOME/jwt.hex` | Path to the 32-byte hex JWT secret shared with the execution client, per the Engine API's authentication spec |

The two URLs are deliberately separate flags, not one host with two well-known ports assumed: reth
(and other clients) expose them as genuinely different listeners, and nothing about this adapter
should assume they're colocated.

`ubft shard-node doctor --executor engine-api` takes the same three flags and runs preflight checks
against them before you ever start a real node — see §"What `doctor` checks" in
`docs/engine-api-adapter-plan.md` §8, and run it first when something's wrong; it is built to name the
failing check instead of leaving you to guess from a stalled round.

`ubft engine-api genesis --shard-conf <path> --out <path>` generates the reth-compatible
`genesis.json` this adapter needs — see §4. It also takes `--gas-limit` (default 30,000,000 — a
starting point, not a validated limit, see §6), `--coinbase`, and `--extra-data`.

For a funded bootstrap, `--manifest <path>` compiles the strict, versioned
`registrygenesis/allocation-build-v1.schema.json` format into the same standard-JSON preparation
pipeline. `registrygenesis/testdata/allocation-build-v1.example.json` is a synthetic parameter
example based on the current T-track defaults; its balances are not approved issuance values. The
manifest's chain ID must match the shard configuration, and its per-recipient balances must sum
exactly to `nativeSupply`. This step records contract artifact references and addresses but does not
deploy or export contract code/storage.

## 2. Round-params derivation

`engineapi/params.go`'s `DeriveAttributes` is the one place a `shardnode.RoundParams` becomes an
Ethereum `PayloadAttributesV3`. It is a pure function — same inputs, same outputs on every honest
validator — which is what lets followers independently recompute a leader's claimed parameters
instead of trusting them (`VerifyPayloadFields`, called from `Adapter.Verify`).

| Payload field | Derived from | Notes |
|---|---|---|
| `timestamp` | `max(UnicitySeal.Timestamp, parent.timestamp + 1)` | Root rounds run sub-second; the seal's own timestamp can repeat across consecutive rounds, but EVM headers require strictly increasing timestamps |
| `prevRandao` | `SHA256(0x01 ‖ SealHash ‖ round)` | Domain-separated from `parentBeaconBlockRoot` below by the `0x01` prefix — same `(SealHash, round)` pair, different derived values |
| `suggestedFeeRecipient` | the zero address | No fee accounting in exec mode — see the build plan's "deliberately out of scope" |
| `withdrawals` | `[]` (always empty) | No validator withdrawals to model |
| `parentBeaconBlockRoot` | `SHA256(0x02 ‖ SealHash ‖ round)` | Deliberately **not** carried in the disseminated `ProposalEnvelope` — every validator derives it independently from the certificate it already has, rather than trusting a leader-supplied copy |

`SealHash` is `UnicitySeal.Hash` — the certified Unicity Tree root — never a re-hash of the whole
certificate: CBOR re-encoding or signature-map ordering could differ byte-for-byte between two honest
implementations of the *same* certificate, where the seal's own `Hash` field cannot.

`ParentBeaconBlockRoot` specifically is not something `VerifyPayloadFields` compares — it isn't a
field an `ExecutionPayloadV3` carries (confirmed against the Cancun spec), so there's nothing to
extract from a received payload to compare it against. It's verified implicitly: `Adapter.Verify`
derives its own copy and supplies it directly to `engine_newPayloadV3`, and a leader that built
against a different beacon root produces a block reth computes a different `stateRoot`/`blockHash`
for — which `newPayloadV3` reports as `INVALID`.

## 3. Status policy

`PayloadStatusV1.status` from `engine_newPayloadV3`/`engine_forkchoiceUpdatedV3` maps onto
`shardnode.Status` directly — `VALID`→`StatusValid`, `INVALID`/`INVALID_BLOCK_HASH`→`StatusInvalid`,
`SYNCING`→`StatusSyncing`, `ACCEPTED`→`StatusAccepted`. The framework's own policy for the latter two
(`Round.verifyWithRetry` in `shardnode/round.go`) is: poll every 100ms until either a terminal status
arrives or the round's await deadline elapses, then abstain from the round rather than treat "not yet
validated" as "rejected" — see `docs/shard-protocol.md` and the build plan §6's status table. This
adapter itself is stateless about status handling; it reports exactly what reth returned and lets the
framework apply that policy uniformly across executors.

## 4. Reth version and chain-spec requirements

This adapter speaks the **V3** Engine API method set exactly:
`engine_forkchoiceUpdatedV3`, `engine_getPayloadV3`, `engine_newPayloadV3`. `Adapter.CheckCapabilities`
calls `engine_exchangeCapabilities` at startup with that list and fails closed if any are missing —
the wrong URL, a rejected JWT, or a reth build that doesn't speak V3 at all are caught before the
first round, not discovered as a mysteriously stalled one.

Capability exchange alone isn't sufficient, though: it reports what a client *build* supports, not
what its loaded chain spec has *scheduled*. A spec that schedules Prague (or later) would pass it on a
reth build that also speaks V4, and reth would then require `engine_newPayloadV4`+ once that fork
activates. `ubft engine-api genesis` generates the intended spec — it derives `genesis.json` from the
shard conf (so `chainId` cannot drift between the two files) and schedules **Shanghai and Cancun at
genesis (timestamp 0)**, leaving every fork after Cancun out of the schedule entirely — but generating
a file locally is no evidence that the remote client loaded it. So startup also reads the loaded
schedule back from the client with the standard `eth_config` (EIP-7910), and refuses anything other
than the pinned profile; §4.1 lists every check. See `docs/adr/0001-executor-boundary.md` decision 3
for what upgrading past Cancun would require (a new adapter capability list, a new genesis fork
schedule, a new pinned profile in `engineapi/profile.go`, and a version bump treated as a real
compatibility change, not a config tweak).

### 4.1 Binding a shard node to its execution client (operator guidance)

`shard-node run --executor engine-api` refuses to start — before it can submit anything or vote —
unless every check below passes, in this order. `shard-node doctor` runs the same checks, through the
same code, and reports each one.

| # | Check | Reads | Refuses when | Fix |
|---|---|---|---|---|
| 1 | Capability set | `engine_exchangeCapabilities` on `--engine-url` | a required V3 method is missing; the exchange fails; the answer is malformed | point `--engine-url` at the client's **authenticated** port with the right `--jwt-secret` |
| 2 | Configured chain id | the shard conf's `chain_id` partition param — **local configuration** | the param is absent | regenerate the shard conf with `--partition-params …,chain_id=<id>`; there is no default |
| 3 | Chain id | `eth_chainId` on **both** URLs | either differs from the shard conf, is unreadable or `null` | the wrong client, or a genesis generated for a different shard conf |
| 4 | Endpoint pairing | `eth_getBlockByNumber("0x0")` on both URLs | the two report different genesis blocks. Always on | `--engine-url` and `--eth-url` must address the same client |
| 5 | Expected genesis | block 0 on both URLs vs `--expected-genesis-hash` | set, and different, unreadable or malformed | see below |
| 6 | Execution profile | `eth_config` (EIP-7910) on `--eth-url` | the loaded spec is not **Cancun at genesis, nothing scheduled after** — a scheduled fork, a later activation, other system contracts, blob schedule or precompiles — or the client does not serve `eth_config` | start the client from a `genesis.json` produced by `ubft engine-api genesis`, **unedited** apart from the allocation |

**`--eth-url` must expose the `eth` namespace** (`--http.api eth,…` on reth). `eth_config` lives there;
the authenticated port does not serve it (the pinned client answers `Method not found`).

**`--expected-genesis-hash` is optional, and should be set on every validator.** Without it, check 4
still refuses two URLs that disagree with each other, but nothing establishes that the genesis they
agree on is *this deployment's*. The value must come from the deployment's own records — the hash
published with its `genesis.json` — never from the client being configured, which would compare a value
with itself. `ubft` has no offline command that computes it; the allocation is not in the shard conf,
and it changes the hash.

**What passing all six does not establish**, so that nobody relies on it:

- **That both URLs address the same client process.** Two clients started from the same genesis agree
  on checks 3 and 4, and would agree on 6 if both loaded the pinned spec. Check 6 reads only
  `--eth-url`, so it binds the Engine connection's schedule through that same assumption. Configure the
  two URLs for one client, on one host.
- **Every chain-spec parameter or the full fork checksum.** The profile checks the listed EIP-7910 fields; it does not attest to arbitrary execution-client configuration or implementation correctness.
- **Anything about UC configuration.** Checking that certificates carry the expected shard
  configuration hash is #10, and none of these checks discharges it.

**Compatibility and migration.** Check 2 has always been enforced; this revision adds its test.
Check 6 is **new**: a node whose client has loaded a spec scheduling any fork after Cancun, or
activating Cancun after genesis, or that does not implement EIP-7910, now refuses to start where it
previously started. The pinned client (`189c0df3`, reth v2.5.0) implements `eth_config`, and a spec
generated by `ubft engine-api genesis` passes unchanged — every lane in `scripts/` was checked to
generate its spec that way and to expose `eth` on its plain port. There is no flag to skip the check,
no on-disk format change and no protocol change; `doctor` gains an `execution profile` line.

## 5. The devp2p decision

Leave reth's devp2p enabled, and configure static peers explicitly — the validators are a private
four-node chain, and leaving devp2p on does not by itself mean they discover each other. Point each
reth instance at the other three's `enode://` addresses (or a static-nodes file) rather than relying
on default discovery.

With that done, devp2p carries user transactions to whichever validator is leading, and it's how a
validator that's fallen behind the *certified* chain — one whose forkchoice target names a head it
doesn't have — backfills once it has a certified hash to sync toward. That is a different job from a
validator merely missing one leader's proposal: a proposal that hasn't been certified yet is
non-canonical, may not even be announced over devp2p, and there is no certified hash to ask for
regardless — the framework handles that case by abstaining for the round (see
`docs/shard-protocol.md` §7 and `Round.awaitTimeout`), not by falling back to devp2p.

## 6. Gas limit versus T2

**This is a benchmark, not something `doctor` can check.** "Worst-case block execution fits inside
T2" isn't verifiable by inspecting a config value — there is no static formula relating a gas limit to
wall-clock execution time that's trustworthy across hardware. Measure it instead: run
`scripts/chaos-evm.sh`-style load at the target gas limit and T2, and treat the *measured* margin as
an operational limit you document for your deployment, not a startup assertion this adapter makes for
you. `ubft engine-api genesis --gas-limit` defaults to 30,000,000 as a starting point for that
measurement, nothing more.
