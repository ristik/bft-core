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

Capability exchange alone isn't sufficient, though: a chain spec that schedules Prague (or later) at
genesis would still pass that check on a reth build that *also* speaks V4 — reth would silently
require `engine_newPayloadV4`+ for any block once that fork activates, and this adapter would start
failing with no signal pointing at why. `ubft engine-api genesis` is the other half of the guarantee:
it derives `genesis.json` from the shard conf (so `chainId` cannot drift between the two files) and
explicitly schedules **Shanghai and Cancun at genesis (timestamp 0)**, leaving every fork after Cancun
— Prague, Osaka, and so on — out of the schedule entirely. See
`docs/adr/0001-executor-boundary.md` decision 3 for the full reasoning, including what upgrading past
Cancun would require (a new adapter capability list, a new genesis fork schedule, and a version bump
treated as a real compatibility change, not a config tweak).

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
