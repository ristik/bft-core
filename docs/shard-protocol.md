# Shard Protocol

Normative reference for anything implementing the shard-node role against
BFT Core's root chain — the contract `shardnode/` implements, and what a
second implementation (in any language) needs to interoperate.

This document describes the *protocol*: what goes over the wire, what the
root chain checks, and the state machine a correct shard node runs. It says
nothing about Go, or about the Engine API — `docs/adr/0001-executor-boundary.md`
covers why those are kept out of this layer, and `engineapi/` is one
possible executor, not the only one.

## Contents

1. [The three messages](#1-the-three-messages)
2. [InputRecord field mapping](#2-inputrecord-field-mapping)
3. [The round state machine](#3-the-round-state-machine)
4. [UC classification](#4-uc-classification)
5. [Genesis is always non-quiet](#5-genesis-is-always-non-quiet)
6. [The quiet-round rule](#6-the-quiet-round-rule)
7. [Crash recovery](#7-crash-recovery)
8. [What the root chain actually checks](#8-what-the-root-chain-actually-checks)

---

## 1. The three messages

Everything a shard node needs to send or receive is three CBOR `toarray`
messages over three libp2p protocols. Nothing else exists at this layer.

| Protocol | Direction | Payload |
|----------|-----------|---------|
| `/ab/handshake/0.0.1` | shard → root | `Handshake{PartitionID, ShardID, NodeID}` — subscribe to the UC feed |
| `/ab/block-certification/0.0.1` | shard → root | `BlockCertificationRequest{PartitionID, ShardID, NodeID, InputRecord, ZkProof, BlockSize, StateSize, Signature}` |
| `/ab/certificates/0.0.1` | root → shard | `CertificationResponse{Partition, Shard, Technical, UC, Status, Message}` |

`Signature` covers the entire request with `Signature` itself zeroed —
sign, then set the field, never the reverse. `ZkProof` is empty for
`proof_type = exec` (see the build plan §8) and populated once stateless or
succinct validation is in use.

`CertificationResponse.Status` is transport-level and is never hashed into
the UC: `CertStatusOK` means the wrapped `UC` is newly certified;
`CertStatusRequestInvalid` means the *request* was structurally rejected
(see §8) and the wrapped `UC` is the last-good certificate to resync from —
not an error about the certified chain itself.

## 2. InputRecord field mapping

| Field | Value | Notes |
|-------|-------|-------|
| `RoundNumber` | `TechnicalRecord.Round` from the *last* accepted certificate | Not a self-incremented counter, not the executor's own block number |
| `Epoch` | `TechnicalRecord.Epoch` from the last accepted certificate | Single-epoch throughout for exec-mode (§10 of the build plan) |
| `PreviousHash` | last certified state root — `UC.InputRecord.Hash` | Nil at genesis (§5) |
| `Hash` | the new state root | |
| `BlockHash` | nil if `Hash == PreviousHash` (quiet, §6); otherwise the block's own hash | `IsValid()` enforces this pairing — see §8 |
| `Timestamp` | `UnicitySeal.Timestamp` from the last accepted certificate, exactly | Not wall-clock time. Repeats across rounds are expected (root time is whole seconds; rounds run sub-second) |
| `SummaryValue` | `[]byte{}` | Must be non-nil once `RoundNumber > 0`; content unused at this layer |
| `SumOfEarnedFees` | `0` | Out of scope — see the build plan §10 |
| `ETHash` | nil | Not validated |

`BlockCertificationRequest.BlockSize` and `.StateSize` sit outside the
`InputRecord` but are hashed into the root chain's quorum key alongside it
(`rootchain/request_buffer.go`'s `Add`) — two validators disagreeing on
either is exactly as fatal to quorum as disagreeing on the state root.
Every executor must derive both deterministically from the block's own
content.

## 3. The round state machine

One entry point: **on receiving a certificate** (`UnicityCertificate` plus
its `TechnicalRecord`), a shard node does exactly this, in order:

```
1. Commit what the certificate just certified — the previous round's result.
2. Derive next-round Expectation from (certificate, TechnicalRecord).
3. Confirm local state actually matches what's certified (§7 if it doesn't).
4. If TechnicalRecord.Leader == self: build a candidate; disseminate it.
   Otherwise: obtain the leader's disseminated candidate.
5. Verify the candidate (every node verifies, including the leader its own).
6. Construct the InputRecord (§2), sign, submit.
```

The state machine is *pulled* by certificates, never self-driven: a shard
node never builds or submits anything except in direct response to a
certificate arriving. This is deliberate — see §7 for why it's also what
keeps crash recovery simple.

### Leader election is not this layer's problem

`TechnicalRecord.Leader` is the root chain's own deterministic selection
(`rootchain/consensus/storage/sharding.go`'s `selectLeader`, seeded by round
number and the last certified root hash) — every honest validator computes
the same leader from the same certificate, with no shard-level election
protocol to build or agree on separately.

## 4. UC classification

Compare every incoming certificate (`newUC`) against the last one this node
accepted (`prevUC`, nil on first startup):

| Class | Condition | Action |
|-------|-----------|--------|
| **Valid** | `prevUC` is nil, or `newUC` legitimately extends it | Drive the round state machine (§3) |
| **Duplicate** | same root round as `prevUC` | No-op — this node is connected to more than one root node and received the same certificate twice |
| **Repeat** | same `InputRecord` as `prevUC`, later root round | The root chain's T2 timed out waiting for this shard; still drive §3 — a repeat UC carries a fresh `TechnicalRecord` naming the next attempt at the same round number |
| **Equivocating** | neither of the above holds | Fatal. Something is wrong with the certificate sequence, this node's own bookkeeping, or both — do not continue building on top of it |

Equivocation detection is `types.CheckNonEquivocatingCertificates` — see its
doc comment for the seven checks it runs. Do not reimplement this by hand;
it encodes the Yellowpaper's own equivocation algorithm.

## 5. Genesis is always non-quiet

The root chain's own genesis `ShardInfo` has `IR.Hash = nil`
(`rootchain/consensus/storage/sharding.go`'s `NewShardInfo`). An executor's
own genesis state, by contrast, is a real value — an EVM genesis block has
a real state root; nothing meaningful is ever represented as "no state" on
the executor side.

Consequence: `PreviousHash` is nil exactly once, for round 1, and a real
executor's state root is never nil — so round 1's `Hash != PreviousHash` by
construction, **regardless of whether the executor did anything**. Round 1
is always treated as non-quiet, and must carry a real, non-nil `BlockHash`.

This is a corner case worth testing explicitly: an executor whose own
"nothing happened" signal (e.g., zero transactions) coincidentally matches
its genesis state must still produce a *distinct* block hash for round 1,
or fall back to using its state root as the block hash (see
`shardnode/round.go`'s `blockHashOrFallback`) — never emit a nil
`BlockHash` for the very first round.

## 6. The quiet-round rule

`bft-go-base/types/input_record.go`'s `IsValid()`:

- `Hash == PreviousHash` ⇒ `BlockHash` **must** be nil
- `Hash != PreviousHash` ⇒ `BlockHash` **must** be non-nil

"Quiet" is judged **against the root chain's own `PreviousHash`**, not
against whatever the executor's local pre-round head happened to be — these
two comparisons coincide everywhere except genesis (§5), which is exactly
why genesis needs its own rule instead of falling out of the general case.

For an executor whose blocks always move state root regardless of content
(an EVM adapter: EIP-4788 writes the beacon root into state on every
produced block, transactions or not) — quiet detection cannot happen before
building. Build the candidate, inspect it, and if it turned out to carry no
real work, discard it and submit the quiet `InputRecord` instead of the
built-but-empty one. See the build plan §6's "quiet-round detection happens
after sealing" note for the fuller reasoning.

## 7. Crash recovery

A shard node crashing between submitting a certification request and
processing its confirming certificate is a real, reachable state — not a
hypothetical corner case. For a single-validator shard specifically, the
root chain can certify a request before the requesting process even
receives the confirmation, since quorum for one validator is met the
instant the root chain processes it.

**What is lost on restart:** in-memory bookkeeping of what was just
submitted (which round, which block hash, whether a commit is still owed).

**What is not lost, for an executor with its own durable storage:** the
block itself. A real execution client's "build a block" call typically
persists it to disk before any separate "make it canonical" call — so the
block a crashed node built is very likely still sitting there, just never
finalized.

**The recovery mechanism** (`shardnode/round.go`'s `reconcile`): when a
freshly-started node's local head diverges from what the next certificate
says is certified, retry the executor's commit operation once, using the
*certificate's own* `InputRecord.BlockHash` field — not anything the
crashed process would have needed to remember. If the executor still has
the block, this succeeds and the node proceeds as if nothing happened. If
it doesn't, the node fails loudly, the same way it always would have.

This only works because `Commit` (or its equivalent) must be **idempotent
and safe to call speculatively** — every `Executor` implementation commits
to this as part of the interface contract, not as an incidental property.

**Scope:** this recovers a same-host restart where the executor's own data
survived. It does not recover the executor itself having lost the block
(disk loss, a different machine). See
`docs/adr/0001-executor-boundary.md` decision 2 for the fuller design
tradeoff and what a stronger mechanism would need.

## 8. What the root chain actually checks

Two different failure modes, with very different visibility:

**Structurally invalid requests fail loudly.** A stale round, wrong epoch,
bad `PreviousHash`, or bad timestamp is caught by
`rootchain/consensus/storage/sharding.go`'s `ValidRequest` and rejected with
an explicit `CertStatusRequestInvalid` response sent straight back to the
node that submitted it (see `rootchain/node.go`'s
`onBlockCertificationRequest`). This is the easy case — the error message
names what was wrong.

**Valid-but-divergent requests fail silently.** A request that is itself
perfectly well-formed but disagrees with what other honest validators
submitted for the same round is not rejected — there's nothing malformed
about it. It simply fails to reach quorum. The root chain's T2 timeout
fires, a repeat UC is issued, and from the outside this looks identical to
a network hiccup. Nothing points at which field diverged or between which
validators.

This is why local validation matters as much as it does:
`shardnode/inputrecord.go`'s `ValidateLocal` mirrors `ValidRequest`'s own
checks before a request is ever sent, turning the first failure mode into
an immediate, local, named-field error — and it's why `BlockSize`/`StateSize`
determinism (§2) and the round-params derivation (for an executor like
`engineapi`, see its own docs) matter as much as the `InputRecord` itself:
they're exactly the kind of thing that silently costs quorum three weeks
later if two implementations derive them differently.
