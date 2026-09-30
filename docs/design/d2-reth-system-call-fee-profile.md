# D2 — Reth system-call and fee profile

> **Later genesis amendment (#167, proposed):** [F4f](f4f-standard-genesis-json-bootstrap.md). The v2 amendment defines bootstrap projection and coordinated client/profile requirements; ABI/layout reuse does not imply current execution support. This note does not activate v2 or alter historical test results.

Issue: [#4 D2](https://github.com/ristik/bft-core/issues/4) · Milestone: M0 ·
Prereq: [#3 D1](https://github.com/ristik/bft-core/issues/3) ·
Profile version: **v1** (shared with D1) · Status: **proposed for freeze**

D2 fixes what the execution client (the reth fork) must do with the D1 canonical
root input: the shape and authorisation of the privileged pre-user call, the
Engine API extension and companion-data transport that carry the input and its
witnesses, and the gas / header / receipt / base-fee accounting so that no
implementation chooses any of it independently.

Model: [`evmroot/d2gas.go`](../../evmroot/d2gas.go),
[`evmroot/d2import.go`](../../evmroot/d2import.go). Vectors:
[`evmroot/testdata/d2-vectors.json`](../../evmroot/testdata/d2-vectors.json).
Decision record: [ADR 0004](../adr/0004-reth-system-call-fee-profile.md).

Specification basis: `docs/pos/specification/appendix-evm.tex` §§ Seal
Transaction, Partition Configuration, Genesis State; `evm-partition.tex` §§ Seal
Feed, Round Parameters, Native Currency.

---

## 1. The privileged system operation

Every **successful** block performs the protocol system operation in **two
steps** carrying the D1 canonical root input:

- an **open step**, first, before any transaction — presence-only: it binds the
  `rootInput` and opens the seal-registry commitment slot, and carries **no
  forced-outcome input** (those are not yet determined);
- a **`FinalizeStep`**, after the forced-inclusion prefix, once every forced
  entry's outcome *at its turn* is known — it writes `sealRegistryCommitment`
  into seal-registry storage. Its work is charged against a `g_sys` sub-budget.

Both steps share these rules (checked by `ValidateImport`):

| Property | Rule |
|---|---|
| position | open step is first (nothing executes before it); the finalize step is after the whole forced prefix |
| count | exactly one open + one finalize per successful block |
| origin | `a_sys` — a fixed protocol address. **No private key** originates it. A forged ordinary sender presenting as `a_sys` is rejected. |
| destination | `a_sr` — the seal-registry address |
| value | `0`; it cannot move or mint value |
| signature / nonce | none — not an EOA transaction, no account nonce |
| mempool | cannot enter through the transaction pool |
| result | on failure **or** on consuming more than `g_sys` (open + finalize combined), the **whole block is invalid** |
| no future input | the open step MUST NOT take a forced-outcome argument — a contract could read it and influence the outcomes being predicted |
| replay | historical import and re-execution apply the identical rules and reach the identical state root |

The name "seal transaction" denotes this protocol operation; it is not an
ordinary zero-price Ethereum transaction. The execution client implements its
privileged origin, fee exemption, deterministic resource limit and identical
replay semantics.

### Fixed-Cancun pre-block ordering

Owner decision, 2026-09-17: retain Ethereum's standard EIP-4788 beacon-root
system call. In the fixed-Cancun profile with an empty forced prefix, the order is
**open → finalize → EIP-4788 → ordinary transactions**. No stock pre-block
call may execute before open or between open and finalize. The beacon-root
argument is D1's `SHA-256(CBOR(["UNICITY_EVM_BEACON", r, n]))`, derived from the
bound authorizing root round and assigned shard round, not a zero placeholder.

EIP-4788 retains its standard Ethereum caller, execution behavior and gas
treatment: its work is not added to the header's `gasUsed`, the registry's
`g_sys` charge, ordinary gas, or the registry outcome commitment. The pre-refund
rule in §3 applies to open and finalize; it does not change EIP-4788 accounting.
Ordinary transaction receipts remain standard. EIP-2935 remains inactive under
this Cancun-only profile; this decision does not activate later fork hooks.

Build and replay must apply this same ordering and derived beacon root. Tests
must include actual beacon-root contract state changes so an omitted or
misordered call cannot pass because the test parent lacks that contract.

`evmroot/d2import.go` `ValidateImport` encodes these as ordered predicates with
stable rejection codes (`system_origin_forged`, `system_value_nonzero`,
`system_eoa_like`, `system_from_pool`, `system_failed`, …) so two clients reject
the same bad block for the same stated reason.

## 2. Header commitment, companion data, and the verified-input boundary

- The header's `extraData` is exactly `SHA-256(CBOR(rootInput))` (D1 §3). 32
  bytes, checked on every block **against the canonical re-encoding of the
  structured companion input**, never against opaque bytes with a matching
  self-hash.
- The block's **companion data** carries the **structured** `rootInput` (a D1
  object, not a blob), the **authentication witness**, and the **seal-outcome
  list** (§3). Witnesses authenticate `rootInput` / `D`; they are **not**
  re-hashed into the commitment.

### The authentication lifecycle — verify the real certificate, don't invent one

D2 does **not** re-verify root signatures and does **not** invent a new
root-quorum message for validators to sign. The existing `UnicitySeal`
signatures already cover `UnicitySeal.SigBytes()`, and its shard-tree /
unicity-tree proofs bind the IR / config / TR into that seal; those signatures
cannot be reused over a different message, and an adapter cannot mint new
root-quorum signatures. So the authentication boundary **consumes two verified
inputs**, each produced upstream by the real verifier and each with a tested
mapping:

1. **`VerifiedCert` (D1)** — the real `types.UnicityCertificate` for this `O_-`
   has been verified against the trust base for its epoch: `UnicitySeal.Verify`
   (signatures **and** the `⌊2W/3⌋+1` quorum), the inclusion paths, and
   `tr.Hash()`. Its `SignaturesValid` field **is** that verdict.
   `VerifyCompanionWitnesses` consumes it through D1's
   `ValidateBoundCertificate(RefFromOrigin(O_-), cert, round, cursor)`, which
   checks `SignaturesValid`, the `O_- / TRHash / rootRound` binding, the
   authorized round `== n`, and a non-stale seal-registry cursor. The
   certificate → `VerifiedCert` mapping is exercised through bft-go-base's real
   `UnicitySeal.Verify` in `TestD2_CertificateBoundaryFixtures` — a quorum
   subset (positive) and a sub-quorum subset (negative). It is explicitly a
   **verified external precondition**, not a new signing obligation.
2. **`ExpectedTransitions`** — the verifier's **authenticated, ordered** committed
   trust-base bodies for this block, from its own committed cursor (produced by
   whoever verified the committed-body chain — D3 / the seal registry).
   `ri.Transitions` must equal it **byte-for-byte, position by position**, so
   substitution, reordering, omission and replay all fail. A byte-count / non-
   empty check is **not** the authentication boundary.

Additional binding: `SHA-256(CBOR(TE_-)) == O_-.TRHash` — a swapped technical
record is rejected.

- **Who runs it, per path**:
  - **build**: the shard node is the leader and holds the verified certificate;
    it emits the `VerifiedCert` + `ExpectedTransitions` in the companion.
  - **`newPayloadWithSealV1`**: the shard-node **adapter** derives both verified
    inputs from authenticated state and runs `VerifyCompanionWitnesses` before
    the call; reth trusts that verdict only over the JWT-authenticated channel.
  - **devp2p import / offline re-execution**: the importer **re-derives** the
    `VerifiedCert` (from the carried UC via the real verifier) and its own
    `ExpectedTransitions`, then re-runs the function. This function is the
    *check*, never the *source of trust*.

  **Implementation boundary**: `VerifiedCert` and `ExpectedTransitions` are
  **verifier-owned inputs**, never trusted fields deserialized straight from a
  peer companion. The model's `TestD2_CertificateBoundaryFixtures` establishes
  the seal-quorum leg of the mapping through bft-go-base's real
  `UnicitySeal.Verify`; the full UC inclusion-path / `ShardConfHash` / `TRHash` /
  committed-body-chain derivation is a **mandatory adapter integration test**
  before F1 enables the path — the model consumes its result as a typed
  precondition.
- **Negative fixtures** (`import_checks`): `cert_not_verified`,
  `cert_wrong_origin`, `cert_wrong_authorized_round`, `cert_stale_root_round`,
  `witness_te_not_bound_to_trhash`, `transition_inserted_body`,
  `transition_substituted_body`, `malformed_origin_breaks_ref`; plus
  `TestD2_AuthenticationBoundary` (inserted / substituted / reordered bodies)
  and `TestD2_CertificateBoundaryFixtures` (the real-verifier mapping).

### Verified-input boundary (ordered predicates)

`ValidateImport` runs, in this fixed order — a block that fails any step is
invalid **regardless of whether its Ethereum payload executes**:

| # | Code | Check |
|---|---|---|
| 0 | `bad_config` | `ExecConfig.Valid()` — non-degenerate denominators, ordinary capacity > 0, positive floor |
| 1 | `companion_missing` | companion data present |
| 2 | `companion_unauthenticated` | `VerifyCompanionWitnesses` passes — the `VerifiedCert` is accepted by `ValidateBoundCertificate`, `TE_-` hashes to `O_-.TRHash`, and `ri.Transitions` equals the authenticated `ExpectedTransitions` position by position (see above) |
| 3 | `rootinput_invalid` | the decoded `rootInput` passes D1 `RootInput.Validate` |
| 4 | `context_mismatch` | `rootInput`'s network/partition/shard, authorized round and parent hash equal the block header context |
| 5 | `extradata_mismatch` | `header.extraData == SHA-256(CBOR(canonical rootInput))` |
| 6 | `tx_list_shape` | non-negative `OrdinaryTxCount` / `ForcedTxCount` |
| 6a | `forced_tx_count_mismatch` | `ForcedTxCount` equals the number of forced entries valid at their turn (each is an ordinary tx in the receipt trie — a builder cannot drop or invent one) |
| 6b | `forced_declared_over_g_fi` | every forced entry's `DeclaredGas ≤ g_fi` (the D5 admission invariant) |
| 7 | `system_*` | the FIRST privileged operation (§1) — presence-only, no forced-outcome input |
| 8 | `seal_finalize_missing` / `seal_registry_commitment_mismatch` | a post-forced-prefix `FinalizeStep` is present and ordered after the whole prefix; its `Committed` and the seal-registry storage value both `== SHA-256(CBOR(DerivedSealOutcomes))` — the outcomes determined **at each forced entry's turn** (§3). Checked via `eth_getProof` against `stateRoot`, not a header field |
| 9 | `base_fee_below_floor` / `withdrawals_nonempty` / `blob_tx_present` | §4 |
| 10 | `gas_split_unreconciled` | `reconcileWork` — `Work.System == SystemCall.GasUsed + Finalize.GasUsed`, `Work.Forced == Σ ExecGas(valid prefix) + turn-rejected count * RejectedConsumptionGas`, every `ExecGas ≤ DeclaredGas`, a turn-rejected entry carries no `ExecGas` (all overflow-checked) |
| 11 | `gas_budget` | §3 — `CheckGas` on the **derived** work: combined `g_sys` cap on `open + finalize`, `g_fi` cap on `g_forced_actual` (executed valid prefix + rejected charges), `g_ordinary_capacity` on `DiscretionaryGasUsed`, `g_max` on the total |

`rootInput = []byte{0x80}` (or any blob) never reaches step 5: it is not a
structured `RootInput`, and step 2 fails first.

### Engine API extension — concrete methods

Two V3-family siblings; a client advertises them in `engine_exchangeCapabilities`
and the adapter's startup check (`engineapi/adapter.go` `CheckCapabilities`) fails
the process if they are absent.

| Method | Adds | Semantics |
|---|---|---|
| `engine_forkchoiceUpdatedWithSealV1(forkchoiceState, payloadAttributesV3, sealBuildInput)` | `sealBuildInput = { rootInput: <cbor>, transitions: [<cbor>] }` | build path. Runs the system operation as step 0, writes `extraData`, starts payload building. Returns `PayloadStatusV1` + `payloadId`. `INVALID` if `rootInput` fails validation or the system op fails; `SYNCING` if the parent is unknown. |
| `engine_newPayloadWithSealV1(executionPayloadV3, expectedBlobVersionedHashes, parentBeaconBlockRoot, sealCompanion)` | `sealCompanion = { rootInput: <cbor>, witnesses: [<bytes>], provenance: <string> }` | import path (follower / devp2p / re-exec). Returns `PayloadStatusV1`: `VALID` only if every step above passes **and** reth's own execution yields the committed `stateRoot`/`blockHash`; `INVALID` (with `validationError` = the rejection code) on any D2 predicate failure; `SYNCING` if the parent block or a referenced trust-base body is not yet local; `ACCEPTED` is not used (a seal block is either valid or not). |
| `engine_getPayloadWithSealV1(payloadId)` | response `{ executionPayload, blockValue, sealCompanion }` | the leader disseminates `sealCompanion` alongside the payload. |

Capability strings: `engine_forkchoiceUpdatedWithSealV1`,
`engine_newPayloadWithSealV1`, `engine_getPayloadWithSealV1`.

### Companion retention and synchronization — future scope

Generic devp2p companion gossip, full-node historical synchronization, and an
archival proof service are future scope; they are not implemented by M1. M1
uses seal-only import and bounded authenticated shard-journal suffix fetches,
with retained local archive state and an explicitly capped journal. It does not
claim public/full-node synchronization or indefinite companion retention.

## 3. Gas, header, receipts, tracing, EIP-1559

Two quantities that implementations routinely conflate are kept distinct:

| Quantity | Definition | Feeds |
|---|---|---|
| **header `gasUsed`** | `g_system_actual + g_forced_actual + g_ordinary_actual` | receipts (`cumulativeGasUsed`), tracing, block-fullness reporting |
| **base-fee feedback input** | `g_ordinary_actual` only | the EIP-1559 next-base-fee update |

Rationale: the system operation and the forced-inclusion prefix are
protocol-mandated work, not a congestion signal. Counting them toward the
base-fee target would push fees up purely because the protocol did its job — and
that includes the gas an admitted forced transaction consumes.

### Budgets

```
g_sys + g_fi + g_ordinary_capacity = g_max          (exact; g_max is the header gas limit)
g_ordinary_capacity = g_max - g_sys - g_fi

g_system_actual   = SystemCall.GasUsed + Finalize.GasUsed                       (DERIVED; overflow-checked) <= g_sys
g_forced_actual   = Σ ExecGas over forced entries VALID at their turn (a valid
                    entry that EVM-reverts still consumed its gas here)
                  + (# entries INVALID at their turn) * RejectedConsumptionGas  (DERIVED; overflow-checked) <= g_fi
g_ordinary_actual = DiscretionaryGasUsed — the Σ receipt gasUsed of the
                    NON-forced transactions only                               (DERIVED)                   <= g_ordinary_capacity
header.gasUsed    = g_system_actual + g_forced_actual + g_ordinary_actual
```

**System-call metering clarification, approved 2026-09-17:** `SystemCall.GasUsed`
and `Finalize.GasUsed` mean execution gas spent **before refunds**. Storage
refunds earned by either privileged call do not reduce its charged work and do
not increase the budget available to the other call. Execute open with at most
`g_sys`, then finalize with at most `g_sys - SystemCall.GasUsed` (checked
subtraction). System calls have no transaction intrinsic gas or EOA fee/nonce
processing; this rule does not turn them into ordinary transactions.

Use these same pre-refund values in the derived system outcome, combined
`g_sys` check, header `gasUsed`, and ordinary-gas recovery. The outcome commitment
contains open's gas only; finalize's gas cannot enter the commitment it is
writing, but is included in the combined system total. Build and replay apply
identical metering. Ordinary and valid forced transactions retain standard
Ethereum transaction refund rules and receipt gas accounting.

For the pinned revm implementation, `total_gas_spent()` supplies this quantity;
the refund-subtracting `gas_used()`/`tx_gas_used()` must not supply privileged
work. This API note is illustrative: the before-refund rule above is normative.
Real execution tests must include a storage reset that earns a nonzero refund,
and a combined-budget boundary that the refund would otherwise make pass.
The earlier model's supplied gas values do not establish that execution test.

**A forced transaction's execution gas is `g_forced_actual`, drawn from the
reserved `g_fi` budget — never `g_ordinary_actual`.** A forced entry valid at its
turn stays an ordinary transaction in `transactionsRoot` / `receiptsRoot` with a
standard receipt (whether it then succeeds or EVM-reverts — a reverted forced tx
is a `status 0` receipt, not a rejection record); only its *gas-accounting bucket*
differs. This is what makes the D5 reservation real: a forced tx the inbox
admitted (`declaredGas ≤ g_fi`, D5 §4) is includable **regardless of
discretionary demand** — it cannot be starved by user transactions filling
`g_ordinary_capacity` — and its gas never moves the base fee. Charging it to
ordinary capacity (the fifth-review model) let a valid 9M forced transaction be
rejected under a 20M `g_fi` / 8M ordinary-capacity profile with an otherwise
empty block; that is fixed.

`ValidateImport` (`reconcileWork`) **derives every bucket** from block content —
the two executed privileged steps, the per-entry `ExecGas` of the re-executed
valid forced prefix, the turn-determined rejection set, and `DiscretionaryGasUsed`
— with overflow-safe `math/bits` arithmetic. It reconciles the builder's claimed
`Work.System` / `Work.Forced` and rejects a mismatch (`gas_split_unreconciled`);
`Work.Ordinary` is advisory (the authoritative value is `DiscretionaryGasUsed`).
Per valid entry `ExecGas ≤ DeclaredGas`, and D5's `DeclaredGas ≤ g_fi`
(`forced_declared_over_g_fi`). The count of forced txs in the receipt trie must
equal the turn-valid set (`forced_tx_count_mismatch`), so an admitted forced tx
cannot be silently dropped. `CheckGas` then caps the derived work: combined
`g_sys` on `open + finalize`, `g_fi` on `g_forced_actual`, ordinary capacity on
`g_ordinary_actual`, `g_max` on the total. Ordinary-gas recovery nets out **both**
`g_sys` steps **and the full `g_forced_actual`**:
`RecoverOrdinaryGas(header.gasUsed, SystemCall.GasUsed + Finalize.GasUsed, g_forced_actual)`.

`g_fi = 0` until the forced inbox is enabled; the split still closes, and with no
forced prefix `Finalize.GasUsed` may be 0 (`g_system_actual = SystemCall.GasUsed`,
`g_forced_actual = 0`).

### EIP-1559 — exact integer arithmetic

```
ordinary_target = g_ordinary_capacity / elasticityDenom        (London elasticityDenom = 2)
numerator       = |g_ordinary_used - ordinary_target|          (<= ordinary_target for a valid block,
                                                                 since g_ordinary_used <= 2*ordinary_target)
delta           = floor( parent_base_fee * numerator / ordinary_target ) / changeDenom
                                                                (the product goes through a full 128-bit
                                                                 intermediate — never truncate parent*numerator)
used  > target  -> next = parent + max(1, delta)
used  < target  -> next = parent - delta          (floored at 0)
used == target  -> next = parent
next            -> clamp to [f_base^min, MaxBaseFee]
```

`g_ordinary_used` is not trusted from the builder: it is
**recovered** as `header.gasUsed - system_receipt.gasUsed -
Σ forced_prefix_receipt.gasUsed` (`RecoverOrdinaryGas`), all of which are
authenticated block content, with the forced-prefix boundary fixed by the
deterministic inbox watermark (D5). `ordinary_gas_recovery` vectors cover it.

- The **base-fee floor `f_base^min` is positive and validated on every block**;
  a block with `baseFee < f_base^min` is invalid (`base_fee_below_floor`).
- `ExecConfig.Valid()` rejects a zero elasticity/change denominator, a
  non-positive floor, and a reserved budget that leaves no ordinary capacity;
  `ValidateImport` returns `bad_config` before touching the block.
- `base_fee_arithmetic_oracle` cross-checks `NextBaseFee` against an independent
  `math/big` computation for parent base fees up to `MaxBaseFee` (`2^62`),
  including the case the first review flagged (parent `10^13`, ordinary at `2×`
  target → `parent + parent/8 = 11_250_000_000_000`).

### Block semantics — keep the standard execution-evidence path

The first-review draft inserted a synthetic receipt at index 0 with no
transaction, treated an intrinsically invalid forced entry as an EVM revert, and
the second-review revision then removed **all** forced entries from
`transactionsRoot` / `receiptsRoot` — which loses the standard receipt/log proof
for an actually-executed forced staking or bridge transaction. The third-review
revision keeps ordinary Ethereum evidence wherever the thing genuinely is an
Ethereum transaction:

- **A successful forced transaction IS an ordinary transaction.** It sits in
  `transactionsRoot` / `receiptsRoot` with a **standard receipt** — logs, logs
  bloom, `cumulativeGasUsed`, `transactionHash`, revert handling, `eth_getProof`
  / receipt-proof lookup — exactly Ethereum's. Its events export through the
  normal path. The only thing distinguishing it is *where it came from* (the
  forced inbox, recorded off-trie), not *how it executes*. `ForcedTxCount` is a
  reporting split of the transaction list, not a separate trie.
- **Only two things cannot be ordinary transactions**, and only these are
  recorded off-trie:
  - the **privileged seal call** — no fee payer, no signature, no nonce;
  - a **rejected forced-inbox entry** — an entry *intrinsically invalid at its
    turn* (nonce already used / insufficient balance / fee cap below base fee /
    incompatible rules). It is **consumed** with an authenticated `reason` and
    `status 0`. It is **not** an EVM transaction, has **no** receipt, and is
    **never** an EVM revert.
- **Rejected-entry digest encoding (D2/D5 shared).** When a rejected entry has
  no supplied 32-byte payload digest, `forcedDigest` is
  `SHA-256(CBOR(["UNICITY_FORCED_ENTRY", position, sender, valueDeltaBytes,
  reason]))`. `valueDeltaBytes` is a CBOR byte string containing exactly eight
  bytes: the signed `ValueDelta` in big-endian two's-complement form. This is a
  fixed-width byte-string encoding, not a CBOR signed integer and not an
  unsigned CBOR integer produced by a signed-to-unsigned cast. Ureth does not
  yet implement this forced-entry digest; its matching implementation is
  tracked in [ureth #43](https://github.com/ristik/ureth/issues/43).
- **Where the off-trie commitment lives, and WHEN it is written.** The
  privileged operation runs in **two steps**:
  - The **first system call is presence-only** — mandatory on every successful
    block, binds the `rootInput`, opens the seal-registry commitment slot. It
    carries **no forced-outcome input**: a preceding valid forced tx can change
    the pre-state (balance / nonce) of a later entry, so the rejection set is
    **not determinable** before the prefix runs, and feeding a future outcome
    into the first call would let a contract read and influence the very
    outcomes being predicted.
  - After the whole forced prefix, a narrowly-scoped **`FinalizeStep`** (a second
    privileged operation, its work charged explicitly against `g_sys`) computes
    `sealRegistryCommitment = SHA-256(CBOR([system, rejection₀, …]))` over the
    outcomes **determined at each entry's turn** and writes it into the
    **seal-registry contract's storage**. That storage is authenticated by the
    block's **`stateRoot`** and provable with a standard `eth_getProof`. **No new
    header field.** `extraData` (D1) hashes only the `rootInput`; the "transitively
    under `extraData`" claim is withdrawn.
  - `ValidateImport` re-derives the outcomes (`DerivedSealOutcomes` →
    `evalForcedPrefix`), requires `FinalizeStep.Present && AfterForcedPrefix`,
    and checks both `FinalizeStep.Committed` and the storage value equal the
    re-derived commitment. Build / import / replay all run
    open → prefix → finalize in that order.
- **`header.gasUsed`** = `g_ordinary_actual` (the **discretionary** transaction
  receipt gas) **plus** the seal call's `g_sys` work (open **and** finalize)
  **plus** `g_forced_actual` (the executed valid forced prefix **and** the `g_fi`
  consumption charge for rejected entries). A valid forced tx's receipt gas is
  counted **once**, in `g_forced_actual`. It is **not** "entirely unchanged"
  versus a vanilla block, and it stays recoverable
  (`RecoverOrdinaryGas(header.gasUsed − (open + finalize) − g_forced_actual)`).
- **Lookup / proof.** A successful forced (or discretionary) transaction:
  standard receipts-trie / log proof. The system ops and rejection records:
  `eth_getProof` on the seal-registry contract slot against `stateRoot`. Both are
  standard Ethereum state/receipt proofs — no bespoke position-proof scheme.
- Vectors: `seal_outcome_list` — a **sequential prefix** where entry 1 (valid at
  its turn) spends alice's balance so entry 2 (valid at *admission*) is invalid
  at *its* turn; the rejection set is `determined_only_at_turn_not_admission` and
  the commitment is `written_by_post_prefix_finalization`; entry 1 is an ordinary
  tx in the receipt trie and its `ExecGas` is charged to `g_forced_actual`.
  `forced_prefix_accounting` — a **mixed** prefix (one entry succeeds, one is
  valid-at-turn but EVM-reverts, one is invalid at its turn): both valid entries
  charge `ExecGas` to `g_forced_actual` against `g_fi`, `g_ordinary_actual` is the
  discretionary receipt gas only, the header gas closes exactly, base-fee
  recovery ignores the forced work, and the 8M of executed forced gas exceeds the
  8M ordinary capacity — proving the reserved budget is what makes an admitted
  forced tx includable (the 9M/20M/8M counterexample).  `import_checks`
  `seal_finalize_missing`, `seal_finalize_not_after_prefix`,
  `finalize_wrong_commitment`, `seal_registry_commitment_mismatch`,
  `forced_prefix_uses_reserved_capacity`, `reverted_forced_tx_uses_reserved_capacity`,
  `forced_prefix_over_g_fi`, `forced_declared_over_g_fi`,
  `forced_gas_charged_to_discretionary`, `forced_exec_over_declared`,
  `forced_tx_count_drops_admitted_entry`, `rejected_entry_carries_exec_gas`;
  `TestD2_SealOutcomeListSeparateFromTxList`,
  `TestD2_ForcedPrefixOutcomesDeterminedAtTurn`,
  `TestD2_ForcedPrefixGasUsesReservedBudget`,
  `TestD2_ForcedTxCountMustMatchTurnValidSet`,
  `TestReview6SuccessfulForcedPrefixUsesReservedCapacity`.

### Worked build → import → replay example (`gas_accounting` vector)

```
config:  g_max 30_000_000   g_sys 2_000_000   g_fi 0
         g_ordinary_capacity 28_000_000   ordinary_target 14_000_000
build:   engine_forkchoiceUpdatedWithSealV1(fc, attrs, {rootInput, transitions:[]})
         -> first system op (presence-only) opens the seal-registry slot,
            binds rootInput;                         g_sys OPEN work     1_780_000
         -> forced prefix empty (g_fi 0)             g_forced_actual         0
         -> FinalizeStep writes sealRegistryCommitment over {system}
            into seal-registry contract storage;     g_sys FINALIZE work    20_000
         -> discretionary txs fill to receipt gasUsed  DiscretionaryGasUsed 15_000_000
         g_system_actual = 1_780_000 + 20_000 = 1_800_000  (DERIVED; <= g_sys 2_000_000)
         header.gasUsed  = 1_800_000 + 0 + 15_000_000 = 16_800_000
         header.extraData = SHA-256(CBOR(rootInput))
         getPayloadWithSealV1 -> { payload, sealCompanion:{rootInput, witnesses, provenance:"build"} }
import:  engine_newPayloadWithSealV1(payload, [], beaconRoot, sealCompanion)
         reconcileWork re-derives g_system_actual (open + finalize),
         g_forced_actual (Σ ExecGas of the valid prefix + turn-rejected count *
         charge) and g_ordinary_actual (DiscretionaryGasUsed); a mismatched
         Work.System / Work.Forced is rejected (gas_split_unreconciled);
         CheckGas enforces the g_sys / g_fi caps on the DERIVED buckets; reth
         re-executes -> same stateRoot/blockHash -> VALID
replay:  recovered ordinary gas = 16_800_000 - (1_780_000 + 20_000) - 0 = 15_000_000
         parent_base_fee 1_000_000_000
         numerator = 15_000_000 - 14_000_000 = 1_000_000
         delta = floor(1e9 * 1_000_000 / 14_000_000) / 8 = floor(71_428_571 / 8) = 8_928_571
         next_base_fee = 1_008_928_571   (>= 7, <= 2^62)
```

### Reserved forced-inclusion budget example (`forced_prefix_accounting` vector)

```
config:  g_max 30_000_000   g_sys 2_000_000   g_fi 20_000_000
         g_ordinary_capacity 8_000_000   ordinary_target 4_000_000
prefix:  entry A  valid at its turn, succeeds       DeclaredGas 4M  ExecGas 3_000_000
         entry B  valid at its turn, EVM-reverts    DeclaredGas 6M  ExecGas 5_000_000
         entry C  invalid at its turn (poison)      consumed for       21_000
         A and B are ordinary txs in transactionsRoot / receiptsRoot (B is a
         status-0 receipt); C is a rejection record, off-trie.
build:   g_system_actual   = 1_500_000 open + 30_000 finalize = 1_530_000   (<= g_sys)
         g_forced_actual   = 3_000_000 + 5_000_000 + 21_000   = 8_021_000   (DERIVED; <= g_fi 20_000_000)
         g_ordinary_actual = DiscretionaryGasUsed (non-forced receipts)      = 4_000_000  (<= 8_000_000)
         header.gasUsed    = 1_530_000 + 8_021_000 + 4_000_000 = 13_551_000
import:  reconcileWork derives all three buckets; ForcedTxCount (2) == turn-valid
         set; every DeclaredGas <= g_fi; CheckGas caps g_forced_actual at g_fi.
replay:  recovered ordinary gas = 13_551_000 - (1_500_000 + 30_000) - 8_021_000 = 4_000_000
         base fee: g_ordinary_actual 4_000_000 == ordinary_target -> unchanged.
         The 8_000_000 of executed forced gas alone exceeds g_ordinary_capacity
         (8_000_000) once any discretionary demand is present: charging it there
         (the fifth-review model) would make an admitted forced tx unincludable.
         Against the reserved g_fi it fits, and it does not move the base fee.
```

## 3a. Deviation inventory (minimal-divergence review)

Every enshrined-EVM deviation from stock Ethereum / stock Engine API, why the
simpler alternative was not enough, and its conformance test. The owner approves
or amends this table before D2 freezes.

| # | Deviation | Simpler alternative considered | Why it does not suffice | Audit surface | Conformance |
|---|---|---|---|---|---|
| 1 | Privileged **system call** (`a_sys → a_sr`, no key/nonce, first, failure ⇒ invalid block) | a genesis pre-deploy that a normal transaction pokes each block | a normal transaction needs a funded EOA + nonce, can be reordered or censored, and cannot be *mandatory*; the authenticated root input must be un-forgeable and un-replayable | the one privileged origin; import validation predicates | `import_checks` `system_*`; `TestD2_SystemCallMustBeFirstAndValid` |
| 2 | **`extraData` = 32-byte `SHA-256(CBOR(rootInput))`** commitment | put the root input in a standard payload attribute | V3 `PayloadAttributesV3` has no field for it and it must be in the *header* so it is covered by the block hash; witnesses do not fit in `extraData` | 32 bytes of header; the D1 encoder | D1 vectors + `TestExtraData_IndependentOracle` |
| 3 | **`sealRegistryCommitment` in seal-registry contract storage**, written by a **post-forced-prefix `FinalizeStep`** (system op + rejection records only); successful forced txs stay ordinary | (a) synthetic receipts in `receiptsRoot`; (b) a new `sealOutcomeRoot` header field; (c) the first system call writes it | (a) changes Ethereum receipt semantics; (b) a new header field expands every client's header/import/RPC surface, needs a normative RLP position + block-hash derivation, and `extraData` does **not** cover it; (c) a prior valid forced tx changes a later entry's pre-state, so the outcome set is not knowable before the prefix runs — and a future-outcome input to the first call is contract-readable. A **contract-state value** written at finalization reuses the authenticated `stateRoot` + `eth_getProof` path — the *smallest* change; successful forced txs keep the standard receipt/log proof. | a known contract + slot; the CBOR list encoder; a `g_sys` sub-budget for the finalize step (derived, capped against the combined `g_sys`); `header.gasUsed` includes both `g_sys` steps | `seal_outcome_list` (sequential prefix); `gas_accounting` (open + finalize split, reconciles, closes); `TestD2_SealOutcomeListSeparateFromTxList`, `TestD2_ForcedPrefixOutcomesDeterminedAtTurn`, `TestD2_FinalizerGasBoundToBudget` |
| 4 | **Ordinary-only EIP-1559 feedback** (`g_sys` **and** `g_fi` — including a valid forced tx's execution gas — excluded from the base-fee target) | feed total `gasUsed`, or discretionary + forced, into the London formula | protocol-mandated gas is not a demand signal; including it raises fees purely because the protocol ran or because someone forced a transaction in | `NextBaseFee` + `RecoverOrdinaryGas` (nets out `g_forced_actual`) | `TestD2_BaseFeeUpdateExcludesSystemAndForcedGas`, `TestD2_ForcedPrefixGasUsesReservedBudget`, `forced_prefix_accounting`, `base_fee_arithmetic_oracle` |
| 4a | **Forced-tx execution gas charged to `g_forced_actual` / `g_fi`, not ordinary capacity** | count a successful forced tx's receipt gas in `g_ordinary_actual` like any other tx (fifth-review model) | with `g_fi` then only consumed by *rejected* entries, discretionary demand filling `g_ordinary_capacity` could permanently exclude a forced tx the D5 inbox admitted (`declaredGas ≤ g_fi`) — the reservation protected nothing it was for (9M forced / 20M `g_fi` / 8M ordinary capacity, empty block ⇒ rejected) | `reconcileWork` (per-entry `ExecGas`, `DiscretionaryGasUsed`); the `g_fi` cap; `ForcedTxCount` ↔ turn-valid set | `forced_prefix_accounting`; `import_checks` `forced_prefix_uses_reserved_capacity`, `reverted_forced_tx_uses_reserved_capacity`, `forced_prefix_over_g_fi`, `forced_declared_over_g_fi`, `forced_gas_charged_to_discretionary`, `forced_exec_over_declared`, `forced_tx_count_drops_admitted_entry`, `rejected_entry_carries_exec_gas`; `TestD2_ForcedPrefixGasUsesReservedBudget`, `TestD2_ForcedTxCountMustMatchTurnValidSet`, `TestReview6SuccessfulForcedPrefixUsesReservedCapacity` |
| 5 | **Positive base-fee floor** `f_base^min` as a validity rule | genesis initial base fee only | a floor that is only a genesis value can be driven to 0 by sustained under-target blocks, breaking fee-market and DoS assumptions | one comparison per block | `import_checks.base_fee_below_floor` |
| 6 | **Three `engine_*WithSealV1` siblings** (fcU / newPayload / getPayload) | a single new method, or overload existing V3 params | build needs `{rootInput, transitions}` in the fcU→getPayload flow; import needs the full witness set in newPayload; getPayload must return the companion for dissemination — the three flows carry different data | the Engine API surface (JWT-authenticated) | capability check in `engineapi/adapter.go`; negative auth fixtures |
| 7 | **Companion retention + archival serving** | rely on devp2p re-gossip | historical import and proof export need the witness after gossip has aged out; a retention horizon is published so this is a bounded obligation, not "keep everything forever" | node storage policy | D6 §"proof export"; retention-horizon vector (F7) |
| 8 | **RPC parity** for `eth_call` / tracing (same fee split, no privileged-state authorisation) | leave RPC unchanged | a local simulation that used a different fee split or could call `a_sys` would diverge from consensus / leak authority | RPC handlers | §5; assertion in the model |

Deviations 1–5 are execution-client changes; 6–8 are Engine API / adapter
changes. No deviation adds a header field or changes ordinary transaction /
receipt / trie semantics; deviation 3 rides in already-authenticated contract
state, and `header.gasUsed` transparently includes the mandated `g_sys` work.

## 4. Payload shape

- **withdrawals**: always the empty list (no beacon chain; no external balance
  issuance).
- **blob transactions**: disabled in the initial profile — `blob_tx_present` is
  a validity failure, `ExpectedBlobVersionedHashes` is always an explicit empty
  slice, and no blobs bundle is propagated.
- **protocol issuance**: none. `Supply(n) = S_0 - Burn(n)`; the system operation
  cannot increase native supply.

## 5. RPC surface

- `eth_call`, `eth_estimateGas` and the tracing endpoints apply the **same**
  pinned system/fee rules where relevant (base-fee floor, gas split), so a local
  simulation matches consensus execution.
- No RPC caller can authorise a privileged canonical state change: `eth_call`
  cannot invoke the system operation as `a_sys`, cannot advance the seal
  registry, and cannot activate a validator set. The privileged path is the
  block's first operation only.

## 6. Acceptance mapping

| D2 acceptance clause | Evidence |
|---|---|
| owner deviation review — minimal-divergence inventory, alternatives, audit surface, conformance | **§3a** (8-row table); each deviation names the simpler alternative and why it fails |
| design traces one block through builder, follower, devp2p/sync and re-execution | §2 "authentication lifecycle" (who verifies per path) + §2 concrete methods + retention rule; §3 worked build→import→replay; `ValidateImport` is path-independent |
| … including missing companion data and a forged ordinary system sender | `import_checks`: `companion_missing`, `witness_*`, `system_origin_forged`; `TestD2_MissingCompanionDataIsFatal`, `TestD2_AuthenticationBoundary`, `TestD2_SystemCallMustBeFirstAndValid` |
| verify the real certificate, not a new signature; transition contents are authenticated | §2 "authentication lifecycle" — `VerifyCompanionWitnesses` consumes D1's `VerifiedCert` (real `UnicitySeal.Verify` + quorum + inclusion paths, mapped in `TestD2_CertificateBoundaryFixtures`) via `ValidateBoundCertificate`, checks **TE↔TRHash**, and requires `ri.Transitions` to equal the authenticated `ExpectedTransitions` byte-for-byte, position by position; negatives `cert_not_verified`, `cert_wrong_origin`, `cert_wrong_authorized_round`, `cert_stale_root_round`, `transition_inserted_body`, `transition_substituted_body`, `witness_te_not_bound_to_trhash`; `TestD2_AuthenticationBoundary`, `TestD2_CertificateBoundaryFixtures` |
| the first privileged op cannot know the rejection outcomes it commits | §3 "Block semantics" — the first system call is presence-only; a post-forced-prefix `FinalizeStep` (gas-charged) writes `sealRegistryCommitment` over the turn-determined outcomes; `seal_outcome_list` shows entry 1 changing whether entry 2 is valid at its turn; `import_checks` `seal_finalize_missing`, `seal_finalize_not_after_prefix`, `finalize_wrong_commitment`; `TestD2_ForcedPrefixOutcomesDeterminedAtTurn` |
| A gas accounting vector closes exactly, with the finalizer gas bound to the budget | `gas_accounting` (`system_open_gas` + `system_finalize_gas` = derived `system_gas`; `work_split_reconciles`, `system_within_g_sys`, `closes_exactly` all true); §3 "Budgets" + worked example; `reconcileWork` derives `Work.System` / `Work.Forced` and rejects a mismatch (`gas_split_unreconciled`), `CheckGas` caps the derived combined `g_sys`; `import_checks` `finalizer_gas_hidden_from_work`, `work_system_mismatch`, `work_forced_mismatch`, `combined_system_over_g_sys`, `system_plus_finalize_overflow`; `TestD2_FinalizerGasBoundToBudget`, `TestD2_GasBudgetInvariant`, `TestD2_HeaderGasUsedIsTheSum` |
| the reserved forced-inclusion budget actually protects an admitted forced tx; a mixed success/revert/rejected prefix closes | §3 "Budgets" + "Reserved forced-inclusion budget example"; deviation 4a; `reconcileWork` charges each valid entry's `ExecGas` (success **or** EVM-revert) to `g_forced_actual` / `g_fi` and derives `g_ordinary_actual` from `DiscretionaryGasUsed` only; `forced_prefix_accounting` vector (`work_split_reconciles`, `header_gas_closes_exactly`, `base_fee_ignores_forced_gas`, `nine_million_forced_tx_fits_with_ordinary_full` all true); `import_checks` `forced_prefix_uses_reserved_capacity`, `reverted_forced_tx_uses_reserved_capacity`, `forced_prefix_over_g_fi`, `forced_declared_over_g_fi`, `forced_gas_charged_to_discretionary`, `forced_tx_count_drops_admitted_entry`; `TestD2_ForcedPrefixGasUsesReservedBudget`, `TestD2_ForcedTxCountMustMatchTurnValidSet`, `TestReview6SuccessfulForcedPrefixUsesReservedCapacity` |
| the frozen fee arithmetic stays exact for representable values | `NextBaseFee` via 128-bit `mulDivFloor`; `base_fee_arithmetic_oracle` (big.Int cross-check incl. parent `10^13`); `ExecConfig.Valid()`; `TestD2_NextBaseFeeNoOverflow`, `TestD2_ConfigValidation` |
| receipt indexing / block semantics resolved, standard execution-evidence path preserved | §3 "Block semantics" — a **forced tx valid at its turn is an ordinary tx** in `transactionsRoot`/`receiptsRoot` with a standard receipt (logs/bloom exported normally; a reverted one is a `status 0` receipt), its **execution gas charged to `g_forced_actual` / `g_fi`** not ordinary capacity; only the system ops + `forced_rejected` records are off-trie, committed by a **seal-registry contract-state value** authenticated by `stateRoot` (`eth_getProof`), **no header field**; `header.gasUsed` transparently includes both `g_sys` steps and `g_forced_actual`; vectors `seal_outcome_list`, `forced_prefix_accounting`; `import_checks` `seal_finalize_missing`, `finalize_wrong_commitment`, `seal_registry_commitment_mismatch`; `TestD2_SealOutcomeListSeparateFromTxList` |
| an intrinsically invalid forced entry is not an EVM revert | §3 — `kind = forced_rejected` with an authenticated `reason` and `status 0`, never in the transaction list; `seal_outcome_list.poison_entry_is_a_rejection_record_not_an_evm_revert` |
| positive base-fee floor as a validity rule | §3; `import_checks.base_fee_below_floor`; `TestD2_BaseFeeClampsToPositiveFloor` |
| empty withdrawals, blobs disabled | §4; `import_checks.withdrawals_nonempty`, `import_checks.blob_tx_present` |
| same pinned rules in eth_call/tracing without RPC-authorised privileged state changes | §5 |
| activation / version compatibility | §2 capability strings + startup check |

## 7. Reproduce

```
go test ./evmroot/... -run TestD2
go run ./evmroot/cmd/d2vectors            # print the vector set
go run ./evmroot/cmd/d2vectors -update    # regenerate testdata/d2-vectors.json
```
