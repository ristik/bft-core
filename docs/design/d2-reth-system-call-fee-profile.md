# D2 — Reth system-call and fee profile

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

Before any user transaction, every **successful** block performs exactly one
protocol system operation carrying the D1 canonical root input.

| Property | Rule |
|---|---|
| position | first entry in the block; nothing executes before it |
| count | exactly one per block; a second occurrence is invalid |
| origin | `a_sys` — a fixed protocol address. **No private key** originates it. A forged ordinary sender presenting as `a_sys` is rejected. |
| destination | `a_sr` — the seal-registry address |
| value | `0`; it cannot move or mint value |
| signature / nonce | none — it is not an EOA transaction and has no account nonce |
| mempool | cannot enter through the transaction pool; cannot be replicated by an ordinary transaction |
| result | on failure **or** on consuming more than `g_sys`, the **whole block is invalid** — the call is never silently skipped |
| replay | historical import and re-execution apply the identical rules and reach the identical state root |

The name "seal transaction" denotes this protocol operation; it is not an
ordinary zero-price Ethereum transaction. The execution client implements its
privileged origin, fee exemption, deterministic resource limit and identical
replay semantics.

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

### The authentication lifecycle — who verifies, and the trusted boundary

There is **no free-standing `Authenticated` boolean**. The verdict is produced by
`VerifyCompanionWitnesses(witness, rootInput, trustBase, threshold)`, whose
inputs, checks and obligations are:

- **Trusted inputs**: the verifier's **own** trust-base view (`trustBase`,
  `threshold`) — a `NodeID → weight` assignment obtained from **authenticated
  seal-registry state** (D3), never from the companion. The `threshold` is
  **recomputed** as `⌊2W/3⌋+1` over that assignment; a companion-supplied
  threshold is ignored.
- **Checks**: (a) the witness UC certifies **exactly this `rootInput`'s `O_-`**
  (`witness.UC.OriginID == rootInput.Origin.Identity()`); (b) the seal's
  **unique authorised signer weight ≥ threshold**; (c) one non-empty transition
  proof per `rootInput.Transitions` entry.
- **Who runs it, per path**:
  - **build**: the shard node holds the authorizing certificate (it is the
    leader). `sealBuildInput` carries only `{rootInput, transitions}` because the
    builder already has and has verified the cert; it emits the full
    `sealCompanion` (with the UC witness + transition proofs) for dissemination.
  - **`newPayloadWithSealV1`**: the shard-node **adapter** runs
    `VerifyCompanionWitnesses` against its trust base **before** the call; the
    execution client trusts that verdict **only** over the JWT-authenticated
    Engine API channel. The adapter, not reth, is the authentication authority.
  - **devp2p import / offline re-execution**: the importer **re-runs**
    `VerifyCompanionWitnesses` against its **own** trust base, using the UC
    witness + transition proofs carried in `sealCompanion.witnesses`. The
    verdict is never an untrusted companion assertion.
- **Negative fixtures** (`import_checks`): `witness_wrong_origin`,
  `witness_below_threshold`, `witness_unknown_signer`,
  `witness_transition_proof_count`, `malformed_origin_breaks_witness` (a
  malformed `O_-` cannot carry a matching witness).

### Verified-input boundary (ordered predicates)

`ValidateImport` runs, in this fixed order — a block that fails any step is
invalid **regardless of whether its Ethereum payload executes**:

| # | Code | Check |
|---|---|---|
| 0 | `bad_config` | `ExecConfig.Valid()` — non-degenerate denominators, ordinary capacity > 0, positive floor |
| 1 | `companion_missing` | companion data present |
| 2 | `companion_unauthenticated` | `VerifyCompanionWitnesses` passes (see above) |
| 3 | `rootinput_invalid` | the decoded `rootInput` passes D1 `RootInput.Validate` |
| 4 | `context_mismatch` | `rootInput`'s network/partition/shard, authorized round and parent hash equal the block header context |
| 5 | `extradata_mismatch` | `header.extraData == SHA-256(CBOR(canonical rootInput))` |
| 6 | `seal_outcomes_shape` / `seal_outcome_root_mismatch` | the seal-outcome list starts with the system op, the rest are forced, and `header.sealOutcomeRoot == SHA-256(CBOR(list))` (§3) |
| 7 | `system_*` | the privileged operation (§1); `outcome[0].Status == 1` |
| 8 | `base_fee_below_floor` / `withdrawals_nonempty` / `blob_tx_present` | §4 |
| 9 | `gas_budget` | §3 |

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

### Companion retention on sync

- A node importing via devp2p receives `sealCompanion` in the block-gossip
  envelope (`ProposalEnvelope` gains a `sealCompanion` field). A node syncing
  historical blocks fetches companions from the archival proof service (F7)
  keyed by `(network, partition, shard, blockHash)`.
- A full node **retains every companion** it has certified, indefinitely, next to
  the block/UC association (D6 §"proof export"); a pruned node publishes its
  retention horizon and serves `unavailable` past it. A block whose companion
  cannot be produced on request is not re-servable and cannot be used as a
  historical proof subject, but this does not un-certify it.

## 3. Gas, header, receipts, tracing, EIP-1559

Two quantities that implementations routinely conflate are kept distinct:

| Quantity | Definition | Feeds |
|---|---|---|
| **header `gasUsed`** | `g_system_actual + g_forced_actual + g_ordinary_actual` | receipts (`cumulativeGasUsed`), tracing, block-fullness reporting |
| **base-fee feedback input** | `g_ordinary_actual` only | the EIP-1559 next-base-fee update |

Rationale: the system operation and the forced-inclusion prefix are
protocol-mandated work, not a congestion signal. Counting them toward the
base-fee target would push fees up purely because the protocol did its job.

### Budgets

```
g_sys + g_fi + g_ordinary_capacity = g_max          (exact; g_max is the header gas limit)
g_ordinary_capacity = g_max - g_sys - g_fi
g_system_actual   <= g_sys        (else block invalid)
g_forced_actual   <= g_fi
g_ordinary_actual <= g_ordinary_capacity
```

`g_fi = 0` until the forced inbox is enabled; the split still closes.

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

### The seal-outcome list — protocol operations stay OUT of the tx/receipt trie

The earlier draft inserted a synthetic receipt at index 0 with no corresponding
transaction, and treated an intrinsically invalid forced entry as an EVM revert.
Both change Ethereum receipt semantics. Instead:

- **Ordinary transactions keep standard semantics, unchanged.**
  `transactionsRoot` / `receiptsRoot` cover **only** the discretionary RLP
  transactions; their indices, `transactionHash`, `cumulativeGasUsed`, revert
  handling and proof/lookup behaviour are exactly Ethereum's. The system op and
  every forced entry are **not** in the transaction list.
- The system op and the forced prefix are recorded in a separate **seal-outcome
  list**, committed by a **`sealOutcomeRoot`** = `SHA-256(CBOR([o₀, o₁, …]))`
  carried in a header sibling field (and, transitively, under the `extraData`
  root-input commitment via the companion). Each `SealOutcome` is
  `{kind, gasUsed, status, reason, digest}` — **not** an RLP receipt:

  | Index | `kind` | Meaning |
  |---|---|---|
  | 0 | `system` | the privileged seal call. `status` must be `1`; `status 0` ⇒ block invalid. `digest` = `extraData` |
  | 1..k | `forced` | an executed forced entry (`status 1`, or `status 0` for an executed-and-reverted transaction — ordinary EVM semantics apply to its execution) |
  | 1..k | `forced_rejected` | an entry **intrinsically invalid at its turn** (nonce already used / insufficient balance / fee cap below base fee / incompatible rules). It is **consumed** with an authenticated `reason` and `status 0`. It is **never** an EVM revert and never enters the transaction list. |

- **Lookup / proof**: an inclusion proof for an ordinary transaction is a
  standard receipts-trie proof. An inclusion/outcome proof for the system op or a
  forced entry is a position proof against `sealOutcomeRoot` (in the companion
  data / archival proof service — D6/F7). The two proof surfaces are disjoint.
- `header.gasUsed` still totals `system + forced + ordinary` — a header field, no
  semantic change. `debug_trace*` replays system → forced → ordinary.
- Vectors: `seal_outcome_list` (system + `forced_rejected` + `forced`, one
  `sealOutcomeRoot`, `ordinary_tx_count` excludes all three, gas closes);
  `import_checks` `system_not_first_outcome`, `seal_outcome_root_mismatch`,
  `seal_outcomes_empty`, `system_outcome_status_zero`.

### Worked build → import → replay example (`gas_accounting` vector)

```
config:  g_max 30_000_000   g_sys 2_000_000   g_fi 0
         g_ordinary_capacity 28_000_000   ordinary_target 14_000_000
build:   engine_forkchoiceUpdatedWithSealV1(fc, attrs, {rootInput, transitions:[]})
         -> system op (index 0) writes the seal registry, gasUsed 1_800_000
         -> ordinary txs fill to gasUsed 15_000_000
         header.gasUsed = 16_800_000   header.extraData = SHA-256(CBOR(rootInput))
         getPayloadWithSealV1 -> { payload, sealCompanion:{rootInput, witnesses, provenance:"build"} }
import:  engine_newPayloadWithSealV1(payload, [], beaconRoot, sealCompanion)
         steps 0-5 pass; reth re-executes -> same stateRoot/blockHash -> VALID
replay:  recovered ordinary gas = 16_800_000 - 1_800_000 - 0 = 15_000_000
         parent_base_fee 1_000_000_000
         numerator = 15_000_000 - 14_000_000 = 1_000_000
         delta = floor(1e9 * 1_000_000 / 14_000_000) / 8 = floor(71_428_571 / 8) = 8_928_571
         next_base_fee = 1_008_928_571   (>= 7, <= 2^62)
```

## 3a. Deviation inventory (minimal-divergence review)

Every enshrined-EVM deviation from stock Ethereum / stock Engine API, why the
simpler alternative was not enough, and its conformance test. The owner approves
or amends this table before D2 freezes.

| # | Deviation | Simpler alternative considered | Why it does not suffice | Audit surface | Conformance |
|---|---|---|---|---|---|
| 1 | Privileged **system call** (`a_sys → a_sr`, no key/nonce, first, failure ⇒ invalid block) | a genesis pre-deploy that a normal transaction pokes each block | a normal transaction needs a funded EOA + nonce, can be reordered or censored, and cannot be *mandatory*; the authenticated root input must be un-forgeable and un-replayable | the one privileged origin; import validation predicates | `import_checks` `system_*`; `TestD2_SystemCallMustBeFirstAndValid` |
| 2 | **`extraData` = 32-byte `SHA-256(CBOR(rootInput))`** commitment | put the root input in a standard payload attribute | V3 `PayloadAttributesV3` has no field for it and it must be in the *header* so it is covered by the block hash; witnesses do not fit in `extraData` | 32 bytes of header; the D1 encoder | D1 vectors + `TestExtraData_IndependentOracle` |
| 3 | **`sealOutcomeRoot`** header sibling + seal-outcome list | reuse `receiptsRoot` with synthetic receipts | synthetic receipts change Ethereum receipt semantics and mislead every existing tool/proof; keeping protocol operations out of the tx/receipt trie is the *smaller* change | one header field; `SealOutcomeRoot` CBOR | `seal_outcome_list`; `TestD2_SealOutcomeListSeparateFromTxList` |
| 4 | **Ordinary-only EIP-1559 feedback** (`g_sys`, `g_fi` excluded from the base-fee target) | feed total `gasUsed` into the London formula | protocol-mandated gas is not a demand signal; including it raises fees purely because the protocol ran | `NextBaseFee` + `RecoverOrdinaryGas` | `TestD2_BaseFeeUpdateExcludesSystemAndForcedGas`, `base_fee_arithmetic_oracle` |
| 5 | **Positive base-fee floor** `f_base^min` as a validity rule | genesis initial base fee only | a floor that is only a genesis value can be driven to 0 by sustained under-target blocks, breaking fee-market and DoS assumptions | one comparison per block | `import_checks.base_fee_below_floor` |
| 6 | **Three `engine_*WithSealV1` siblings** (fcU / newPayload / getPayload) | a single new method, or overload existing V3 params | build needs `{rootInput, transitions}` in the fcU→getPayload flow; import needs the full witness set in newPayload; getPayload must return the companion for dissemination — the three flows carry different data | the Engine API surface (JWT-authenticated) | capability check in `engineapi/adapter.go`; negative auth fixtures |
| 7 | **Companion retention + archival serving** | rely on devp2p re-gossip | historical import and proof export need the witness after gossip has aged out; a retention horizon is published so this is a bounded obligation, not "keep everything forever" | node storage policy | D6 §"proof export"; retention-horizon vector (F7) |
| 8 | **RPC parity** for `eth_call` / tracing (same fee split, no privileged-state authorisation) | leave RPC unchanged | a local simulation that used a different fee split or could call `a_sys` would diverge from consensus / leak authority | RPC handlers | §5; assertion in the model |

Deviations 1–5 are execution-client changes; 6–8 are Engine API / adapter
changes. None changes ordinary transaction, receipt or trie semantics.

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
| the authentication lifecycle is finished — the verdict is not an untrusted companion assertion | §2 "authentication lifecycle"; `VerifyCompanionWitnesses` (own trust base, recomputed threshold, `OriginID` binding, transition-proof count); negatives `witness_wrong_origin`, `witness_below_threshold`, `witness_unknown_signer`, `witness_transition_proof_count`, `malformed_origin_breaks_witness`; `TestD2_AuthenticationBoundary` |
| A gas accounting vector closes exactly | `gas_accounting.closes_exactly = true`; §3 worked example; `TestD2_GasBudgetInvariant`, `TestD2_HeaderGasUsedIsTheSum` |
| the frozen fee arithmetic stays exact for representable values | `NextBaseFee` via 128-bit `mulDivFloor`; `base_fee_arithmetic_oracle` (big.Int cross-check incl. parent `10^13`); `ExecConfig.Valid()`; `TestD2_NextBaseFeeNoOverflow`, `TestD2_ConfigValidation` |
| receipt indexing / block semantics resolved | §3 "seal-outcome list" — protocol operations stay OUT of `transactionsRoot` / `receiptsRoot`; system op + forced entries committed by `sealOutcomeRoot`; ordinary tx/receipt semantics unchanged; canonical block vector `seal_outcome_list` (poison + valid forced); `import_checks` `system_not_first_outcome`, `seal_outcome_root_mismatch`; `TestD2_SealOutcomeListSeparateFromTxList` |
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
