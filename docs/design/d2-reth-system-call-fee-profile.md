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
  object, not a blob), its authentication witnesses (the authorising UC, its
  tree paths, and the transition proofs for `D`), and the caller's
  **authentication verdict**. Witnesses authenticate `rootInput` / `D`; they are
  **not** re-hashed into the commitment.

### Verified-input boundary (ordered predicates)

`ValidateImport` runs, in this fixed order — a block that fails any step is
invalid **regardless of whether its Ethereum payload executes**:

| # | Code | Check |
|---|---|---|
| 0 | `bad_config` | `ExecConfig.Valid()` — non-degenerate denominators, ordinary capacity > 0, positive floor |
| 1 | `companion_missing` | companion data present |
| 2 | `companion_unauthenticated` | `Authenticated == true` **and** witnesses non-empty — the caller has verified the witnesses against committed certificate/transition state (D1 `ValidateBoundCertificate` + D3 signature verification + transition proofs). Executing the payload authenticates nothing. |
| 3 | `rootinput_invalid` | the decoded `rootInput` passes D1 `RootInput.Validate` (version, epoch boundary, digest widths, genesis nulling) |
| 4 | `context_mismatch` | the decoded `rootInput`'s network/partition/shard, authorized round and parent hash equal the block header context — a valid `rootInput` for a **different** block cannot be spliced in |
| 5 | `extradata_mismatch` | `header.extraData == SHA-256(CBOR(canonical rootInput))` |
| 6 | `system_*` | the privileged operation (§1) |
| 7 | `base_fee_below_floor` / `withdrawals_nonempty` / `blob_tx_present` | §4 |
| 8 | `gas_budget` | §3 |

`rootInput = []byte{0x80}` (or any blob) never reaches step 5: it is not a
structured `RootInput`, so it cannot be presented, and an unauthenticated
companion fails at step 2.

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

### Receipts and tracing — exact convention

The system operation is not an EOA transaction but it occupies **receipt index
0** and contributes to the block's receipts trie:

| Field | Value |
|---|---|
| `transactionHash` | `SHA-256("UNICITY_EVM_SEAL_TX" ‖ header.extraData)` — deterministic, unique per block, distinct from any RLP transaction hash |
| `transactionIndex` | `0` |
| `type` | a reserved receipt type `0x7e` (system), never a user tx type |
| `status` | `1` — a failed system op invalidates the block, so a `0` system receipt never appears in a valid block |
| `gasUsed` | `g_system_actual`; `cumulativeGasUsed` = `g_system_actual` |
| `from` / `to` | `a_sys` / `a_sr` |
| `logs` / `logsBloom` | the seal-registry-write events; folded into `header.logsBloom` and the receipts-trie leaf at index 0 |
| `effectiveGasPrice` | `0` — fee-exempt, no fee payer debited |

Forced-inclusion entries (when `g_fi > 0`) follow at indices `1 .. k`, are
**real RLP transactions** with ordinary receipts and ordinary
`transactionHash`es, and `cumulativeGasUsed` accrues normally. A forced entry
that is **invalid at its turn** (nonce/balance/fee-cap — D5) is consumed with a
`status = 0` receipt and an authenticated rejection reason in its logs; it is
distinct from an *executed-and-reverted* transaction only by that reason code,
not by receipt shape. Ordinary user transactions follow at indices `k+1 ..`.

`receiptsRoot` is the Merkle-Patricia root over `[system, forced…, ordinary…]` in
that order; `debug_trace*` replays the same order.

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
| design traces one block through builder, follower, devp2p/sync and re-execution | §2 concrete methods (`engine_*WithSealV1`) + retention rule; §3 worked build→import→replay example; `ValidateImport` is path-independent |
| … including missing companion data and a forged ordinary system sender | `import_checks`: `companion_missing`, `companion_unauthenticated`, `system_origin_forged`; `TestD2_MissingCompanionDataIsFatal`, `TestD2_UnauthenticatedOrInvalidRootInputRejected`, `TestD2_SystemCallMustBeFirstAndValid` |
| a verified-input boundary — arbitrary bytes + matching self-hash cannot pass authentication | §2 ordered predicates; companion carries the **structured** `rootInput`, `Authenticated` + witnesses required, D1 `Validate` + header-context match before the commitment check; `import_checks.rootinput_invalid`, `context_mismatch_*`, `spliced_rootinput_for_other_block` |
| A gas accounting vector closes exactly | `gas_accounting.closes_exactly = true`; §3 worked example; `TestD2_GasBudgetInvariant`, `TestD2_HeaderGasUsedIsTheSum` |
| the frozen fee arithmetic stays exact for representable values | `NextBaseFee` via 128-bit `mulDivFloor`; `base_fee_arithmetic_oracle` (big.Int cross-check incl. parent `10^13`); `ExecConfig.Valid()`; `TestD2_NextBaseFeeNoOverflow`, `TestD2_ConfigValidation` |
| system work affects capacity/gasUsed/receipts/tracing/EIP-1559 target — no independent choice | §3 table + budgets + exact receipt convention (index 0, `type 0x7e`, `transactionHash = SHA-256("UNICITY_EVM_SEAL_TX" ‖ extraData)`) + `RecoverOrdinaryGas`; `TestD2_BaseFeeUpdateExcludesSystemAndForcedGas`, `TestD2_RecoverOrdinaryGas` |
| positive base-fee floor as a validity rule | §3; `import_checks.base_fee_below_floor`; `TestD2_BaseFeeClampsToPositiveFloor` |
| how invalid forced entries differ from executed/reverted transactions | §3 "Receipts and tracing" — `status = 0` + authenticated rejection reason vs a normal reverted receipt |
| empty withdrawals, blobs disabled | §4; `import_checks.withdrawals_nonempty`, `import_checks.blob_tx_present` |
| same pinned rules in eth_call/tracing without RPC-authorised privileged state changes | §5 |
| activation / version compatibility | §2 capability strings + startup check |

## 7. Reproduce

```
go test ./evmroot/... -run TestD2
go run ./evmroot/cmd/d2vectors            # print the vector set
go run ./evmroot/cmd/d2vectors -update    # regenerate testdata/d2-vectors.json
```
