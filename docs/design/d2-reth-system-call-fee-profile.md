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

## 2. Header commitment and companion data

- The header's `extraData` is exactly `SHA-256(CBOR(rootInput))` (D1 §3). 32
  bytes, checked on every block.
- The block's **companion data** carries the canonical `rootInput` and its
  authentication witnesses (the authorising UC, its tree paths, and the
  transition proofs for `D`). Witnesses authenticate `rootInput` / `D`; they are
  **not** re-hashed into the commitment.
- A block whose Ethereum payload executes but that **lacks companion data cannot
  be certified.** `companion_missing` is checked before anything else.
- Companion data is retained and served for import, synchronisation and proof
  export.

### Engine API extension

Stock Engine API V3 `PayloadAttributesV3` cannot carry the root input or its
witnesses, and `newPayloadV3` has no parameter for them. D2 defines a V3-family
extension (methods are `engine_*` V3 with an added structured field), used on
both the build and the import path:

```
engine_forkchoiceUpdatedV3  + sealRootInput: { rootInput: <cbor bytes>, transitions: [<cbor bytes>] }
engine_newPayloadV3         + sealCompanion: { rootInput: <cbor bytes>, witnesses: [<bytes>] }
engine_getPayloadV3         response carries the sealCompanion the leader must disseminate
```

- On **build**, the client is handed `rootInput` + `D`; it runs the system
  operation as the first step, writes `extraData`, and returns the payload plus
  the `sealCompanion` the leader disseminates.
- On **import** (`newPayloadV3` + follower/devp2p/re-execution), the client
  verifies `extraData == SHA-256(CBOR(sealCompanion.rootInput))`, verifies the
  witnesses against its committed certification/transition state, then executes
  the system operation with the **verified** input and checks every
  parent/round/header binding.
- Version/activation: the extension is gated by the partition `version` record;
  a client not advertising it fails the startup capability check (as
  `engineapi/adapter.go` `CheckCapabilities` already does for V3), so an
  incompatible execution client cannot start.
- Test vectors for `system_origin_forged` and `companion_missing` are in the
  `import_checks` vector group.

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

### EIP-1559

```
ordinary_target = g_ordinary_capacity / elasticityDenom        (London elasticityDenom = 2)
next_base_fee   = London_update(parent_base_fee, g_ordinary_actual, ordinary_target, changeDenom)
next_base_fee   = max(next_base_fee, f_base^min)                (positive floor — a validity rule)
```

- The **base-fee floor `f_base^min` is positive and validated on every block**;
  a block with `baseFee < f_base^min` is invalid (`base_fee_below_floor`).
- `gas limit` and `base fee` are fixed by the versioned execution configuration
  and checked independently of any builder preference.

### Receipts and tracing

- The system operation produces a receipt with `status = 1` (its failure
  invalidates the block, so a failed system receipt never appears in a valid
  block) and its own gas contribution to `cumulativeGasUsed`.
- Forced-inclusion entries produce ordinary receipts (a revert is a normal
  failed receipt; it still consumes gas).
- `debug_trace*` over a block reproduces system → forced → ordinary in that
  order.

### Worked example (`gas_accounting` vector, `closes_exactly = true`)

```
g_max = 30_000_000   g_sys = 2_000_000   g_fi = 0
g_ordinary_capacity  = 28_000_000        ordinary_target = 14_000_000
g_system_actual = 1_800_000   g_forced_actual = 0   g_ordinary_actual = 15_000_000
header gasUsed  = 16_800_000
parent_base_fee = 1_000_000_000
next_base_fee   = London_update(1e9, 15_000_000, 14_000_000, 8) = 1_008_928_571  (then >= 7)
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
| design traces one block through builder, follower, devp2p/sync and re-execution | §2 Engine API extension (all four paths); `ValidateImport` is path-independent |
| … including missing companion data and a forged ordinary system sender | `import_checks`: `companion_missing`, `system_origin_forged`; `TestD2_MissingCompanionDataIsFatal`, `TestD2_SystemCallMustBeFirstAndValid` |
| A gas accounting vector closes exactly | `gas_accounting.closes_exactly = true`; §3 worked example; `TestD2_GasBudgetInvariant`, `TestD2_HeaderGasUsedIsTheSum` |
| system work affects capacity/gasUsed/receipts/tracing/EIP-1559 target — no independent choice | §3 table + budgets + `TestD2_BaseFeeUpdateExcludesSystemAndForcedGas` |
| positive base-fee floor as a validity rule | §3; `import_checks.base_fee_below_floor`; `TestD2_BaseFeeClampsToPositiveFloor` |
| empty withdrawals, blobs disabled | §4; `import_checks.withdrawals_nonempty`, `import_checks.blob_tx_present` |
| same pinned rules in eth_call/tracing without RPC-authorised privileged state changes | §5 |
| activation / version compatibility | §2 "Version/activation" |

## 7. Reproduce

```
go test ./evmroot/... -run TestD2
go run ./evmroot/cmd/d2vectors            # print the vector set
go run ./evmroot/cmd/d2vectors -update    # regenerate testdata/d2-vectors.json
```
