# ADR 0004: Reth system-call and fee profile (D2, v1)

## Status

Proposed (D2, issue #4). Revised twice:

- After review #78: a verified-input boundary, 128-bit fee arithmetic +
  `ExecConfig.Valid()`, concrete `engine_*WithSealV1` methods.
- After re-review #78: a **deviation inventory** (§3a, 8 rows with alternatives /
  audit surface / conformance); the **seal-outcome list** — protocol operations
  are committed by a `sealOutcomeRoot` header sibling and stay **out** of
  `transactionsRoot` / `receiptsRoot`, so ordinary transaction/receipt semantics
  are unchanged and an intrinsically invalid forced entry is a
  `forced_rejected` record, never an EVM revert; the **authentication
  lifecycle** is finished — `VerifyCompanionWitnesses` runs against the
  verifier's own trust base with a **recomputed** threshold, and the per-path
  "who verifies" is stated (adapter over JWT for `newPayload`; re-run for devp2p
  / offline).

Freeze once re-reviewed by a Go-adapter + reth reviewer other than the author.
Depends on ADR 0003 (D1).

## Context

D1 fixes the canonical root input. D2 fixes what the execution client does with
it. The prototype adapter (`engineapi/`) drives stock Engine API V3 and has:

- no privileged system operation — it derives payload attributes but nothing
  executes a protocol call carrying the root input;
- no companion-data transport — `ProposalEnvelope` carries only the execution
  payload and an (always empty) blob-hash list;
- no reserved system gas budget, no base-fee floor, no separation of
  protocol-mandated gas from the EIP-1559 feedback loop;
- `BlockSize` computed from JSON length, explicitly acknowledged as non-canonical
  across implementations.

A second implementation (the reth fork, an offline re-executor) cannot agree with
it byte-for-byte. D2 is the gate that pins the missing rules.

## Decision

Adopt the profile in
[`docs/design/d2-reth-system-call-fee-profile.md`](../design/d2-reth-system-call-fee-profile.md):

1. **Privileged system operation** — first, exactly once, from fixed `a_sys` to
   fixed `a_sr`, value 0, no signature/nonce, not from the mempool. Failure or
   over-budget consumption invalidates the whole block. No private key
   originates it; a forged ordinary sender is rejected. Historical import and
   re-execution apply the identical rules.

2. **Header commitment + companion data** — `extraData = SHA-256(CBOR(rootInput))`
   (from D1); a V3-family Engine API extension carries `rootInput` + `D` on the
   build path and `rootInput` + witnesses on the import path. A block with no
   companion data cannot be certified even if its payload executes. Gated by the
   partition `version` record and the startup capability check.

3. **Gas separation** — `g_sys + g_fi + g_ordinary_capacity = g_max` exactly.
   Header `gasUsed` is the sum of system + forced + ordinary actual gas. The
   EIP-1559 base-fee update uses **ordinary** gas against an **ordinary** target
   only; protocol-mandated gas is outside the feedback loop.

4. **Validity rules** — positive base-fee floor `f_base^min` checked every block;
   withdrawals always empty; blob transactions disabled; no protocol issuance.

5. **RPC** — `eth_call`/`estimateGas`/tracing apply the same system/fee rules;
   no RPC caller can authorise a privileged canonical state change.

## Deliverables

- `evmroot/d2gas.go` — budgets, header `gasUsed`, EIP-1559 update with the
  ordinary-only substitution and the floor clamp.
- `evmroot/d2import.go` — the ordered import-validation predicate set with stable
  rejection codes.
- `evmroot/testdata/d2-vectors.json` — exec config, a gas-accounting vector that
  closes exactly, a base-fee series (up/flat/down/floor), and 12 import-check
  vectors including `system_origin_forged` and `companion_missing`.
- `evmroot/cmd/d2vectors` + `TestD2_VectorsMatchGolden`.

## Consequences

- `F3` (privileged call in reth) implements against this profile and these
  vectors; `F5` (fee rules / work budgets) consumes the gas model directly;
  `F4` (SealRegistry) consumes the companion-data / import path.
- The Engine API extension is a real fork change; the reth fork must carry it and
  advertise it in the capability exchange.
- `BlockSize`/`StateSize` canonicalisation (currently JSON length) is flagged for
  `F1`/`F5` — out of D2's scope but noted so it is not lost.

## Alternatives considered

- **Count system gas toward the EIP-1559 target.** Rejected: raises fees for
  protocol work, not congestion.
- **Carry the root input in `extraData` itself rather than a 32-byte commitment
  plus companion data.** Rejected: `extraData` is size-limited and the witnesses
  do not fit; the commitment + retained companion data is the standard split.
- **Reuse stock `PayloadAttributesV3` with the beacon-root field as a smuggling
  channel.** Rejected: the beacon root is already a derived D1 field; overloading
  it hides the input from import validation.
