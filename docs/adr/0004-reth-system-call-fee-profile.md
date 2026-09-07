# ADR 0004: Reth system-call and fee profile (D2, v1)

## Status

Proposed (D2, issue #4). Revised twice:

- After review #78: a verified-input boundary, 128-bit fee arithmetic +
  `ExecConfig.Valid()`, concrete `engine_*WithSealV1` methods.
- After re-review #78: a **deviation inventory** (§3a); a `sealOutcomeRoot`
  header sibling committing a seal-outcome list; a finished authentication
  lifecycle.

- After the third review #78:
  - **No new header field, and the standard execution-evidence path is kept.**
    A **successful forced transaction is an ordinary transaction** —
    `transactionsRoot` / `receiptsRoot` with a standard receipt (logs, bloom,
    cumulative gas), so its events export through the normal receipt proof. Only
    the privileged seal call and **rejected** forced-inbox entries are off-trie,
    committed by `sealRegistryCommitment` — a value the system call writes into
    the **seal-registry contract's storage**, authenticated by the block's
    `stateRoot` and provable with `eth_getProof`. The false "transitively under
    `extraData`" claim is withdrawn; `extraData` hashes only the rootInput.
    `header.gasUsed` transparently includes the mandated `g_sys` work (not
    "unchanged").
  - **`VerifyCompanionWitnesses` verifies proof bindings, not assertions.** No
    `threshold` parameter — it is derived. (Superseded below.)

- After the fourth review #78:
  - **Verify the existing certificate, don't invent a root signature.** The
    third-review `D2SealWitnessStatement` (a new message for root validators to
    sign) is removed. `VerifyCompanionWitnesses` now consumes **D1's
    `VerifiedCert`** — the real `types.UnicityCertificate` verified against the
    trust base for its epoch (`UnicitySeal.Verify`: signatures **and** quorum,
    plus inclusion paths and `tr.Hash()`) — through D1's `ValidateBoundCertificate`.
    It is an explicit **verified external precondition**; the certificate →
    `VerifiedCert` mapping is exercised through bft-go-base's real verifier in
    `TestD2_CertificateBoundaryFixtures` (positive quorum subset / negative
    sub-quorum subset). D2 no longer holds root keys or has a signing obligation.
  - **Transition contents are authenticated.** A second verified input,
    `ExpectedTransitions` — the verifier's authenticated ordered committed-body
    sequence. `ri.Transitions` must equal it byte-for-byte, position by
    position; substitution, reordering, omission and replay all fail (a
    byte-count check does not).
  - **The commitment is written after the forced prefix.** The first system call
    is presence-only. A post-prefix `FinalizeStep` (a second privileged
    operation, gas-charged against `g_sys`) writes `sealRegistryCommitment` over
    the outcomes determined **at each forced entry's turn** — because a prior
    valid forced tx can change a later entry's pre-state, and a future-outcome
    input to the first call would be contract-readable. `ValidateImport`
    re-derives the outcomes (`evalForcedPrefix`) and checks the finalized
    commitment and the storage value against them.

- After the fifth review #78:
  - **The finalizer gas is bound to the checked budget.** `ValidateImport`
    (`reconcileWork`) **derives** `Work.System = SystemCall.GasUsed +
    Finalize.GasUsed` (overflow-checked) and `Work.Forced = turn-rejected count *
    RejectedConsumptionGas`, rejects a caller-supplied `Work` that does not match
    (`gas_split_unreconciled`), and runs `CheckGas` on the **derived** work so the
    combined `g_sys` cap covers open + finalize. Ordinary-gas recovery nets out
    both `g_sys` steps. The `gas_accounting` vector and the §3 worked example
    show the open/finalize split. An independently supplied `Work.System` /
    `Work.Forced` can no longer hide an over-budget finalizer or defeat the
    `g_sys` / `g_fi` split.
  - `VerifiedCert` / `ExpectedTransitions` are **verifier-owned**, not
    peer-deserialized; full UC inclusion / config / TR / committed-body
    derivation is a mandatory adapter integration test before F1.

- After the sixth review #78:
  - **A valid forced transaction's execution gas draws on the reserved `g_fi`
    budget, not ordinary capacity.** The fifth-review model counted a successful
    forced tx's gas in `Work.Ordinary` and derived `Work.Forced` from rejected
    entries only, so with `g_fi` never consumed by successful entries,
    discretionary demand filling `g_ordinary_capacity` could make a D5-admitted
    forced transaction (`declaredGas ≤ g_fi`) unincludable while the whole `g_fi`
    reservation sat unused — a valid 9M forced tx was rejected under a 20M `g_fi`
    / 8M ordinary-capacity profile with an otherwise empty block. `reconcileWork`
    now derives `Work.Forced = Σ ExecGas(forced entries valid at their turn — a
    valid entry that EVM-reverts included) + turn-rejected count ×
    RejectedConsumptionGas` and `Work.Ordinary = DiscretionaryGasUsed` (the Σ
    receipt gasUsed of the NON-forced transactions), overflow-checked, and
    reconciles `Work.System` / `Work.Forced` (`gas_split_unreconciled`).
    `ForcedEntry` gains `DeclaredGas` (the D5 admission limit, `≤ g_fi`) and
    `ExecGas` (`≤ DeclaredGas`); a turn-rejected entry carries no `ExecGas`; the
    count of forced txs in the receipt trie must equal the turn-valid set
    (`forced_tx_count_mismatch`). `CheckGas` caps the derived `g_forced_actual`
    at `g_fi`. Forced-tx gas is now genuinely outside the EIP-1559 loop, and
    ordinary-gas recovery nets out the full `g_forced_actual`. New:
    `forced_prefix_accounting` vector (mixed success / EVM-revert / rejected),
    the `forced_prefix_*` / `forced_declared_over_g_fi` /
    `forced_gas_charged_to_discretionary` import checks,
    `TestD2_ForcedPrefixGasUsesReservedBudget`,
    `TestD2_ForcedTxCountMustMatchTurnValidSet`,
    `TestReview6SuccessfulForcedPrefixUsesReservedCapacity`. D2 §3 and D5 §4 are
    reconciled — D2 charges each executed prefix entry's gas against the same
    `g_fi` D5 admits it under.

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
   All three buckets are **derived** by `reconcileWork` from block content, not
   taken from a caller-supplied `Work` total; `Work.System` / `Work.Forced` are
   reconciled and a mismatch is `gas_split_unreconciled`:
   - `g_system_actual` = `SystemCall.GasUsed + Finalize.GasUsed` (both `g_sys` steps);
   - `g_forced_actual` = `Σ ExecGas` of the forced entries valid at their turn
     (a valid entry that EVM-reverts included) + turn-rejected count × charge —
     charged against the reserved `g_fi`, **never** ordinary capacity;
   - `g_ordinary_actual` = `DiscretionaryGasUsed`, the Σ receipt gasUsed of the
     NON-forced transactions.
   Header `gasUsed` = the sum. The EIP-1559 update uses `g_ordinary_actual`
   against an ordinary target only; protocol-mandated gas — the system steps
   **and** all forced work — is recovered as
   `header.gasUsed − (open + finalize) − g_forced_actual`.

3b. **Off-trie commitment in contract state, not a header field, written after
   the forced prefix** — a successful forced transaction is an ordinary
   transaction with a standard receipt. Only the system ops and `forced_rejected`
   records are off-trie. The first system call is presence-only; a post-prefix
   `FinalizeStep` (gas-charged against `g_sys`) writes `sealRegistryCommitment`
   over the outcomes determined at each forced entry's turn into seal-registry
   contract storage (authenticated by `stateRoot`, `eth_getProof`).

3c. **Authentication consumes verified inputs.** `VerifyCompanionWitnesses`
   consumes D1's `VerifiedCert` (the real `UnicityCertificate` verified against
   the trust base — signatures, quorum, inclusion paths, `tr.Hash()`) via
   `ValidateBoundCertificate`, checks `SHA-256(CBOR(TE_-)) == O_-.TRHash`, and
   requires `ri.Transitions` to equal the authenticated `ExpectedTransitions`
   position by position. D2 invents no root signature and holds no root keys.

4. **Validity rules** — positive base-fee floor `f_base^min` checked every block;
   withdrawals always empty; blob transactions disabled; no protocol issuance.

5. **RPC** — `eth_call`/`estimateGas`/tracing apply the same system/fee rules;
   no RPC caller can authorise a privileged canonical state change.

## Deliverables

- `evmroot/d2gas.go` — budgets, header `gasUsed`, EIP-1559 update with the
  ordinary-only substitution and the floor clamp; `BlockWork.System` / `.Forced`
  / `.Ordinary` are DERIVED (see `d2import.go` `reconcileWork`);
  `RecoverOrdinaryGas` nets out both `g_sys` steps and the full `g_forced_actual`.
- `evmroot/d2import.go` — the ordered import-validation predicate set with stable
  rejection codes; `SealRegistryCommitment` (contract-state value);
  `FinalizeStep` + `ForcedEntry` (now with `DeclaredGas` / `ExecGas` / `Reverted`)
  / `evalForcedPrefix` / `DerivedSealOutcomes` (turn-determined outcomes);
  `SealBlock.DiscretionaryGasUsed`; `reconcileWork` (derives `Work.System` /
  `Work.Forced` / `Work.Ordinary`, overflow-checked, `gas_split_unreconciled`);
  `forced_tx_count_mismatch` and `forced_declared_over_g_fi` predicates;
  `VerifyCompanionWitnesses(witness, rootInput, lastAppliedRootRound)` consuming
  D1's `VerifiedCert` via `ValidateBoundCertificate`, the TE↔TRHash binding, and
  position-by-position `ExpectedTransitions` matching. (The invented `d2seal.go`
  seal-witness statement + keys are removed.)
- `evmroot/testdata/d2-vectors.json` — exec config, a `gas_accounting` vector
  that shows the open/finalize split and closes exactly, the
  `forced_prefix_accounting` vector (a mixed success / EVM-revert / rejected
  forced prefix under `g_fi = 20M`: valid-entry `ExecGas` charged to `g_fi`,
  discretionary gas from receipts only, header closes, base fee ignores forced
  work, the 9M/20M/8M counterexample), a base-fee series (up/flat/down/floor),
  the `seal_outcome_list` vector (a sequential forced prefix where entry 1
  changes entry 2's turn-validity; entry 1 stays ordinary, its `ExecGas` charged
  to `g_fi`; commitment written post-prefix), and import-check vectors including
  `cert_not_verified`, `cert_stale_root_round`, `transition_inserted_body`,
  `transition_substituted_body`, `seal_finalize_missing`,
  `finalize_wrong_commitment`, `finalizer_gas_hidden_from_work`,
  `work_system_mismatch`, `work_forced_mismatch`, `combined_system_over_g_sys`,
  `system_plus_finalize_overflow`, `forced_prefix_uses_reserved_capacity`,
  `reverted_forced_tx_uses_reserved_capacity`, `forced_prefix_over_g_fi`,
  `forced_declared_over_g_fi`, `forced_gas_charged_to_discretionary`,
  `forced_exec_over_declared`, `forced_tx_count_drops_admitted_entry`,
  `rejected_entry_carries_exec_gas`.
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
- **Synthetic receipts in `receiptsRoot` for protocol operations.** Rejected:
  changes Ethereum receipt semantics and misleads every tool/proof.
- **A new `sealOutcomeRoot` header field (second-review version).** Rejected on
  the third review: it expands every client's header/import/RPC surface, needs a
  normative RLP position + block-hash derivation, is not covered by `extraData`,
  and removing successful forced txs from `receiptsRoot` loses their standard
  log/receipt proof. A **contract-state value** committed by the system call
  reuses the authenticated `stateRoot` + `eth_getProof` path and keeps successful
  forced txs ordinary.
- **A caller-supplied threshold / signer-name list for `VerifyCompanionWitnesses`.**
  Rejected: a supplied threshold can be 1 and a name is not a signature.
- **A new root-quorum message (`D2SealWitnessStatement`) for validators to sign
  (third-review version).** Rejected on the fourth review: the existing
  `UnicitySeal` signatures cover `SigBytes()` and cannot be reused over a new
  message, and an adapter cannot mint root-quorum signatures — this would become
  a new signing obligation / attestation layer. D2 consumes D1's `VerifiedCert`
  (the real verifier's verdict) as an explicit verified precondition instead.
- **Authenticate committed transition bodies by proof count / non-emptiness.**
  Rejected: an inserted body with a one-byte "proof" passes. `ri.Transitions`
  must equal the verifier's authenticated `ExpectedTransitions` byte-for-byte.
- **Write `sealRegistryCommitment` in the first system call.** Rejected: a prior
  valid forced tx changes a later entry's pre-state, so the rejection set is not
  determinable before the prefix runs; and a future-outcome input would be
  contract-readable. The commitment is written by a post-prefix `FinalizeStep`.
- **Take `Work.System` / `Work.Forced` from a caller-supplied total and check it
  with `CheckGas`.** Rejected on the fifth review: a finalizer over the whole
  `g_sys` budget imported successfully because nothing tied `Work.System` to
  `SystemCall.GasUsed + Finalize.GasUsed`. Both are now derived (`reconcileWork`),
  a mismatch is rejected, and the `g_sys` cap is applied to the derived sum.
- **Charge a successful forced transaction's execution gas to ordinary capacity
  (fifth-review model).** Rejected on the sixth review: with `g_fi` then consumed
  only by *rejected* entries, discretionary demand filling `g_ordinary_capacity`
  could permanently exclude a forced transaction the D5 inbox had admitted
  (`declaredGas ≤ g_fi`) — the reservation protected nothing it was for (a valid
  9M forced tx rejected under 20M `g_fi` / 8M ordinary capacity, empty block).
  `g_forced_actual` is now `Σ ExecGas` of the valid prefix (EVM-reverting entries
  included) + rejected charges, charged against `g_fi`; `g_ordinary_actual` is
  `DiscretionaryGasUsed` (NON-forced receipt gas) only. Any alternative policy
  must revise D5 admission, reservation, `K` and the fee rationale together.
