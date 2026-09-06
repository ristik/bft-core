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
   Header `gasUsed` = ordinary cumulative gas (transaction list, including
   successful forced txs) + `g_sys` work + the `g_fi` consumption charge for
   rejected entries. The EIP-1559 base-fee update uses **ordinary** gas against
   an **ordinary** target only; protocol-mandated gas is outside the feedback
   loop and is recovered as `header.gasUsed − g_sys − rejectedConsumption`.

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
  ordinary-only substitution and the floor clamp.
- `evmroot/d2import.go` — the ordered import-validation predicate set with stable
  rejection codes; `SealRegistryCommitment` (contract-state value);
  `FinalizeStep` + `ForcedEntry` / `evalForcedPrefix` / `DerivedSealOutcomes`
  (turn-determined outcomes); `VerifyCompanionWitnesses(witness, rootInput,
  lastAppliedRootRound)` consuming D1's `VerifiedCert` via
  `ValidateBoundCertificate`, the TE↔TRHash binding, and position-by-position
  `ExpectedTransitions` matching. (The invented `d2seal.go` seal-witness
  statement + keys are removed.)
- `evmroot/testdata/d2-vectors.json` — exec config, a gas-accounting vector that
  closes exactly, a base-fee series (up/flat/down/floor), the `seal_outcome_list`
  vector (a sequential forced prefix where entry 1 changes entry 2's
  turn-validity; successful forced tx stays ordinary; commitment written
  post-prefix), and import-check vectors including `cert_not_verified`,
  `cert_stale_root_round`, `transition_inserted_body`,
  `transition_substituted_body`, `seal_finalize_missing`,
  `finalize_wrong_commitment`.
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
