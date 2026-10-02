# Later amendment: validator-entity model and launch scope

Status: accepted owner decisions of 2026-10-01; decision [ADR 0012](../../../adr/0012-validator-entity-model.md).
This is a Markdown amendment, not a recompiled yellowpaper. The seven `.tex` files and `repair.patch` stay
exactly as the snapshot; read the snapshot first, then accepted D/F-series amendments, then this amendment
for the passages it names. Where this text and the snapshot differ, this text governs.

## A. Superseded passages (each checked against the snapshot text)

| Where (snapshot) | Snapshot says | Governs now |
|---|---|---|
| `governance.tex`, introduction (PoS activation) | Authoritative PoS is activated only after weighted consensus, the epoch handoff, objective slashing, retirement protection, **forced inclusion** and checkpoint recovery are enabled and validated together. | Forced inclusion (roadmap I-track) is **deferred**: it is not a prerequisite of the PoA launch or of PoS shadow. Its D5 design stays as a reference. Reinstating it for authoritative PoS needs a new owner decision and an activation gate. |
| `governance.tex`, "Evidence" item | "A bounded forced-inclusion path protects access against an EVM producer." | A node fully trusts its co-hosted EVM node; defenses are across validators and peers. Evidence submission uses ordinary inclusion until the I-track is reinstated. |
| `governance.tex`, Slashing paragraph | "the forced inbox can preserve a timely commitment while execution is delayed." | Same as the row above. |
| `governance.tex`, Registry paragraph | The registry binds a staking account to **owner and consensus-key roles**; registration proves possession of **each** signing key. | A validator is authenticated at the top level **only by its BFT Core consensus key**; P3 binds only the root key. EVM and signing-authority keys are delegated and procedural, are not shared with the co-hosted BFT Core process, and are not separate staking-registry roles. |

Passages checked and **left as they are** because they already agree: `evm-partition.tex` ("the EVM uses exactly the same
effective weights as the root assignment"), `governance.tex` Proof of Authority (all effective weights 1), and the
handoff passages of `governance.tex`/`bft.tex` (the assignment changes through the committed root handoff).

## B. Statements this amendment adds (no snapshot passage to replace)

1. **Weights.** PoS weights exist only at the root/validator-entity level. The EVM shard mirrors root weights; aggregator
   shards are unweighted (unit stake). Roadmap Q2 and Q3 shrink to that scope.
2. **Coupled changes.** A validator-set change is one handoff that changes the BFT Core committee and the EVM assignment
   together; an EVM-only rotation is not a supported operation (ADR 0006 as amended, H3 design and runbook).
3. **Proofs.** Only certified positive execution proofs are required from the EVM; absence proofs are not a requirement and
   receive no further work (existing code may stay). Bridge-side nullifier non-membership is a separate bridge
   data-structure check and is not changed here.
4. **Aggregator shards at launch** run centrally with `proof_type` none; the trust-assumption disclosure in ADR 0012 is part
   of this amendment.
5. **Reconfiguration.** New aggregator partitions and shard splits happen only at a BFT Core epoch boundary, ordered by
   root consensus in the same handoff record, never by a per-root-node HTTP PUT; operator-sourced at launch, later possibly
   EVM-contract-sourced.
6. **Broad F7** (public RPC, SDK, account/storage proofs, permanent-storage service) belongs to the bridge track B5
   ([#66](https://github.com/ristik/bft-core/issues/66)); F7's receipt-complete archive and positive-proof export stay in M2.

## Application order

1. Snapshot (`.tex`, `repair.patch`). 2. D/F-series amendments (for example ADR 0010). 3. This amendment.
The roadmap and issue index carry the ticket-level consequences.
