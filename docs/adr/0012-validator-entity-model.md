# ADR 0012: Validator-entity model and launch scope (owner decisions of 2026-10-01)

## Status

Accepted: owner architecture decisions of 2026-10-01. This ADR records them in the repository
so that the roadmap, the specification amendments and the design documents can cite one place.
It changes no code, no wire format and no vector. Where an earlier ADR, design document or
roadmap ticket says otherwise, this ADR governs; each affected document carries a pointer here
(see "Documents amended" below, and [the specification amendment](../pos/specification/amendments/0012-validator-entity-model.md)).

## Decisions

1. **One validator is one organizational entity.** It runs a BFT Core node plus a co-hosted EVM
   execution client (reth) and helper processes. At the top level it is authenticated **only** by
   its BFT Core consensus key, listed in the current Unicity Trust Base entry (each new entry is
   signed by the previous set). PoA now, PoS later; both apply at this level only.
2. **Validator-set changes are always coupled.** One root handoff changes the BFT Core committee
   and the EVM assignment together. An EVM-only rotation is not a supported operation: the code may
   support it, but runbooks and lanes do not use it. Supersession of a failed successor stays.
3. **Co-hosted trust.** A BFT Core node fully trusts its co-hosted EVM node. Defenses are needed
   across validators and peers, not between a node and its own reth.
4. **Key separation.** The co-hosted BFT Core and EVM processes must not share private keys. EVM
   and signing-authority keys are delegated and procedural.
5. **Proofs.** Only certified **positive** execution proofs (something happened) are required from
   the EVM. Absence proofs are not a requirement: existing code may stay, but no further work goes
   into them.
6. **Weights.** PoS weights apply at the root/validator-entity level only. The EVM shard mirrors
   the root weights; aggregator shards are unweighted. Q2 and Q3 shrink accordingly, P3 binds only
   the root key, and the I-track (bounded forced inclusion) is deferred.
7. **Aggregator shards** run centrally at launch (aggregator-go is production; rugregator is
   experimental) **without consistency proofs** (`proof_type` none). The root certifies the
   transitions presented to it; the trust assumption is disclosed below. Data availability and
   backup, endpoint discovery and liveness are solved by aggregator-go or the payment gateway and
   are out of scope at this layer.
8. **Aggregator reconfiguration.** New aggregator partitions and shard splits happen **only at a
   BFT Core epoch boundary**. Configuration changes are ordered by root consensus, carried by the
   same epoch-boundary handoff record, never by a per-root-node HTTP PUT. At launch the source of a
   change is an operator (PoA); later it may be EVM smart contracts (slot auctions and the like).
   The data structures and data flows are to be prepared now.
9. **Broad F7** (public account/storage proof export, SDK and RPC) belongs to the bridge track
   (B5, [#66](https://github.com/ristik/bft-core/issues/66)). F7's receipt-complete archive and
   positive-proof export stay in the foundation.

## Trust-assumption disclosure: aggregator shards at launch

Aggregator partitions run with `proof_type` none and a central operator. The root and the BFT Core
certification protocol therefore give the following, and nothing beyond it. Code references are to
the integration branch at the time of this ADR.

**What the root checks before it certifies an aggregator round:**

- **Signatures from the configured keys.** Every counted certification request is signed by a key
  in the shard's installed configuration (`ShardInfo.ValidRequest` in
  `rootchain/consensus/storage/sharding.go`; `BlockCertificationRequest.IsValid`).
- **A count majority on one record.** More than half of the configured keys, one vote per key and
  unweighted (`GetQuorum`), signed the same input record, block size and state size
  (`IRChangeReq.Verify` in `rootchain/consensus/types/ir_change_request.go`). A key's second,
  different request in the same round is refused and not counted (`rootchain/request_buffer.go`);
  it is not recorded as evidence or penalised.
- **Chain continuity and binding.** The request's previous state hash equals the last certified
  state hash, its round and epoch equal the last technical record, its timestamp equals the last
  unicity seal's, and the input record is well formed (a block hash exactly when the state hash
  changes). Every root validator re-verifies the change request instead of trusting the root
  leader (`rootchain/consensus/ir_change_req_verifier.go`).
- **Configuration binding.** The certificate carries the configuration hash the root has installed
  for the shard and is sealed by the root committee of its epoch. Under the handoff profile that
  configuration is the genesis one or one activated by a committed root handoff at its boundary
  (`rootchain/consensus/storage/assignment.go`); a per-node `PUT /api/v1/configurations` is
  refused (`cli/ubft/cmd/root_node.go`, `rootchain/partitions/orchestration.go`). New aggregator
  partitions and shard splits are not yet carried by the handoff record (decision 8: to be prepared).
- **Order.** Each certified state extends the previous certified state of the same partition and
  shard, so certified states form one chain; a later certificate for the same round only repeats
  the same input record (repeat UC), never a different state.

**What the root does not check:**

- **The correctness of the state transition.** With `proof_type` none the root uses the
  `NoOpVerifier` (`rootchain/consensus/zkverifier/registry.go`), and `verifyZKProof` returns before
  reading any proof (`rootchain/node.go`). The root sees only the previous and new state roots, the
  block hash and the summary; it never sees the SMT leaves or the block. It certifies the transition
  presented by the signing quorum, it does not verify that the transition is valid under the
  aggregator's rules.
- **Data availability.** Nothing at this layer ensures that the data behind a certified root is
  available or retained; nor endpoint discovery or service liveness (these are solved by
  aggregator-go or the payment gateway). If no quorum forms, the root issues only a repeat
  certificate (on a proven no-quorum or after the T2 timeout).
- **Independence of the signers.** With a centrally run shard the operator holds the configured
  keys, so the quorum attests only that the operator signed. Censoring, reordering within the
  operator's own rounds, and an incorrect but well-formed transition are not detected at this
  layer.
- **Stake.** Aggregator shards are unweighted; no stake backs their certificates.

Clients that rely on an aggregator shard's certificates therefore trust its operator for the
correctness and availability of the transitions, and the root for the signature quorum, chain
continuity, ordering and configuration binding. Changing this (a proof type other than none,
decentralized aggregation) needs a separate owner decision.

## Open owner questions

These are recorded, not decided, by this ADR:

1. **Disclosure wording.** The trust-assumption disclosure above is derived from the decision text and the
   certification code, not dictated by the owner; the owner is asked to confirm it.
2. **What replaces the I-track safeguard.** H7 (the I4 inbox evidence watermark for withdrawal), S4 (the
   censored-evidence scenario) and X4 (I5) used forced inclusion as a safeguard. What protects them while the
   I-track is deferred is open, as is whether bridge nullifier non-membership (`appendix-bridging.tex`) is a bridge
   data-structure check outside decision 5 rather than an EVM absence proof.

## Consequences

- **Roadmap:** Q2/Q3 shrink to the EVM shard mirroring root weights; P3 binds only the root key;
  the I-track (I1-I5) is deferred, not deleted; H2/H3/F8 carry the coupling and the
  epoch-boundary, root-ordered aggregator reconfiguration; F7's broad export moves to B5.
- **Superseded wording:** statements that give aggregator shards or the EVM shard their own weights,
  that bind separate consensus/node key roles in the staking registry, that treat forced inclusion
  as a launch dependency, or that offer EVM-only rotation as an operation are superseded as listed
  in the specification amendment.
- **Unchanged:** existing absence-proof, EVM-only and weighted-shard code and vectors may remain;
  this ADR only stops new work on them and removes them from release gates.
- **Documents amended with a pointer:** `docs/pos/roadmap.md`, `docs/pos/issue-index.md`,
  `docs/pos/README.md`, `docs/pos/specification/README.md` and the new amendment,
  ADR 0005 / D3, ADR 0007 / D5, and F7 (`docs/design/f7-parent-registry-witness-archive.md`).
