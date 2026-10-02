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
   The data structures and data flows are prepared now.
9. **Broad F7** (public account/storage proof export, SDK and RPC) belongs to the bridge track
   (B5, [#66](https://github.com/ristik/bft-core/issues/66)). F7's receipt-complete archive and
   positive-proof export stay in the foundation.

## Trust-assumption disclosure: aggregator shards at launch

Aggregator partitions run with `proof_type` none and a central operator. The root and the BFT Core
certification protocol therefore give the following, and nothing beyond it.

**The root does guarantee, for an aggregator shard:**

- certificates are issued only for the shard's configuration as ordered by root consensus at an
  epoch boundary (no per-node configuration drift), under the trust base of the certificate's epoch;
- each certified round carries a request that satisfied the certification protocol's checks
  (matching signed requests from the shard's configured validators, round and epoch binding,
  non-equivocation per round, the technical-record rules);
- the order of certified state transitions per partition and shard, and that a certificate, once
  issued for a round, is not replaced by a different one.

**The root does not guarantee:**

- that a certified state transition is *valid* for the aggregator's application rules: with no
  consistency proof the root certifies the transition that was presented, it does not verify it;
- availability or retention of the data behind a certified state, endpoint discovery, or liveness
  of the aggregator service (these are solved by aggregator-go or the payment gateway);
- protection against a malicious or compromised operator of a centrally run shard: censoring,
  reordering within the operator's own rounds, or presenting an incorrect but well-formed
  transition are not detected at this layer;
- any stake backing for the shard: aggregator shards are unweighted.

Clients that rely on an aggregator shard's certificates therefore trust its operator for
correctness of the transitions, and the root for ordering, configuration binding and
non-equivocation. Changing this (a proof type other than none, decentralized aggregation) is a
separate, versioned decision with its own activation gate.

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
