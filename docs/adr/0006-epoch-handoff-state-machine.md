# ADR 0006: Reconfiguration-suffix epoch handoff

## Status

Proposed for independent model/proof review, amended 2026-09-29. The profile-2
root runtime includes an explicit operator-triggered abort path; automatic PoS
handoff and the H6 live acceptance remain gated on review and end-to-end
evidence. Depends on ADR 0003 (D1) and ADR 0005 (D3).

## Context

The prior D4 model let the first new block build on the committed handoff's
fixed old parent. Old consensus can commit further shard state before that
block, so this forks away valid old UCs. A tentative old-round fence proposed
to stop the tail deadlocks if the c+2 leader crashes before delivering
QC(c+1). Removing that fence requires a branch-local rule for old descendants.
Independent review also found that a later empty old suffix QC can mint a
valid same-IR old UC at an unbounded round. A per-node Changed flush cannot
prevent external minting. The original raw-round consumer rule would either
apply a terminal repeat as a timeout or reject a subsequent new UC.

## Decision

1. The root orders one terminal H per predecessor. H binds network, old epoch,
   predecessor and attempt, FrozenID, next BodyID, original order round `o`,
   `A*` and successor TR. The D3 body retains `A_min`, with pre-freeze and
   candidate-context hashes that do not include their own BodyID. Endorsement
   binds known frozen state only. Abort is old-quorum committed and pre-H. An
   operator may explicitly collect signatures in `prepared` or `endorsed`;
   each old validator checks the exact authenticated target and signs only on
   local operator instruction. The existing abort-only domain and
   authorization companion are reused. No candidate body or successor key is
   needed. Root leaders prioritize a quorum-ready Abort from branch control
   state before consulting the volatile handoff-plan cache. Handoff approval
   receipt is not cancellation: only a committed Abort is final. A racing H
   wins or loses under ordinary BFT locks; H cannot be rewound. Retry uses
   `attempt+1` and newly observed parent state. **Prepare freezes the EVM
   shard.** From the Prepare record (not only from Freeze) the designated EVM
   shard, selected by partition type, refuses every certification, timeouts
   included; Abort returns the control state to `aborted`, which lifts the
   Prepare-time and the Freeze-time freeze by the same transition. A leader
   orders Prepare only while the plan's frozen parent is still the certified
   EVM IR in its own branch; otherwise it drops the plan (outcome `dropped`,
   nothing ordered, nothing frozen) and the operator re-plans from the current
   parent. The EVM therefore cannot move between Prepare and Freeze, so the
   Freeze check no longer aborts under load: a busy EVM certifying every round
   can be handed off. The cost is an EVM certification pause that starts about
   one root round earlier. Endorsement signatures, possession proofs and the
   parent binding are unchanged. Prepare carries no signatures, so a single
   faulty leader could order one for an unendorsed body: the Prepare-time
   freeze therefore **lapses by itself** `PrepareFreezeLapseRounds` (24) root
   rounds after the Prepare unless a Freeze for that attempt was ordered in
   the window. The lapse is a function of the Prepare's ordered round and the
   executing block's round, so every root agrees; the EVM certifies again, the
   lapsed attempt is dead (a Freeze for it is refused) and the next Prepare
   uses `attempt+1`, as after an abort, once `PrepareCooldownRounds` (24) more
   rounds have passed. Residual: a faulty leader repeating the attack can still
   freeze the EVM for at most 24 of every 48 rounds; removing that needs a
   signed Prepare. A handoff left `prepared` with no cached plan therefore no
   longer needs an operator abort to unfreeze the EVM (root-handoff-abort.md
   still applies to `endorsed`).
2. A voter reads authenticated parent-branch control state before every old
   proposal. Any descendant of H must have empty payload and execute as the
   identity on every shard/control field, including scheduled configuration,
   `nextEpoch`, fees and stats. `BlockStore.Add`, pre-vote validation and
   recovery enforce the same rule. Durable honest locks survive restart;
   Byzantine members may equivocate. A certified H's honest refusing weight
   exceeds `W-Q`, preventing a payload-suffix QC.
3. A versioned, reserved `P_CTL = 0xffffffff` control leaf, always the
   rightmost IMT leaf, commits canonical record and
   state under the existing unicity tree. Verification fixes both control
   path keys and requires old QC(c+1)'s signed VoteInfo and commit seal for
   `(c,e,R_H)` at consecutive rounds. `QC_c` is optional; endorsement and
   genesis exemptions are not finality proof. Later consecutive empty suffix
   blocks can prove the same H at `c>o`, including after `A*`.
4. New consensus installs a verified full checkpoint and a distinct typed
   epoch-genesis anchor G. GenesisID excludes proof `c` and signature subset.
   Its slot is `A*−1`; the initial round is fixed at **A***, even if an old
   proof arrives with `c>=A*`. New-epoch TCs can advance the pacemaker.
   Tagged anchor highQC, committed head and timeout bytes preserve durable
   locks. The anchor cannot be a commit subject or UC producer. A consecutive
   pair of ordinary new blocks commits only an ordinary new parent. Until
   new-epoch reputation ancestry is complete, root leadership uses canonical
   round-robin; successor TR selects EVM leadership only.
5. Shard, ureth and SealRegistry consumers persist an authenticated e→e+1
   transition and compare `(rootEpoch,rootRound)` lexicographically. A valid
   old same-IR/R_H UC at seal `>=o` is historical terminal evidence. Before
   proof it is quarantined without timeout/revert; after proof it never becomes
   current, even before readiness. A new `(e+1,A*)` UC can follow old
   `(e,c')` for any `c'`. Every inherited LastCR is verified with its own
   lineage-verified epoch body and shard identity. Historical verification
   grants no current authority.
6. The first ordinary new block applies deferred shard `nextEpoch` exactly
   once, preserving IR/TR/LastCR and not marking Changed solely for that
   transition. The EVM parent is FrozenID's last certified parent. The
   authenticated acknowledgement uses `SealRegistry.open` first, with
   frozen-parent/TR binding; ureth and contract changes are required before
   runtime admission.

`A*` is a scheduling bound, not a voting fence or finality proof. Old empty
consensus and new consensus may overlap while shard-state authority remains
single-valued. Old-quorum loss before handoff proof/state availability stalls
safely; after delivery new progress does not require old signatures.

## Model and evidence

The executable D4 model uses signed VoteInfo/seal QCs, full snapshot/control
path checks, honest durable locks with Byzantine equivocation, typed anchor
bootstrap, epoch-qualified consumers and cross-replica committed-history
checks. Independent standard-library vectors pin V2 record, proof and genesis
bytes and the D3 hash-cycle repair. Their Ed25519 signatures are model-crypto-only;
the runtime verifier needs separate secp256k1 vectors. The design's review table names every
required trace and negative. The model is inert and supplies no runtime
consensus wiring. Runtime integration still needs proposal/timeout/recovery
changes, checkpoint import, suffix execution, UC consumers, ureth and
SealRegistry.

## Rejected alternatives

- A fixed old parent would discard later committed old state.
- A tentative `A*` fence can permanently halt a live old quorum.
- A new quorum committing an old block needs a cross-epoch UC witness and
  changes the signer/seal epoch contract.
- A proof-dependent first-round floor splits new validators and lets later
  old suffix proofs chase the new pacemaker.
- Suppressing local duplicate UCs cannot prevent an external holder from
  minting a later same-state old UC.
- A bare round or epoch-only trust-base lookup cannot authorize a certificate;
  typed proof, lineage, interval and shard continuity are required.

## H3 amendment: the EVM assignment changes through the same handoff

Full design: [h3-evm-assignment.md](../design/h3-evm-assignment.md).

- The committed candidate may carry an EVM assignment (version-2 candidate, successor PDR, one proof of
  possession per successor key). Old **root** quorum remains the only authority for H; old EVM signatures
  never authorize the successor. Every handoff, including a configuration-only boundary with identical root keys,
  advances the root epoch.
- The EVM shard's configuration is **derived from committed history** (the committed record, successor
  body, retained candidate and activation boundary) and installed once at the first new-root block.
  Orchestration is a derived, idempotent index repaired on startup before the block tree loads; an
  external write of that shard's configuration after genesis is refused.
- The epoch switch is decided against the installed configuration hash, not `TR.Epoch != IR.Epoch`, which
  stays true during a delayed acknowledgement.
- An EVM assignment whose acknowledgement is not certified may be **superseded** on the same frozen
  parent; only the newest installed set can acknowledge, and one folded acknowledgement summarizes the
  committed span. Abort-before-H and attempt+1 are unchanged; there is no post-H rollback.
- Validator-set changes are always coupled (owner decision 2026-10-01): the candidate binds each successor root
  entity to one delegated EVM validator of the same weight and a different key. An EVM-only change is refused,
  and where the EVM configuration carries `validator_coupling=true` so is a root-only committee change, in every root
  validator's block validation (the legacy root-only freeze companion included), the endorsers and the CLI.
