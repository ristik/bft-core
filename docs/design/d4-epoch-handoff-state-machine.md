# D4 — Epoch handoff state machine

**Amendment 2026-09-25.** The accepted fixed-parent bootstrap would discard old
commits after H. A tentative round fence can deadlock after the c+2 leader
crashes. Empty old suffixes also let any holder of a later commit QC mint valid
higher-round, same-IR old UCs. This revision uses a branch-local reconfiguration
suffix, a typed epoch genesis, and epoch-qualified consumer ordering. It is a
model and design revision; automatic PoS handoff remains disabled.

Issue [#6](https://github.com/ristik/bft-core/issues/6). Decision:
[ADR 0006](../adr/0006-epoch-handoff-state-machine.md). Executable model:
[`evmroot/d4handoff.go`](../../evmroot/d4handoff.go),
[`d4explore.go`](../../evmroot/d4explore.go),
[`d4multireplica.go`](../../evmroot/d4multireplica.go), and
[`d4progress.go`](../../evmroot/d4progress.go). The independent standard-library
proof generator is
[`generate_d4_vectors.go`](../../evmroot/testdata/generate_d4_vectors.go).

## 1. Safety boundary and ordered state

There is one effective successor for an old epoch. The old committee may keep
certifying empty consensus suffixes while the new committee starts; this is not
overlapping authority to change shard state. All shard certification pauses
from the terminal old state through verified checkpoint import and first new
certification. No fixed wall-clock bound follows from the model.

The root orders `prepare → freeze → endorse → commit H → activate → acknowledge`.
A committed abort applies only before H. In `prepared` or `endorsed`, an
operator can instruct old validators to sign the existing abort-only domain;
the target must match network, old epoch, predecessor, attempt and successor
BodyID in authenticated control state. Signatures are aggregated against the
old trust base's quorum and attached to the existing Abort record. No new
consensus transition, candidate-body authorization, or successor key is
introduced. Leaders schedule a ready Abort before the volatile plan lookup,
including after restart has lost that plan cache. Acceptance of an approval is
not finality: only a committed Abort releases the ordered freeze, and a race
with H is resolved by ordinary BFT locks. After Abort, a new handoff uses
`attempt+1` and a freshly observed parent. A request after H cannot rewind it.
The predecessor and attempt are held in root control state so attempts cannot
each install an independent successor.

All members of the old validator set must run a version that understands the
bounded abort-approval peer message before operators use this path. An older
peer will not contribute an approval; the old trust base's ordinary quorum
availability requirement still applies.
Freeze signs `FrozenID`, which binds the D3 body, pre-freeze summary, last
certified EVM parent, candidate, attempt and predecessor. Endorsement never
binds the later `A*` or successor TR. The D3 body contains `A_min` and uses the
non-circular pre-freeze and candidate-context hashes specified in D3; `A*`
lives in H. H fixes network, old epoch, predecessor BodyID, attempt, FrozenID,
next BodyID, `A*`, successor TR hash and its original ordered round `o`.
`A* >= max(A_min,o+3)` is only a scheduling margin.

Before an old voter signs, it executes or validates the proposal's certified
parent chain and reads that branch's authenticated control state. If the parent
contains H, the proposal is a suffix. Missing parent state causes recovery,
never an assumption of no H. A suffix has no payload of any kind: no shard
success, repeat, no-quorum or timeout request; no EVM/governance transaction;
no prepare, freeze, commit or abort; no unknown kind. Production, execution,
`BlockStore.Add`, recovered pending blocks and every honest pre-vote check
apply this rule. H's own ordered block may contain prior deterministic changes;
those changes are included in `R_H` before installing H.

Execution of a suffix is the identity on *all* shard and control state:
IR, TR, epochs and rounds, state/input/block hashes, fees/stats, membership,
configuration, shard creation/removal and pending configuration. Automatic
`nextEpoch`, round-selected activation and timeout IR/TR updates are deferred
to the first ordinary new block. Root rounds, timestamps, QCs and TCs can
advance. The suffix predicate is branch-local; ordinary BFT locking decides
which conflicting branch an honest signer may vote for. Durable honest locks
survive restart. For weighted total `W` and quorum `Q`, certified H contains
honest refusing weight greater than `W-Q`; Byzantine equivocation cannot form
a payload-descendant QC. Root ordering and BFT safety exclude a competing
committed H or abort. The complete ancestor shard state and old certificate
history survive checkpoint import; abandoned speculative work need not.

The old quorum is needed until a commit proof and full state are available. A
lost c+2 leader or QC is bypassed by old timeouts and arbitrarily later
consecutive empty blocks, even beyond `A*`. There is no old round fence.
Permanent old-quorum loss before proof stalls safely; after proof/state
availability new progress needs only the new quorum and data availability.

## 2. Signed control leaf and exact finality proof

Reserve `P_CTL` in a versioned network profile before wire implementation.
The model's profile 2 freezes `P_CTL = 0xffffffff`, the rightmost IMT leaf.
Orchestration,
registration, normal shard requests and shard timeout scheduling reject the
reserved key. It is root-maintained control data, never a UC destination.

The deterministic CBOR preimages are:

```text
ControlState = ["UNICITY_ROOT_HANDOFF_STATE",1,network,e,predecessorBodyID,
                attempt,phase,orderedRound,recordBytes,previousControlDigest]
RecordID = SHA256(CBOR(["UNICITY_ORDERED_HANDOFF_RECORD",1,network,e,
            predecessorBodyID,attempt,kind,orderedRound,recordPayload]))
```

The record payload excludes ID, signatures and proof. The control leaf's value
is `SHA256(CBOR(ControlState))`, included under the existing
`UnicityTreeData(P_CTL,value)` and indexed Merkle tree hashing. Genesis,
execution, checkpoint/recovery and certificate-tree reconstruction must all
include exactly one such leaf. Recovery ShardInfo carries it as typed control
data with no shard UC/config. Reconstruct all shard leaves without scheduled
config activation and compare the whole computed root to the authenticated
committed root. Missing, duplicate or substituted control data is refused.

A handoff proof contains profile version, canonical record, ControlState,
`path_CTL`, and the old `QC(c+1)`; `QC_c` is optional. Verify the control path
with **both** its leaf key and `IndexTreeOutput` lookup key fixed to `P_CTL`.
Recompute RecordID and digest; check network, predecessor, attempt, phase,
original `o`, body, FrozenID, `A*`, TR and full snapshot. Verify unique old
signatures by authenticated weight, version and signed
`PreviousHash=Hash(VoteInfo)`. The commit QC must have
`VoteInfo.(round,epoch,parentRound)=(c+1,e,c)` and
`LedgerCommitInfo.(round,epoch,hash)=(c,e,R_H)` with nonzero c and a valid
timestamp. There is no genesis or endorsement quorum exemption. If provided,
`QC_c` is checked independently against the same epoch, state and timestamp.
A gapped QC with no commit seal proves nothing.

Normally `c=o`. If an earlier QC is lost, consecutive later empty blocks can
commit H's unchanged state at `c>o`; the control leaf retains `o` and
`R_c=R_H`. Verification accepts that proof even when `c>=A*`. No condition
`c+1<A*` is permitted.

## 3. Typed epoch genesis and new voting

Derive the *virtual* anchor, never an ordinary QC or old block, from the
verified proof, next body and complete shard checkpoint:

```text
G = CBOR(["UNICITY_EPOCH_GENESIS",1,network,e+1,nextBodyID,A*,
          RecordID,o,R_H,H(ControlState),FrozenID,successorTRHash])
GenesisID = SHA256(G)
```

The logical parent `(e,o,R_H,RecordID)` is checkpoint identity, not an old
block hash. Signature subsets, optional `QC_c`, proof seal round `c`, and
arrival order do not enter `GenesisID`. Its typed slot is `A*−1`; it has no
author, timestamp, UC or commit subject. A verified anchor and full snapshot
are installed once per `(e+1,GenesisID)` together with durable new-epoch
safety/pacemaker state. Every new validator starts at **exactly `A*`**,
regardless of `c`; new-epoch timeouts may advance the first successful QC.
Later old proofs never raise the floor, reset votes/locks or replace a new QC.

Proposal, timeout and TC highQC carry a tagged `EpochAnchor | OrdinaryQC`.
The anchor tag binds GenesisID, epoch and slot into signed timeout bytes;
new-body signatures and quorum are verified. It ranks below an ordinary new
QC. Old QCs and TCs cannot advance the new pacemaker. A typed recovery
CommittedHead includes proof and full checkpoint; ordinary heads keep both
required QCs. Pending recovery accepts only same-new-epoch blocks extending
the anchor or verified new QCs. The first proposal references the anchor, and
`isCommitCandidate` yields no commit subject for it. `BlockTree.Commit` also
rejects the anchor before pruning or UC generation. Only a consecutive pair
of ordinary new blocks commits its ordinary parent. A timeout gap delays that
commit under the usual rule.

When certified ancestry lacks the full new-epoch reputation history, root
leadership is deterministic round-robin over ordered new root members:
`members[(r-A*) mod len(members)]`. The successor TR governs EVM leadership,
not root leadership. The existing old-highQC extension/broadcast path must be
replaced before runtime admission. Joining validators fetch old proof, lineage,
next body, full snapshot and durable auxiliary state from any peer/archive and
verify them before signing; a control-leaf path alone proves no availability.
Inherited LastCRs are independently verified with lineage-verified
`GetByEpoch(uc.GetRootEpoch())` and the expected shard identity. Missing bodies
cause fetch or refusal, never fallback to the current body. This historical
verification grants no current authority. The control leaf is not a UC.

## 4. Shard consumers and terminal repeats

All ordinary accepted UCs retain `seal epoch = signer epoch`. Shard nodes,
ureth admission/import/replay and `SealRegistry` compare authenticated
`(rootEpoch,rootRound)` lexicographically and persist the installed transition
and epoch floor atomically. A verified e→e+1 transition is required; arbitrary
higher epochs are refused. Within an epoch keep round and non-equivocation
checks. Across that authorized boundary preserve shard-state continuity and
canonical IR equality without a scalar-root-round rejection. Thus a new
`(e+1,A*)` UC follows an old `(e,100)` UC even if `A*=13`.

A later empty-suffix commit QC can be used by *any* holder to mint valid old
same-IR UCs at unbounded `c'`. Nodes may flush ancestor changes when they
locally first commit H, with their own seal c; persisting/clearing Changed
prevents local duplicate emission, not external minting. Before proof/snapshot
installation, a higher-round same-IR old UC is deferred for classification and
must not trigger timeout or revert. With proof, an old UC at seal `>=o` whose
root is `R_H` and IR equals that shard's canonical `IR_H` is terminal
historical evidence/repeat. Missing terminal state is imported only through
verified checkpoint import. Once proof is installed, no old UC becomes current,
even before new certification is ready. Old signatures and high numeric rounds
cannot replace a new UC. Historical old LastCRs remain available.

The first ordinary new block applies deferred `nextEpoch` under authenticated
shard configuration. It preserves IR/TR/LastCR semantics, exact fee/stat/config
state and does not set Changed or emit a UC merely for `nextEpoch`. Replay and
restart cannot apply it twice. Subsequent payload certification follows normal
Changed rules. The frozen EVM parent remains the last certified EVM parent;
new EVM work waits for the authenticated transition/ack in `SealRegistry.open`,
executed first and bound to FrozenID/TR. Both ureth and contract changes are
mandatory before runtime admission.

Normal proposal/vote/QC/TC epoch selectors, including embedded highQCs, obey
authenticated intervals. Old suffix proof/recovery is a separately typed old
epoch path allowed past `A*`, with no ability to authorize new work. Neither
an unconditional old-round cutoff nor epoch-only key selection is sufficient.
Legacy mixed-tip transitions remain disabled. There is no cross-epoch UC
witness, changed `GetRootEpoch` contract, or new-quorum commit of an old block.

## 5. Executable review gate

The model exercises `CanVoteOldSuffix`, `VerifyHandoff`, `CanBootstrapNew`,
`CanAcceptShardUC`, actual signer sets/locks, checkpoint reconstruction and
cross-replica committed histories. Tests use `errors.Is` sentinels and isolated
mutations. The V2 vectors independently generate the control path, signed
VoteInfo/seal, genesis bytes and the D3 pre-freeze/candidate-context hashes.
Their Ed25519 signatures are model-crypto-only; the runtime verifier needs
separate secp256k1 vectors. Old vector encodings are never reinterpreted.

| Trace | Key observation |
|---|---|
| `suffix_payload_refused`, `payload_bearing_recovered_suffix`, `next_epoch_carry_over` | All payload/config/timeout/state mutation routes refuse on an old suffix; deferred work applies once in new consensus. |
| `suffix_payload_no_qc`, `leader_c_plus_2_crash` | Signer-weight QC impossibility is formula/illustrative; the old progress model executes timeouts past A* and a later consecutive suffix seal. |
| `deterministic_genesis`, `different_c_fixed_start`, `new_bootstrap_timeout`, `anchor_commit_refused` | Alternate c/signatures yield one G and fixed A* start; anchor never commits; new locks persist. |
| `consumer_epoch_and_round`, `minted_late_suffix_uc` | Shard, ureth and registry consumer models quarantine/reclassify old repeats; `(e+1,13)` follows `(e,100)`. |
| `proof_negatives`, `missing_forged_control`, `mixed_historical_lastcr` | Record, leaf/path, QC, signer and checkpoint substitutions refuse; LastCR epoch flags are illustrative pending runtime signatures. |
| `pause_measurement` | Illustrative event times show the last old UC, proof, snapshot, first new QC/UC and EVM ack in normal and crashed-leader schedules. |

The inert model does not establish runtime completeness. Runtime review must
cover suffix identity through every executor path, typed timeout/recovery
plumbing, historic LastCR verification, and consumer suppression of late old
UCs. The old quorum is a liveness dependency only until proof/state delivery.

## H3 amendment: EVM assignment candidate, derived configuration, supersession

The D4 machine is unchanged; H3 adds an optional EVM assignment to the candidate that
`TrustBaseBodyV2.ChangeRecordHash` already binds through `D4CandidateContextHash`.

- **Candidate.** `evmassign.Candidate` (version 2) binds the successor root members, the replaced
  assignment (epoch, full hash), the successor PDR, the ordered PoPs and optionally a supersession.
  Hash order: assignment hash → PoPs → candidate digest → change-record hash → next BodyID → FrozenID.
  The preimage rides the version-2 freeze companion and the handoff bundle, once.
- **Commit.** `SuccessorTRHash` for an assignment handoff is the hash of the successor technical record
  (next monotone shard round, successor epoch, new leader, rolled fee/stat), derived from the retained
  candidate and verified at admission. Old-epoch suffix blocks stay identity.
- **Activation.** The first new-root block installs that record and the derived PDR once
  (`activateEVMAssignment`); IR stays P's original IR, so the first recertification of P authorizes the
  acknowledgement and never replaces P's resulting evidence.
- **Supersession.** While the installed assignment is unacknowledged (`TR.Epoch != IR.Epoch` with the
  configuration already installed), a handoff whose candidate extends the committed chain read from the
  validator's own derived history may replace it on the same frozen parent. Every other handoff is
  refused with `ErrAssignmentAckPending`.
- **Races.** If the acknowledgement certifies first, P changes and the supersession proposal aborts and is
  rebuilt; if the Freeze orders first the acknowledgement cannot certify. Ordinary root consensus decides;
  there is no wall-clock override.
