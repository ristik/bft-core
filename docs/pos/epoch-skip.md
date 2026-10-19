# Shard configuration transitions (epoch skipping, ristik/bft-core#640)

Design: `briefs/epoch-skip-design.md`. This page is the contract the code implements (PR-A: transition operation, proposal filtering,
execution, request views; PR-B: recovery, restart, synthetic anchors, fresh-profile pin and lane).

## The applied configuration

A shard's *applied configuration* is named by `ShardInfo.ShardConfHash`, nothing else. `IR.Epoch` (old through delayed acknowledgement
and T2 repeats) and the announced TR epoch never decide whether a configuration is applied. In the new state `TR.Epoch` is the epoch of
the applied configuration; there is no announced-but-not-installed state any more.

## One transition operation

`advanceShardConfiguration(parent, target)` (`rootchain/consensus/storage/sharding.go`):

* same hash: a clone, whatever the IR;
* target epoch above the applied epoch: install it directly (also when it skips epochs), no intermediate state, no synthetic
  acknowledgement; IR and RootHash unchanged; hash, T2, parameters, members, verifiers and request context are the target's; the
  accounting rotates once (previous applied epoch = the parent's accumulators, current = zero for the target's members); `TR.Epoch =
  target`, shard round +1 (checked overflow), the target set's leader, fee/stat commitments of the new accumulators;
* a backward epoch, or the same epoch under another hash, is `ErrShardEpoch`.

`ShardStates.nextBlock` applies it to every shard whose configuration at the block's round differs from the applied one, marks the shard
Changed (the transition is certified through the normal pipeline) and reports the switched set. `nextRound` only advances the attempt
inside the applied configuration. The handoff boundary (`activateEVMAssignment`) and H's successor record
(`successorTechnicalRecord`, `AssignmentSuccessorTRHash`) call the same operation, so what H commits is exactly what the first successor
block installs. The `+1` admission checks of the handoff (`conf.Epoch == TR.Epoch+1`) are kept: the operation can jump, the handoff
rules do not authorise a jump.

When the parent's applied configuration is left by a real switch and the orchestration serves its history (`ConfigHistory`,
`Orchestration.ShardConfigByHash`), the hash must name a stored configuration of the shard whose epoch is the state's TR epoch; a missing
entry is an error, never "unchanged". Unchanged shards never consult the history.

## No request for a switching shard in the switching block

The executor refuses a block (`ErrShardSwitching`) that carries a request, T2 repeat included, for a shard whose configuration switches in
it (whole block, not skipped silently). The proposer excludes such shards before it resolves any timeout or view:
`BlockStore.SwitchingShardsForBlock(parentRound, blockRound)` is the plan from the exact proposal parent (a terminal suffix switches
nothing), `IrReqBuffer.Drop` discards the buffered requests and the timeouts are filtered. Other shards keep progressing in that block.
After the block is committed the shard's requests are judged under the target configuration; until then the shard is a change in the
pipeline.

## Request views

`expectedTR` accepts an assignment whose epoch is above the last certified TR's (the transition is not certified yet), no longer only its
direct successor. The predecessor case (parent not yet installed) still requires the `+1` successor, which is what H commits.

## Accounting

`PrevEpochFees/PrevEpochStat` hold the previous **applied** epoch's accumulators, rotated once per applied change. Nothing is credited for
epochs that were never applied. The two slots are not a payout ledger.

## The execution rule is a network profile (ES4, arch ruling `briefs/epoch-skip-profile-ruling.md`)

The root handoff network profile is **3**. Profile 2 is the profile before this rule and is not a profile of this binary: nothing of it is
read, nor reinterpreted, by profile 3. Fresh deployments select 3 explicitly (`root-node run --profile-3`; the former `--profile-2`
does not exist), with no fallback.

Where the number lives (the concrete consumers):

* **Blocks and payloads** carry it: `rctypes.VersionHandoff = 3` is `BlockData.Version`, `Payload.Version` and the payload's wire tag
  (`[3, requests, handoffRecords, posControls]`), the genesis block, every ordinary proposal, the epoch-anchor block, recovery heads and
  pending blocks (`GetVersion` checks in `BlockData.IsValid`, `BlockStore.Add`, `NewRootBlock`, `checkStoredRoot`, the recovery message).
  A block or payload of version 2, or one whose block and payload versions differ, is refused before voting and before persistence.
* **The store** records it: `metadata/networkProfile`, written when an empty store is first opened and checked before anything else is
  read. A store that recorded another profile, or that holds blocks and recorded none (a root of the earlier rule), is refused with
  `ErrNetworkProfile`, whatever its state looks like (it may satisfy the new invariants); a refusal pins nothing. The root trust-history
  identity is `unicity/root-profile-3/history/1`, so a history database of the earlier rule is a different identity.
* **Startup, scripts, deployment descriptors**: `--profile-3` (helper.sh, `scripts/lib/m2-handoff-lib.sh`, `deploy/testnet/generate.py`
  and its tests, `utbprofile` refusals). `payload-vectors.json` (types/testdata) is regenerated for the new tag; it is not one of the
  xrepo shared fixtures.
* **Unchanged on purpose**: the Q3 tuple layout and its UTB revision, UTB record version 2, the vote/QC envelope 3, native UC signing,
  the bridge protocol, the container versions of the checkpoint/shard-state encodings (the block inside carries the profile).

Recorded refusals (not only unit tests):

* The pre-change binary (`946e75da3`, `root-node run`) given the new startup selection: `Error: unknown flag: --profile-3`.
* The same binary decoding the profile-3 vectors: every payload and block is refused (`non-canonical root payload: profile tag`; the
  epoch-anchor blocks fail in its block decoder).
* This binary: a version-2 block/payload (`TestBlockVersionTwoIsRefused`, `TestVersionTwoAndMixed...`), a profile-2 or unpinned store
  (`TestAProfile2StoreIsRefusedEvenWhenItsStateSatisfiesTheNewInvariants`), a head or stored block whose applied configuration is stale,
  future, edited, announces another epoch, names another fee-map member or carries edited accounting
  (`TestRecoveryRefusesStaleFutureEditedAndMismatchedShardStates`).

Peer connectivity is not forbidden; taking part in new-rule consensus is.

## Recovery and reopen (ES3)

A recovered head (`NewRootBlock`) and a stored block (`initBlock`) are judged by one invariant, `ShardInfo.checkAppliedConfiguration`,
against the configuration in effect at the state's **execution** round (the ordered round for a terminal checkpoint or synthetic anchor,
which keep the old checkpoint, so they are not "normalised" to a newer configuration): applied hash, the TR epoch, the fee map's members,
the TR's fee and stat commitments against the accumulators. `TestHeadsBeforeAtAndAfterTheSwitchRecoverIdentically` replays heads before,
at and after each switch from the network and the disk.

## Legacy profile and existing devnets

The invariant above and the transition rule apply to the legacy profile (1) as well, and the legacy profile adopts the network-profile pin
on a store that never recorded one. A legacy store written by the execution before #641 (for example one whose TR announced an epoch ahead of
its applied configuration) can therefore fail `initBlock` on this binary; the deployments are fresh-genesis, a restarted old legacy devnet
is not supported. The handoff profile is stricter: a store without the pin is refused outright.

## Why the lane assertion is "a quorum of the running roots", not "every running root" (evidence: lane run 2026-10-19 12:23)

The first version of `p85_epoch_switches` required each running root to log both EVM switches (K->J, recovery). The 12:23 run
(`briefs/devnet-runs/utb-20261019T122315Z`, all other steps passed) failed it, and the failure was the assertion's premise, not the system:

| root | process starts (15:3x/15:4x) | EVM switch 0->1 (K->J) | EVM switch 1->2 (recovery) |
|---|---|---|---|
| 1 | 15:26:04, 15:37:19, **15:40:22**, 15:42:44 | rounds 658, 659 | **856 at 15:40:28.05** |
| 2 | 15:26:06, 15:37:22, **15:40:25**, 15:42:47 | rounds 658, 659 | **856 at 15:40:28.03** |
| 3 | 15:26:07, 15:37:26, **15:40:27**, 15:42:50 | rounds 658, 659 | **856 at 15:40:27.93** |
| 4 | 15:26:09, 15:37:30, **15:40:31**, 15:42:53 | round 659 | none |
| 5 | 15:28:31, 15:37:34, **15:40:33**, - | round 659 | none |

The recovery epoch's first successor block (round 856) was proposed, voted and committed by roots 1-3 - a quorum of the five - at
15:40:27.9-28.05, **before roots 4 and 5 were even started** (15:40:31 and 15:40:33; the lane installs the roots one after the other). Root 4's
log shows it starting at round 856 ("CM starting ... round=856", "awaiting proposal"), then timeout votes and
`processing *abdrc.StateMsg ... pending consensus recovery crosses epoch: the committed head is the first successor of an epoch anchor`
(15:40:40): it never executed block 856; it took the epoch's state from its peers afterwards. A root that enters an epoch through a
checkpoint/state import does not execute the blocks the others committed before it arrived, so it cannot log their switches. The same shape
explains why the K->J switch is logged at round 658 by roots 1-3 only and at 659 by all five: round 658's block was executed by the three roots
that were up, the round timed out, and 659 re-proposed the switch from the same parent, which all five executed.

What the assertion still requires (and what it cannot be satisfied without): the EVM switches form one chain of at least two pairs, one epoch
up each; every pair was logged by a quorum (3) of the running roots; for every pair the **last** round at which a root switched is identical on
every root that logged it (an earlier line is a proposal that did not become the block); every running root logged at least one switch;
none of the refusal messages ever appears. It fails on silence (no lines), on a pair known to fewer than a quorum, on roots disagreeing about the
committed round, on a broken chain and on an unreadable line - exercised offline against this run's real data (accepted) and against five
mutations of it (each refused for its own reason). The reviewer's original formulation (`every running root`) remains falsifiable here only by
making the lane start the roots together; that is a lane-ordering change, not an evidence relaxation, and is not done.
