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
