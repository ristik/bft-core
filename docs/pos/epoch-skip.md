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
