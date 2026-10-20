# Root vote evidence service (S3, #55)

Design: `briefs/s3-evidence-service-design.md`. This is the first slice: observation, durable journal, bounded export and the retention rule. The
submitter (builder, `submitEvidence`, `settleEvidence`) follows in its own change.

## What a root records

`--evidence-journal <file>` on `root-node run` enables an observer. It is a tap in `onVoteMsg` that sees every decoded vote **before** the
stale-round, epoch, leader and duplicate filters (`rootchain/consensus/consensus_manager.go`). It never admits, changes or answers the vote, and
its failures cannot reach consensus.

A queued vote is processed by one worker: `abdrc.VoteMsg.VerifyStatement` verifies the signed statement alone (the vote signature over
sha256(PV) and, for a committing vote, the seal signature, both with the voter's key of the voting epoch). The high QC, the anchor, the envelope
and the round the vote arrived in play no part, so a stale or unverifiable transport context does not erase genuine evidence. Only scheme 2
votes are kept; timeouts, scheme 1 votes and UTB-endorsement-only conflicts are not (the contract does not slash them).

Each statement is stored as normalized fields the Evidence contract takes (`parent, exec, timestamp, committing, commitHash, commitRound,
commitEpoch, commitTimestamp`), with the **original signatures** and the **exact PV bytes**: nothing is re-signed. A slot is
`(author, voting epoch, voting round)`. The first authenticated statement is kept, then the first *different* one (different sha256(PV));
the same preimage with another signature encoding is a duplicate and a third variant adds nothing. Both statements, the event index and the
size account are written in one transaction.

## Bounds and explicit gaps

- one statement ≤ 4 KiB; a page ≤ 64 records and ≤ 256 KiB; a journal budget of 1 GiB (sum of record encodings);
- a full queue (1024 votes) or a failed journal write is counted (`Observer.Gaps`) and the observer reports itself unhealthy; a refused record
  (`ErrBudget`) leaves no trace. Nothing evicts an actionable record to make room, and consensus never waits for the journal;
- `Journal.Export(afterSeq, limit)` returns `OldestSeq`, `NextSeq`, `More` and `Gap`: a requested range that contains pruned events (`afterSeq` below the highest
  pruned sequence, kept in the journal) is a declared gap, never an apparently complete empty page; votes the observer never captured are
  reported by `Observer.Gaps`. Sequence numbers are monotone across restarts.

## Retention (`rootevidence.Retention`)

A statement may be dropped from the required archive only when certified EVM values prove the contract can no longer admit it, never by local
time or cache freshness. The rule mirrors `Evidence.sol _requireTimely` and is never optimistic:

| Case | Dropped when |
|---|---|
| assignment not activated | never (kept) |
| H not yet imported | never: the contract provisionally treats the vote as ordinary, but an old suffix vote has no expiry before closure |
| round above H | closure authenticated **and** progress > pClose + suffix window |
| ordinary round | progress > offset + (round − firstRound) + evidence window (the cutoff is inclusive) |
| round before the assignment's first round | at once (never admissible) |

`Journal.Prune` applies a caller's decision per slot; an error of the decision (unavailable or unverifiable view) keeps the slot. A pending case
or an uncertain submission is the submitter's to add. Unclosed epochs can hold records indefinitely: the bound is per record and per page, not a
fixed total, and at the budget the observer stops taking new slots and says so.

## Submitter (`ubft evidence`, package `rootevidence`)

Permissionless and key-free: it holds a funded EVM account, never a root or owner key.

- `evidence scan --journal a.db --journal b.db`: merges the journals (copies: a running root holds its file) by slot. One half of an offence in
  each observer is a pair neither alone could show. Prints the offences and the number of declared export gaps.
- `evidence submit --journal … --eth-rpc URL --evidence ADDR --assignment ID… --sender-key FILE [--settle]`: for each pair, `Submitter.Submit`.
  1. `offenceSeen` (the contract's own answer): known offences are never resubmitted, whoever reported them (`AlreadyAdmitted`).
  2. The exposure is resolved among the given candidate assignments (root epoch = voting epoch, exposure holding the voter's key hash) and read
     with the assignment's cutoff values and captured policy windows; none found is `Unresolved` (transient).
  3. `Retention` against the contract's `progress()`: a proven-late pair is `TooLate` and not sent; the inclusive cutoff is still sent.
  4. `SubmitCalldata` builds `submitEvidence(header, a, b, exposureID)` with the **original** vote and seal signatures, statements ordered by
     digest. Before it does, it rebuilds from the typed fields exactly what the contract rebuilds (PV through `votesig`, the native seal bytes
     through `UnicitySeal.SigBytes`) and refuses unless they equal the bytes the signatures were verified under.
  5. Sent through `posrelayer.Sender` (estimateGas simulates, the receipt must succeed); the case must exist afterwards. A revert is classified
     by the contract's own error selector: `EvidenceLate`/`RoundBeforeEpoch` permanent, `DuplicateOffence` already admitted,
     `AssignmentNotActivated`/`ExposureUnknown` transient, the rest rejected. An unclassified failure is returned for the caller to retry.
- `Submitter.Settle` (`--settle`): `settleEvidence` in ascending batches of the contract's `maxBatch`, from the on-chain cursor; resumable.

ABI selectors are pinned against `forge inspect` output of unicity-pos-contracts 07891a6 (`TestABIMatchesTheContracts`).

## Not in these slices

The peer `GetRootEvidence` service (collectors read journal files), backfill from the anti-equivocation decision store, a durable submit outbox
(restart safety rests on `offenceSeen`; a submission whose receipt timed out may still land, and a second send then reverts with
`DuplicateOffence`), automatic backoff scheduling, resolving candidate assignments from chain, and the live S4 exercise.
