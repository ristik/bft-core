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

## S4: the focused live slashing exercise (#57)

One lane run proves the service path with real effects (`S4_LANE=1`; in CI a `ci-lane-run/**` push whose `scripts/ci/run-inputs.json` says `"s4": true`;
locally `S4_LANE=1 scripts/p85-lane.sh`, or `scripts/utb-lane.sh` for the combined lane). Code: `scripts/lib/s4-lib.sh` (steps), `scripts/s4-equivocate`
(harness signer and vote sender), `scripts/s4/s4_assert.py` (the named PASS lines and the independent policy arithmetic; `python3 -m unittest test_s4_assert`).

1. Every root runs `--evidence-journal test-nodes/rootN/evidence.db`.
2. `s4_equivocate` (epoch 2 live): a harness-only signer holding the joiner root's key (`test-nodes/root5/keys.json`; the root5 process is untouched) makes two scheme 2
   votes for one past epoch-2 round, different statements, one committing (vote and seal signatures), and delivers them over `/ab/root-vote/0.0.1` from a host with the
   joiner's libp2p identity, to two different roots among 1-4, never the root the genuine vote of that round went to (read from the offender's own log), so no journal
   holds a genuine third statement. Both halves arrive stale (the first some rounds after its slot, the second later).
3. The recovery evicts the joiner (epoch 3). `s4_collect_after_rotation` pauses each observer root (SIGSTOP) for the copy of its journal (a consistent crash-point snapshot of the copy-on-write bbolt file, tested under continuous writes) and continues it; `S4_RESTART_ROOTS=1` stops and restarts the root instead, as the first runs did - in the milestone runs the execution chain stopped certifying after those restarts (the control without S4 did not); `ubft evidence scan` runs
   over each copy alone (no offence) and over both (exactly one; no gap; the observers' `evidence observer stats` lines show no dropped/failed).
4. `s4_submit_settle`: a fresh funded reporter (neither a root key nor an owner key) runs `ubft evidence submit --eth-rpc <every validator> --evidence ... --assignment ...`.
   Controls first (eth_call of the real pair altered: identical statements, altered payload, seal stripped: `IdenticalStatements`, `BadSignature`, `SealSignatureMissing`);
   the first submitter run has no `--settle` and is stopped after it printed the admitted case; the second run resumes and settles from the on-chain cursor.
5. `s4_check`: inclusion, calldata carries the original signatures, `EvidenceAccepted`/`offenceSeen`, holds on exactly the attributable lots, the exact historical lot
   debit once, bounty (capped) and treasury equal to the arithmetic from `policyTerms`, honest lots unchanged (reference counts excluded: the next election references
   them), duplicate resubmission and the reordered pair refused (`DuplicateOffence`) with the state identical, `SHA256SUMS`. `s4_claim` (a later step, before the lane's reward step) has the reporter claim exactly the bounty and re-archives; it is separate because the claim, the last transaction of the check, repeatedly got no block in the 3-validator window right after the observer roots' restarts (the other S4 assertions never failed), and the credit stays on chain.

Differences from the design (§5), complete list:

- The joiner holds one election weight, so its exposure has one lot and settlement is one batch (interrupting between batches is covered in process by `TestSettle`); the live run stops the submitter after admission (the first run has no `--settle`) and reruns it.
- Every vote half is stale on arrival (the genuine vote of the round went to the next leader and the harness chooses the two observers elsewhere).
- "Unchanged honest/new deposits": the honest lots 1-3 are unchanged across the case (reference counts excluded); **no new deposit made after the offence is checked** in the live run (the rotation-evidence fixture of #697 covers "a deposit after G is not penalised" in the contracts' tests).
- "An unrelated withdrawal" is reduced to the reporter's claim of exactly the bounty plus the honest lots staying unchanged. **Imported Retirement and maturity are not exercised**: the assertion is only that a missing Retirement is not an evidence hold and that the hold is removed by settlement.
- **A delayed EVM/root-extension period is not induced**: the submission waits for the recovery, but no extension period is made in the scenario.
- "Rotation" in the steps means the **eviction** of the offender's root from the committee (epoch 3, checked from the first epoch-3 certificate), not a key replacement of the offender; the offender key is never replaced. The collector is a fresh process that holds no runtime state (each `ubft evidence scan`/`submit` is a new process over the journal copies); the observer roots are not restarted by default (paused for the copy, see above); no UTB caches are cleared because the exercise does not use a relayer.
- The late-refusal control is **in process only**: `rootevidence` `TestSubmit` "a certified view that proves the cutoff passed is not sent" (outcome `TooLate`, nothing sent) and "a revert is classified by the contract's own error" (`EvidenceLate` -> `TooLate`); the live run has none, and the contract's own `EvidenceLate` revert is tested in the contracts repository.
- Evidence and hold parameters of the lane (its pinned genesis policy, read back in `snapshot-before.json`): `penaltyBps` 100, `lifetimeCapBps` 500, `bountyBps` 1000, `bountyCap` 1 ether, `evidenceWindow` 1000 and `suffixEvidenceWindow` 1000 rounds, `holdNormal`/`holdSuffix`/`holdRetirement` 2000, `timeFloor` 3600 s. The offence is at root round ~600-690 of epoch 2 and is submitted within about 100 rounds of it, inside the 1,000-round window: the submitter checks the certified progress before sending and the contract's `_requireTimely` accepted the transaction.
- The live run found two defects of the S3 command (a reader pinned before its own transactions; no peer yet in a fresh host's table, in the S4 sender) and the lane's chain needs the signed transaction at every validator (no gossip: `--eth-rpc a,b,c`) and no `eth_estimateGas`-based `cast send`.
