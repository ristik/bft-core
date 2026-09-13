# F6c (#105) acceptance ledger

What this is: a line-by-line reconciliation of #105's acceptance list against the work merged for it,
naming the pull request and the exact test, scenario or retained run behind each claim, and what each
one does not show.

What it is not: a closure of #105. The ledger is written by the party that did the work, so it is a
proposal for review. §4 proposes whether #105 can close within its approved scope and leaves the
decision to that review.

Base for every citation: `integration/enshrined-evm` at `80efeffb` (the #149 merge).

## 0. The contract the list is read against

#105 was written before the mechanism was chosen, and several of its lines are phrased in terms of
persistence: "durable-before-sign", "persistence", "missing/corrupt/replayed signing records", "backup
restore and replacement-host scenarios". The accepted mechanism is not a persistent store. The owner
accepted a disposable private profile (ADR 0009, `docs/design/f6c-signing-state-contract.md` §1 and §9,
Q1 to Q3 approved 2026-09-11). Under that profile:

- **The authority is its own process.** One independent signing authority per validator key owns a
  fresh, non-exported key and an in-memory signing record with the same lifetime as that key.
- **The authority does not persist.** Nothing about it is written to disk. It has no journal, no key
  import and no restore path (§5, §6: "No safety-critical disk writes in this profile").
- **Authority death is permanent.** When the authority process or host dies, its key and record are
  lost together. The validator cannot sign again under that identity. Returning it to service needs a
  new, separately authorized assignment naming a new key.
- **The shard side is untrusted.** Its files may be replayed, restored from an older backup, or run
  twice. The authority's record, which lives outside that domain, is what cannot roll back.
- **Isolation is assumed.** The authority runs on a host outside the shard's backup, snapshot and
  cloning domains. This is a deployment premise that no test in this repository establishes.

The persistence wording is therefore read as follows. A line about durability of the signing record
is met by the record's non-rollback property while its authority lives, together with the tested
outcome when the authority dies. **No claim is made for disk durability, reboot recovery of the
authority, or continuity on a replacement host.** The profile deliberately provides none of them. What
it provides instead, and what is tested, is that each of those events ends signing for that identity
and cannot be turned into a second signature.

## Evidence classes

Every row names its class. The classes are not interchangeable.

| class | meaning |
|---|---|
| **P** process test | separate operating-system processes: the authority as its own process (the `ubft` binary or a re-executed test binary), clients across the real Unix-socket transport |
| **F** in-process fixture | production code in one process (for example `signingauthority.Authority` called directly, or a `Round` with stub executors) |
| **M** executable model | `docs/design/models/f6csigning`, test-only and imported nowhere; models the contract, not the code |
| **R** retained real-reth measurement | a recorded run of a lane against the pinned reth with real root, authority and shard processes, with a manifest and digests; it shows what happened once, on that revision |
| **A** deployment assumption | stated, required of the private deployment, and not tested |

Pull requests and merge commits cited:

| PR | unit | merge |
|---|---|---|
| #126, #128, #130 | contract, in-memory revision, owner decisions | `d793adfd`, `0de1aa1f`, `75748bff` |
| #137 | step 1: enrollment and authentication | `4f0ec961` |
| #140 | step 2: record, reservation, fencing | `dd9e6975` |
| #142 | step 3: round wiring | `3d75e55e` |
| #144 | authority process boundary | `99bb5a58` |
| #145 | deployment wiring (two-phase enrollment, CLI) | `935134b3` |
| #146 | process acceptance lane (fake executor) | `50070aa4` |
| #147 | signing record across processes | `f6d674cf` |
| #148 | step 4: restored voting through the record | `de5f29d8` |
| #149 | real reth and older shard-home backup | `80efeffb` |

---

## 1. The design deliverable

The first half of #105 asks for a reviewed contract before any storage primitive is assumed.

| line | status | evidence |
|---|---|---|
| name the signing scope (network, partition/shard, epoch/configuration, message domain, round, canonical content); identical retransmission; a high-water round alone must not authorize a different message at that round | **met** | contract §2 and §4 (#126); the conflict key is the assigned partition round, with the full canonical request bytes as the lock (§4, §5). The legacy request preimage carries no domain prefix, so domain and network are enforced as an enrollment policy binding, not a cryptographic addition (§2). |
| durable-before-sign/release transition and crash boundaries; evidence-observed, applied execution and signing authorization kept distinct | **met, translated (§0)** | §5 transition table, §6 crash table; retain-before-release is the "durable" step, in authority memory (#128) |
| adversary and trust assumptions; what prevents whole-store rollback, backup restoration, replacement disk/host and concurrent instances | **met** | §3: the shard store is fully untrusted; the authority host is outside backup, snapshot and cloning domains (**A**); a checksum or local watermark is rejected as freshness (§3 table), with the negative control `TestReplayableLocalJournalIsNotFreshness` (**M**) |
| compare the smallest feasible mechanisms; no Engine API/reth change | **met** | §3 mechanism table (#126, #128); no Engine API or reth change in any of #137 to #149 |
| failure behavior: missing, corrupt, unsupported or untrusted state means non-voting with a diagnostic; a valid UC chain and matching executor head cannot override it | **met** | §6; see §2.4 and §2.5 below for the tested outcomes |
| migration from the current state and the operational recovery procedure | **met as documentation; not exercised** | §1: no in-place migration for a validator whose key was ever exported; fresh private genesis or an independently authorized assignment. §8 "Deployment wiring" and `ubft signing-authority --help` give the deployment order. Authority loss requires a new assignment (H-series/#10), which #105 does not authorize and no test performs. |
| implement only the accepted mechanism with its deployment assumptions enforced; keep the #92 gate until integration evidence passes | **met** | steps 1 to 3 (#137, #140, #142), process boundary (#144), wiring (#145); the restored gate stayed unconditional until #148, which replaced it only for the authority signer, after the process and real-reth evidence in §2.6 |

---

## 2. The acceptance evidence, line by line

### 2.1 "A whole older checkpoint verifies as historical evidence but cannot lower signing authorization."

**Met** for the private profile.

| what | class | evidence | PR |
|---|---|---|---|
| an older shard backup with its old session and a lower round cannot move the record | F | `TestAnOlderNodeBackupCannotResetTheAuthority`: the backup's token is `signing-session-fenced`, its round is `signing-stale`, reserved round unchanged | #140 |
| historical node state cannot reset the watermark | M | `TestHistoricalCheckpointQuietHeadAndRepeatCannotResetSigning` | #126 |
| the older checkpoint authenticates as history | F | `TestVerifyRestoredLUC` / "an authentic certificate is accepted"; `TestRestoredNodeIsNonVoting` / "the production restore sequence ..." (`verifyRestoredLUC` passes: authenticity is not currency) | #86, #92, #148 |
| production restore sequence, older checkpoint, real authority process: lower round refused, identical request gets the retained bytes, changed bytes refused | P + F | `TestRestoredVotingThroughAnIndependentAuthority` / "an older checkpoint cannot lower signing history, and fresh work is signed": restored from the round-4 checkpoint while the authority held round 7, round 6 is `signing-stale`, round 7 identical returns the retained bytes byte for byte, changed round-7 bytes are `signing-conflict`, round 8 is signed | #148 |
| a physical older shard home restored while the same authority lives, against real reth | R | `scripts/f6c-reth-backup-acceptance.sh`, arm `backup-restore`, recorded at `26118279`. The checkpoint is byte-identical to the backup; v1 resumed at partition round 7 while the authority held round 12. Its first request was for round 14, and the record went from 12 to 15. | #149 |

Limit: in the #149 run the restored node's first request was already above the reservation, because the
root timed rounds out while v1 was down. #149 does not show a restored node re-entering an existing
reservation. That case rests on the #148 fixture above and on #147 (§2.3).

### 2.2 "Crash injection immediately before/after persistence and signature release cannot yield two conflicting signed messages in one scope/round."

**Met, translated (§0).** "Persistence" in this profile is authority-memory retention before release,
and, on the shard side, the checkpoint write that follows handling. The authority writes nothing to
disk, and an authority crash loses the key, so no second message can come from it.

| boundary | class | evidence | PR |
|---|---|---|---|
| client lost before reservation, after reservation, after signing, after retention, after release | F | `TestCrashBoundariesKeepOneStatement` (five cuts): the old session is fenced; the round cannot be reopened with different bytes (`signing-conflict`); the same request answers identically, and a released response replays byte for byte | #140 |
| the same cuts, modelled | M | `TestCrashBoundariesKeepOnePreimage`; `TestAdversarialOrdersNeverReleaseTwoStatements` (256 request and fence schedules) | #126, #128 |
| a cancelled caller does not undo its reservation | F / P | `TestACancelledCallerDoesNotUndoItsReservation`; `TestACancelledCallDoesNotWaitForTheAuthority` | #140, #144 |
| authority process killed mid-exchange | P | `TestKillingTheAuthorityMakesTheClientUnavailableAndNothingElse`: after a reservation, every later operation is `signing-authority-unavailable` and nothing else | #144 |
| authority death loses key and record together | F / P | `TestAuthorityDeathLosesKeyAndRecordTogether`; `TestARestartedAuthorityIsANewOneAndNotARecoveredOne` (the restarted process has a different key, the old credential is fenced) | #140, #144 |
| shard checkpoint write fails after the request was signed, then the certificate is re-delivered | F | `TestARedeliveredRoundReplaysWithoutSigningAgain`; `TestARefusedAuthorizationIsNotRebuiltAfterAPersistenceFailure`; `TestARebuiltCandidateNeverOverwritesAReservation` | #142 |
| response lost after the authority signed and retained it, then a restored instance asks again | P + F | `TestRestoredVotingThroughAnIndependentAuthority` / "a lost response, concurrent instances and session replacement": the restored instance recovers exactly that signature | #148 |
| a delayed call cannot receive another reservation's response | F / M | `TestReleaseNamesItsReservation`; `TestLaterReservationCannotAnswerAnEarlierCall`; `TestReleaseBindsRoundAndRequestDigest` | #140, #128 |

Limit: no power-loss or disk fault is injected anywhere, because the profile has no authority
persistence to fault. Shard checkpoint durability (atomic block, UC and technical-record storage)
belongs to #14.

### 2.3 "Identical retries behave exactly as specified; altered payload, epoch/config/domain substitution and concurrent-instance attempts are rejected."

**Met.**

| what | class | evidence | PR |
|---|---|---|---|
| identical retry answers identically; different bytes at the round conflict; a lower round is stale even for identical bytes | F | `TestTheAssignedRoundIsTheLock` (all four subtests) | #140 |
| identical requests from a second client process and repeated releases return the retained bytes; a different root authorization with identical bytes returns them too | P | `TestSigningRecordAtTheProcessBoundary` / "identical requests and a repeat authorization replay one retained signature": one signature for 8 releases, 3 client processes, 2 root authorizations | #147 |
| same-round conflict under the same and under a distinct root authorization; stale round; refusals shown not to be authentication failures | P | same test / "conflicting requests for one assigned round never obtain a second signature", with order-swapped controls in fresh authority processes | #147 |
| a distinct root round is a different authorization with the same conflict key | F | `TestRepeatedAssignmentsAndRepeatCertificates`; `TestValidSignerSubsetsAreOneAuthorization` | #137 |
| the full request, size fields and nil/empty proof are the lock | F / M | `TestMissingProofIsDistinctFromAnEmptyOne`; `TestFullRequestAndCanonicalBytesAreTheLock`; `TestTheResponseIsTheReservedRequestSigned` | #137, #126, #140 |
| a proposal that is not the one the authorization assigns | F | `TestProposalMustBeTheOneTheAuthorizationAssigns` | #137 |
| network, partition, shard configuration, shard epoch and root epoch substitution | F | `TestEnrollmentIsAGuardNotANamespace` (another node, partition, network, shard configuration, shard epoch, assignment for another shard epoch); `TestRootEpochIsFrozenByEnrollment`; `TestTheFreezeRefusalDoesNotAssertAuthenticity`; `TestAuthenticationUsesTheAuthoritysOwnTrust` / "an unknown root epoch is refused, not assumed" | #137 |
| the same substitution across the transport | P | `TestRefusalsKeepTheirNamesAcrossTheWire` / "a certificate this authority was not enrolled for" (`signing-context-mismatch`) | #144 |
| domain (profile) | F | `TestEnrollmentIsAGuardNotANamespace` / "an unsupported profile is refused at enrollment" | #137 |
| enrollment scope, modelled | M | `TestScopeIsEnrollmentNotAResetNamespace` | #126 |
| a configuration that does not name the authority's own key | F / P | `TestCompletingAnEnrollmentChecksTheConfigurationAgainstTheAuthority` (all subtests); `TestAPendingAuthorityIsCompletedThroughTheOperatorEndpoint` | #145 |
| concurrent clients on one round | F / M | `TestConcurrentClientsCannotBothWinOneRound`; `TestConcurrentCandidatesAndFencedRelease` | #140, #126 |
| two racing client processes, conflicting and identical, with overlap asserted | P | `TestSigningRecordAtTheProcessBoundary` / "racing client processes get one signature per assigned round" | #147 |
| concurrent instances and fencing: only the current credential is admitted and the record survives | F / P | `TestFencingIsOperatorControlled`; `TestASessionBelongsToTheAuthorityThatIssuedIt`; `TestReplacingTheSessionFencesTheCredentialItReplaced`; `TestConcurrentSessionReplacementsLeaveExactlyOneUsableCredential`; `TestSigningRecordAtTheProcessBoundary` / "a session replacement racing two client instances admits only the current credential" and "concurrent session replacements admit exactly one credential" | #140, #144, #147 |
| a restored instance and an old instance racing a session replacement, through the round | P + F | `TestRestoredVotingThroughAnIndependentAuthority` / "a lost response, concurrent instances and session replacement" | #148 |

Limit: the domain binding is enrollment policy over the legacy preimage, which carries no domain
prefix (§2 of the contract). A key reused under another domain is forbidden by enrollment. It is not
detectable from the signed bytes.

### 2.4 "Missing/corrupt/replayed signing records, backup restore and replacement-host scenarios have explicit tested outcomes."

**Met, translated (§0)**, with the host-isolation premise explicitly not tested.

| scenario | tested outcome | class | evidence | PR |
|---|---|---|---|---|
| **missing** record: the authority process died | key and record lost together; every operation `signing-key-lost` or `signing-authority-unavailable`; no session can be issued | F / P | `TestAuthorityDeathLosesKeyAndRecordTogether`; `TestKillingTheAuthorityMakesTheClientUnavailableAndNothingElse` | #140, #144 |
| **corrupt** record: the reserved bytes no longer match or decode | latched `signing-state-untrusted`, record kept, no reset with the same key | F / M | `TestAnInconsistentRecordIsDetectedAndLatched` (both subtests); `TestDetectedInconsistencyLatchesAndKeepsTheRecord`; `TestAuthorityLossAndDetectedStateFaultNeverBootstrap` | #140, #126 |
| **replayed** record: an exported or older journal | refused by construction: no journal import, no key import, no generic signing | F / M | `TestAuthorityOffersNoGenericSigningOrKeyImport`; `TestEnrollmentBytesAreOwnedByTheAuthority`; `TestReplayableLocalJournalIsNotFreshness` (negative control) | #137, #126 |
| **shard** backup restore | see §2.1: fenced token, stale round, identical request recovers retained bytes, changed bytes conflict; real reth with a physical older home | F / P / R | §2.1 rows | #140, #148, #149 |
| corrupt or tampered **shard** checkpoint | refused before it becomes authority | F | `TestVerifyRestoredLUC` ("an unsigned certificate is rejected", "a tampered but decodable certificate is rejected", "an unavailable or untrusted epoch is rejected, not adopted") | #86, #134 |
| **authority** restarted, or its host replaced | a new key; the old credential is fenced; the configuration naming the old key is refused by `complete-enrollment` (`signing-context-mismatch`); no session (`signing-enrollment-incomplete`); the round abstains; responses under a key the configuration does not name are refused | P + F | `TestARestartedAuthorityIsANewOneAndNotARecoveredOne`; `TestLostAuthorityCannotRecreateEnrolledKey` (**M**); `TestRestoredVotingThroughAnIndependentAuthority` / "an unreachable authority, a wrong key and a new authority lifetime abstain" | #144, #126, #148 |
| operator requirement after authority loss | a separately authorized new assignment naming the new key (fresh private genesis or H-series/#10); no automatic key or enrollment replacement exists | documented; not exercised | contract §1, §6 | #126, #128 |
| authority host outside shard backup/snapshot/cloning; no snapshot of the authority's memory is restored | **assumption** | A | contract §3 | not tested |

Limit: no continuity on a replacement host is provided or claimed. A replacement authority is a new
identity, and the tests show that it cannot act as the old one.

### 2.5 "An executor unchanged across many quiet rounds cannot be used as a signing watermark."

**Met.**

| what | class | evidence | PR |
|---|---|---|---|
| a quiet executor head cannot reset or advance the signing cursor | M | `TestHistoricalCheckpointQuietHeadAndRepeatCannotResetSigning` | #126 |
| with a local key, a restored node whose executor matches the certified head and which even installs a matching anchor does not sign | F | `TestRestoredNodeIsNonVoting` / "the production restore sequence yields a node that follows but never signs" | #92, #148 |
| with the authority, a restored node whose executor is on the certified block is refused a round below the record (`signing-stale`) | P + F | `TestRestoredVotingThroughAnIndependentAuthority` / "an older checkpoint cannot lower signing history ..." | #148 |
| a matching state root at a different block does not authorize signing | P + F | same test / "P-id comes before the authority for a restored process" (leader and follower, no client call) | #148 |

### 2.6 "The integrated restart path remains non-voting until both P-sign and #92's authenticated head/reconciliation conditions hold, then demonstrates continued work with retained evidence and no conflicting signature."

**Met** for the private profile, against both the fake executor and actual reth.

| what | class | evidence | PR |
|---|---|---|---|
| **P-id before leadership and signing**: a restored process on the wrong block at the same state root, or with no anchor, makes no authority call and does not seal; a restored follower on the wrong block makes no call, and on the certified block signs | P + F | `TestRestoredVotingThroughAnIndependentAuthority` / "P-id comes before the authority for a restored process"; gate mutations (the vote-level P-id verdict skipped for a restored process fails this subtest) | #148 |
| **P-sign**: a signer without an independent record keeps the blanket refusal | F / P | `TestRestoredVotingThroughAnIndependentAuthority` / "the local key keeps the blanket restored refusal"; `TestTheSignerIsNotReachedWhenTheRoundMayNotVote` / "a restored process"; lane `local-restart-at-anchor` | #148 |
| restart without an anchor stays non-voting (P-id `no-anchor` first) | P | `scripts/f6c-authority-acceptance.sh` scenario `restart` | #146, #148 |
| restart with an anchor signs fresh rounds through the surviving authority, which the root certifies (fake executor) | P | lane scenario `restart-at-anchor`, recorded at `bc56b0f5` | #148 |
| **actual reth, ordinary restart**: acquisition, adoption of the exact ordinary block, no submission before adoption, signing resumed above the pre-stop round, rounds certified that need v1's request (quorum 2 of 2), then one post-adoption transaction certified with v1's non-quiet request | R | `scripts/f6c-reth-backup-acceptance.sh` arm `ordinary-restart`, recorded at `26118279` (39 assertions): resumed at round 10 while the authority held 11, adopted block 2, signed from round 13, record 11 to 14 | #149 |
| **actual reth, physical older home restored** | R | arm `backup-restore`, same run (42 assertions): see §2.1 | #149 |
| **no conflicting signature** | P / R | the root rejected no request as invalid in any #146, #148 or #149 run; the record only advanced; same-round conflict and re-entry refusals rest on #147 and #148 (§2.1, §2.3), **not on #149** | #147, #148, #149 |
| retained evidence | R | manifests with revision, clean-tree flag and binary digests; per-arm identities, authority status snapshots and refusal diagnostics; 113 sealed digests for #149 (verified by the reviewer); secrets removed; reth datadirs removed only after a successful seal (reviewer repair `12997c11`) | #146, #149 |

Limits:

- The #149 receipt check compares the containing block number and hash on both clients, not every
  receipt field. Its transaction count compares canonical inclusions.
- The #149 lane uses one root node and two validators on one host.
- Neither lane rolls back the execution datadir or tests power-loss durability; both belong to #14.

---

## 3. Gaps, separated

### 3.1 Clauses without evidence

None of #105's acceptance lines lacks evidence under the translation in §0. The following are
deliberately **not** evidenced, and a reviewer should read the rows above with them in mind:

| not shown | why | where it belongs |
|---|---|---|
| host, backup and snapshot isolation of the authority | a deployment premise; same-host tests cannot establish it | the private deployment's own statement (**A**) |
| disk durability, reboot recovery, replacement-host continuity of the authority | not provided by the accepted volatile profile | a later recoverable authority or HSM profile would need its own contract (§1 of the contract) |
| a restored node re-entering an existing reservation **against real reth** | #149's run did not reach that state | fixtures #147 and #148 carry the property |
| every receipt field compared across clients | the lane compares block identity | a later execution-agreement lane if required |
| execution datadir rollback, power-loss durability | outside #105 | #14 |
| operational re-assignment after authority loss | not authorized by #105 | H-series/#10 |

### 3.2 Verification context

- GitHub Actions has not run on these branches since 2026-09-09. The evidence consists of local runs
  and the reviewer's independent reruns recorded in each review.
- In the #148 review, one full `make test` run had a proposal-timeout failure in
  `Test_ConsensusManager_messages/IR_change_request_forwarded_by_peer_included_in_proposal`, and three
  isolated reruns of that test family passed. Its cause is not established, and this ledger does not
  attribute it.

## 4. Proposal

1. Every acceptance line of #105 maps to evidence under the approved private profile (§2), with the
   persistence wording translated to the volatile independent-authority contract (§0) and the premises
   of §3.1 stated rather than claimed.
2. On that basis #105 can be **proposed** for closure within its approved private-deployment scope,
   by the ledger review and not by this document.
3. Closing #105 would discharge none of these:
   - #14 (block, UC and technical-record durability);
   - H-series/#10 (key replacement and re-assignment);
   - public activation;
   - the host-isolation premise.
4. After this reconciliation, work returns to the program's foundation and enshrined-execution backlog
   instead of extending this acceptance lane further.

## 5. What this ledger does not do

It does not re-run the evidence it cites. Every row points at a test in the repository at `80efeffb`
or at a recorded run whose manifest and digests were retained and reviewed. The mapping is the claim,
and the mapping is what a reviewer should check. It does not treat the classes as substitutes for one
another. A fixture shows that the code has a property. A process test shows that the property holds
across a real process boundary. A retained real-reth run shows that real clients and a real root chain
behaved that way on one revision. An assumption is a requirement on the deployment, not a result.
