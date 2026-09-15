# F6a (#14): the certified-block record and crash contract

Issue: #14, bounded prerequisite slice (claim issuecomment-5680242084). Base: `integration/enshrined-evm` at
`e2730083`. Status: **design and test-only executable model** (`docs/design/models/f6arecord`), revised for
review 5210262067 (§11). No production change.

This record defines what a node keeps durably for a certified EVM block B, so that after a crash it can become
ready for B's child without trusting anything it cannot re-verify. It fixes:

- the record's content, context and encoding;
- the separation between observed, executor-applied, witness-verified and durable-ready state;
- how currency is established on top of a durable record;
- the one-transaction write boundary and its retention;
- the outcome of a crash at every step, and of damaged, stale or foreign records on reload.

It does not wire any of this into a node; that follows review of this boundary.

## 1. Starting point at the base

| Piece | Today |
| --- | --- |
| `shardnode/store.go` `FileStore` | one canonical CBOR certificate, written by temp file and rename, **no fsync**, no history |
| `shardnode/node.go` `persistingDriver` | saves that certificate **after** `Round.HandleCertificate` returns, which is after `executor.Commit` of the certified block |
| `shardnode/anchor.go` `continuityState` | the execution anchor and verified quiet interval, **process memory only** |
| `keyvaluedb/boltdb` | bbolt v1.4.0 with default options (`NoSync` false): a transaction is synced before `Commit` returns |
| signing record | the authority's process memory for the life of its key (ADR 0009, `f6c-signing-state-contract.md` §5) |
| `witness(B)` | acquired and verified by `registrywitness`, held in memory only (#158) |

So today a crash between the executor commit and the certificate file write leaves the executor ahead of what
the node recorded, and nothing records `witness(B)` at all.

## 2. States

Each state rests on different evidence. Only the last one authorizes anything.

| State | Evidence | Where it lives | Survives a crash |
| --- | --- | --- | --- |
| **observed** | a certificate for B, authenticated under configuration (P-ctx) | process memory | no |
| **executor-applied** | the executor's head is B (hash and state root) | the execution client | yes, but it is the executor's state, not a claim this node made |
| **witness-verified** | `witness(B)` acquired by hash and accepted by `registryproof.Verify` | process memory | no |
| **durable-ready** | the record for B committed in one transaction with the head pointer, **re-verified on reload**, and the executor's head is B | the store and the executor | yes, re-established on every reload |

Two rules follow.

- **Durable-ready is necessary, not sufficient.** A retained record replays perfectly after a whole-store
  rollback (`f6b-quiet-uc-recovery.md` §6.1). Readiness for B's child therefore also requires **authenticated
  continuity** from the record's own certificate to the certificate this process currently holds (§6.1). That
  certificate need not name B: quiet rounds certify no block and advance the partition round while B stays the
  execution parent. No state here implies signing authority. The P-id gate and the signing authority's own
  admission are unchanged.
- **Durable readiness is never recovered without a verified witness.** A record without `witness(B)`, or one
  whose witness does not verify, is not a record this contract accepts.

## 3. The record

One record per certified EVM block. In the model its fields are `certifiedRecord` in `record_test.go`.

| Field | Content | Checked on reload against |
| --- | --- | --- |
| `Version` | `1` | the build's supported version; the envelope and payload versions must also agree |
| `Context` | network, partition and shard ids; `fullShardConfHash`; registry code hash; `genesisCommitment`; `evmGenesisHash`; shard and root epochs | the node's configuration, verified at startup (#153 §5.3); never taken from the record |
| `BlockHash`, `BlockNumber`, `StateRoot`, `PartitionRound` | B's identity | the certificate (ordinary records) or the configured EVM genesis (the genesis record), and the witness |
| `Certificate` | the CBOR bytes of the `UnicityCertificate` that certifies B | `verifyRestoredLUC` (UC.Verify against the configured trust base, partition, shard and `fullShardConfHash`), then the block rule below |
| `Technical` | the CBOR bytes of the bound `TechnicalRecord` | `TechnicalRecord.HashMatches(UC.TRHash)` |
| `Witness*` | `witness(B)`: RLP header, account proof, 22 storage proofs | `registryproof.Verify` under the configured context, at B's hash; the proven number and state root must equal the record's |

**Two block rules.**
- **An ordinary record** (block number above 0) requires a certificate that **names B**: its input record's
  block hash, state hash and partition round equal the record's.
- **The genesis record** is configuration-bound. Its block hash must be the configured `evmGenesisHash`. Its
  certificate is genesis history as #153 §7.3 E2 defines it: it **names no block**, and its state and previous
  state are the genesis state. `registryproof.Verify` at the configured genesis hash then enforces block 0 and
  exactly the §5.4 storage, so the registry has executed nothing.

A block-0 record whose certificate names a block, and an ordinary record whose certificate names none, are both
refused (`TestGenesisRecordShapeRefusals`).

**Encoding.**
- The record is canonical CBOR (toarray), stored inside an envelope carrying the version, the payload and
  SHA-256 of the payload.
- A digest mismatch is damage the backend did not detect.
- A stored value is bounded at 1 MiB before decoding. Certificate and technical record stay well under 64 KiB,
  and the witness under `registryproof`'s 256 KiB node bound.

**No signing state.** The record has no field for, and the store no key for, the signing record, reservation,
generation, session, journal or any signed or voted cursor. The signing record stays in the authority's memory
(ADR 0009). This contract does not persist, reset or restore it, and it adds no local signing fallback
(`TestTheRecordHoldsNoSigningState`).

## 4. The atomic write boundary

**One transaction** writes three things, and nothing else:

1. the record for B, under `record/<partition round, zero-padded>/<block hash>` (genesis under `record/genesis`);
2. the head pointer `head`, naming that record's key;
3. the retention deletions (§5).

**Preconditions, checked before the transaction starts:**
- the node holds a verified `witness(B)` for exactly the observed block;
- the executor's head is B.

A durable record therefore never claims more than the node established
(`TestPersistRefusesToClaimMoreThanItEstablished`).

**Backend assumption.** The store's transactions are all-or-nothing at commit and durable once commit returns.
bbolt with default options provides this: data and meta pages are synced before `Commit` returns, and a crash
before the meta page is written leaves the previous meta page current. The model states this as an assumption
(`faultStore`), not as evidence. The storage unit that implements this record must establish it for its backend
and filesystem, including the directory sync bbolt performs when it creates the file.

**Why one transaction.** If the head pointer and the record were written separately, a crash between them
would leave the head naming a record that is not there, or a record that no pointer names. Retention inside the
transaction means a crash cannot delete old records without also committing the new one.

## 5. Retention

- The store keeps the genesis record and the newest `N` non-genesis records; `N` is a deployment parameter.
- Older records are deleted in the same transaction that commits a newer one (`TestRetentionIsPartOfTheWrite`).
- Retained older records exist for replay and for #15's archive serving. **They are never substituted** for
  an unreadable head record (§6).
- The retention horizon that #153 §8.2 and D2 companion retention require, and the choice of `N`, belong to
  the storage unit and the deployment; this contract only fixes that retention is transactional and never a
  fallback.

## 6. Reload and readiness

A new process decides durable readiness from the store, its configuration and the executor's head. In order:

1. **Head pointer.** Missing means no record (`errNoRecord`). If the head names a key that is not there, the
   record is untrusted (`errRecordUntrusted`).
2. **Envelope.** Size bound, CBOR, envelope version, digest, and payload version equal to the envelope's. Any
   failure is `errRecordUntrusted` or `errRecordVersion`.
3. **Context.** The record's context must equal configuration (`errWrongContext`).
4. **Certificate.** It must authenticate (`errCertificate`), be for this network, partition, shard and
   configuration (`errWrongContext`), and satisfy the block rule of §3 for an ordinary or genesis record
   (`errWrongBlock`).
5. **Technical record.** It must be the one the certificate commits to (`errTechnicalRecord`).
6. **Witness.** `registryproof.Verify` at B's hash under the configured context (`errWitness`), and the proven
   number and state root equal the record's (`errWrongBlock`).
7. **Executor.**

   | Executor head | Outcome |
   | --- | --- |
   | B | durable-ready |
   | below B's height | `errExecutorBehind`: recover by committing B, which the certificate authorizes; if the executor lacks the payload, still not ready |
   | above B's height | `errExecutorAhead`: the association for the newer block was lost; readiness needs that block's own record |
   | another block at B's height | `errExecutorDiverged`: a fault |

**Never a fallback.** An unreadable, foreign or unverifiable head record is not replaced by an older retained
record, the legacy certificate file, the executor's head, or a zero cursor. The executor, not the record,
decides where the node is, and an older record would present an older state as current.

### 6.1 Readiness for B's child: continuity to the held certificate

Durable readiness says B is recorded and the executor is at B. Readiness for B's child additionally requires
that B is still the parent of the round the node is being asked to build on. That is a statement about the
certificate the process holds now, and the record cannot make it.

**Currency is established by authenticated continuity** from the record's certificate (the *source*, with its
technical record) through a chain of certificates to the *held* certificate. The rules are the accepted #92
anchor-evidence rules (`shardnode/anchorevidence.go` `VerifyAnchorEvidence`,
`f6b-quiet-tail-anchor-recovery.md` §2). The model is `verifyContinuity` in `continuity_test.go`.

- Every certificate, the source and held ones included, authenticates, is for this configuration, and is in
  the source's shard epoch (`errCertificate`, `errWrongContext`, `errEpochChange`). The epoch is compared only
  after authentication.
- Every technical record is the one its certificate commits to (`errTechnicalRecord`).
- Each certificate is the round its predecessor's technical record **assigned**, never round + 1
  (`errContinuityGap`).
- A certificate for the round just accepted is a **repeat** only with an identical input record
  (`errCandidateSplit`) and a strictly later root round (`errContinuityGap`). A repeat supersedes the
  assignment only.
- Every certificate after the source is **quiet at the source's state**: no block, and state and previous
  state equal to the source's (`errNotQuiet`). An intervening block, or a block-naming round at the same state,
  ends B's readiness.
- The chain **ends at the held certificate**: the same partition round (`errUnconnected`) and the same input
  record, root round and signatures excluded (`errConflict`).
- The chain is bounded at 512 certificates (`errExhausted`), as `DefaultAnchorEvidenceLimits` is.

State equality alone is never enough, and no unsigned counter is consulted. Every refusal is `errStale`, with
the specific rule in the error chain.

**For the genesis record**, the same chain rules apply from the no-block genesis certificate: repeats after
initial root timeouts, and quiet rounds at the genesis state. #153 §7.3 E1 to E4 then decide eligibility for
the round the held certificate assigns, using that same certificate chain and the verified genesis snapshot
(`TestGenesisReadinessUsesTheSameCertificateThroughout`, rounds 1, 2 and 4).

**Retained or reacquired.** Continuity is **not** in the record, and the record cannot attest to it: a stored
chain replays exactly as a stored record does.
- In a running process, the chain is the certificates this process observed (`shardnode` `continuityState`).
- After a restart, it is **reacquired** as #92 anchor evidence ending at the certificate the restarted process
  holds.
- Until that evidence verifies, the restarted node is durable-ready but not ready for the child.

Persisting observed links is outside this contract.

## 7. Crash and fault cases

Record(P) is durable and the executor is at P. The node then processes B, P's child. Model tests are in
`contract_test.go` and `continuity_test.go`.

| # | Fault | Outcome | Test |
| --- | --- | --- | --- |
| 1 | crash after observing B, before the executor commits | durable-ready for P; B's certificate does not continue P's (not quiet), so not ready for the held round | `TestCrashBetweenPipelineSteps` |
| 2 | crash after the executor commits B, before witness acquisition | executor ahead: not ready for P or B | same |
| 3 | crash after `witness(B)` verified, before the durable write | executor ahead: not ready | same |
| 4 | crash inside the durable write, before commit | nothing applied; executor ahead: not ready | same |
| 5 | crash after the durable write commits | durable-ready for B | same |
| 6 | B's proof window passes before capture | acquisition unavailable, no record written, executor ahead: not ready; obtaining `witness(B)` is #15 | `TestProofExpiryBeforeCaptureStaysUnavailable` |
| 7 | a bit flipped or a value truncated on the medium; the head naming a missing record | `errRecordUntrusted`; no older record substituted | `TestInterruptedAndDamagedRecordsAreRefused` |
| 8 | a missing witness, another block's witness, another deployment's witness | `errWitness` | `TestInconsistentRecordsAreRefusedOnReload` |
| 9 | a record for another context; another block's certificate; an unissued certificate; an uncommitted technical record; a claimed height the witness does not prove; an unknown version | the named refusal | same |
| 10 | executor behind the record, with and without the payload | not ready; ready after committing the recorded block when the payload exists | `TestExecutorAheadOrBehindTheRecord` |
| 11 | executor ahead of the record; executor on another block at the record's height | not ready; diverged is a fault | same |
| 12 | whole-store rollback, with the executor ahead or also rolled back | not ready, or durable-ready but without continuity to the held round | `TestWholeStoreRollbackCannotTestifyToCurrency` |
| 13 | empty replacement disk | no record: not ready | `TestReplacementDiskAndMigration` |
| 14 | an unissued held certificate; a future envelope version; an oversized stored value; an issued certificate for another network naming the recorded block; a block hash of the wrong width | `errCertificate`, `errRecordVersion`, `errRecordUntrusted`, `errWrongContext`, `errWrongBlock` | `TestChecksNoOtherRuleCovers` |
| 15 | quiet successors: one, a non-consecutive run, a repeat that changes the next assignment, holding a repeat of the last round | ready for the child of B throughout, with executor and witness unchanged | `TestReview159QuietSuccessorPreservesReadiness`, `TestQuietHistoryKeepsReadiness` |
| 16 | a gap; a quiet round at another state; a repeat not at a later root round; a repeat with another input record; a block-naming round at B's state; an intervening block; a held certificate naming a block where the chain is quiet; a chain that stops short; an unissued, unbound, foreign-context or other-epoch link; a chain over the bound | `errStale` with `errContinuityGap`, `errCandidateSplit`, `errNotQuiet`, `errConflict`, `errUnconnected`, `errCertificate`, `errTechnicalRecord`, `errWrongContext`, `errEpochChange`, `errExhausted` | `TestContinuityRefusals` |
| 17 | the real no-block genesis certificate persisted and reloaded; readiness for rounds 1, 2 and 4 after initial timeouts, and after a quiet genesis-state round; a later block-naming certificate; a held certificate that assigns round 0, or assigns its own round | reloads; ready; the later block ends genesis readiness; E1 or E2 refuses the last two | `TestReview159GenesisCertificateDoesNotNameABlock`, `TestGenesisReadinessUsesTheSameCertificateThroughout` |
| 18 | a genesis certificate naming a block; a genesis certificate with another previous state; a block-0 record for another hash; an ordinary record with a no-block certificate | `errWrongBlock` | `TestGenesisRecordShapeRefusals` |

Rows also pass through `TestHappyPathEndsDurableReady`, `TestRetentionIsPartOfTheWrite`,
`TestPersistRefusesToClaimMoreThanItEstablished` and `TestTheRecordHoldsNoSigningState`, and
`TestFixtureChainVerifiesAsFinalizedParents` checks the fixture chain itself.

**Mutation check.** Run locally, one mutation at a time, with the model files restored and compared after each.
The results are in §11.

## 8. Limitations, stated explicitly

- **Whole-store rollback.** A restored backup or cloned disk is internally perfect, and nothing in the store can
  tell that it is stale. Only the executor's head and continuity to the held certificate expose it. This
  contract never makes durability a claim of freshness.
- **Replacement disk, retained executor.** With no record, the node is not ready for any non-genesis child.
  It must obtain the certificate and `witness(B)` for the executor's certified head from the network: the
  certificate and its continuity from the live feed or #92 anchor evidence, the witness within the client's
  proof window or through #15.
- **Replacement host, fresh executor.** The executor must first reach a certified block, by execution-client
  sync that this contract does not define. Until then the executor is behind or empty and the node is not ready.
- **Genesis.** With a wiped store and the executor at genesis, the genesis record can be rebuilt from
  configuration. `registrygenesis` derives `witness(evmGenesisHash)`, and the no-block genesis certificate
  comes from the network. It is then verified and persisted like any other record, under the genesis block
  rule of §3. Readiness for a payload whose parent is genesis still requires §6.1 continuity and #153 §7.3 E1 to
  E4.
- **Migration from `FileStore`.** The legacy file holds only the latest certificate. After re-authentication a
  migration may treat it as an observed certificate. It carries no witness, so it creates no readiness
  (`TestReplacementDiskAndMigration`). The file is left in place, as `LoadLUC` already does for legacy formats.
  No public state exists yet, so no in-place conversion is defined.
- **Continuity after restart** is reacquired, not recovered from the store (§6.1). A restarted node that cannot
  obtain anchor evidence ending at its held certificate stays not ready for the child.
- **Backend durability** is an assumption of this model (§4), not a property it demonstrates.
- **Signing.** Restored voting stays governed by ADR 0009 and the F6c contract. A durable record gives no
  signing history, and every authority restart still ends that voter's signing for the current assignment.

## 9. What the next units own

| Unit | Owns |
| --- | --- |
| storage implementation (#14) | the bbolt schema for this record; establishing the backend durability assumption; the retention parameters; fault injection against the real store |
| node wiring (#14, after the storage unit) | capturing at commit before the next block; writing the record; the reload sequence of §6 at startup; readiness for B's child from the live continuity state or reacquired anchor evidence, alongside P-id |
| #15 | serving retained records and witnesses to peers; obtaining `witness(B)` after the proof window has passed |

## 10. Not in this unit

No production code, store schema, migration, node wiring, peer protocol, activation, `v0` removal or
WithSealV1 advertisement. The signing record is untouched. #10, #11, #12 and #14 stay open.

## 11. Review record

**Review 5210262067 (of `d0f878a4`).**

| Finding | Resolution | Applied in |
| --- | --- | --- |
| P1: readiness required the held certificate to name B, so the first valid quiet successor revoked readiness (the #92 quiet-tail stall) | the immutable record is kept separate from currency. Readiness for B's child requires #92 continuity from the record's certificate to the held certificate. Continuity is not in the record and is reacquired after restart | §2, §6.1, §7 rows 15 and 16, `continuity_test.go` |
| P1: the model stored a fabricated block-naming genesis certificate, so the real no-block certificate passed E1 to E4 but failed reload | a configuration-bound genesis record: identity from the configured EVM genesis and its witness; a no-block genesis-history certificate; that same certificate used through persistence, reload, continuity and E1 to E4 at rounds 1, 2 and 4. Ordinary records still require a block-naming certificate | §3, §6.1, §7 rows 17 and 18, `record_test.go` `verifyRecord`, `continuity_test.go` |

**Mutation check of the repair.** Run locally, one mutation at a time, with the files restored and compared after each. Each of the 23 rules the repair introduces or changes was disabled in turn: 17 in continuity and its use for readiness, 2 in input-record identity, and 5 in the genesis and ordinary block rules. Every one fails at least one test.

The first pass was not clean:
- **Did not compile:** 2 mutations, rewritten. One of them, dropping the quiet-state check, was killed only after I added the case "a quiet round at another state".
- **Redundant check:** 1 mutation removed the source check inside continuity and survived. The source is the record's own certificate, which record verification on reload already authenticates, checks against configuration and binds. I deleted that check and recorded the reason in the code.
- **Genuine survivor:** 1 mutation skipped E1 to E4 for genesis. Continuity alone does not refuse a genesis-history certificate that assigns round 0 or its own round, so both cases were added, and the mutation is now killed.

**Mutation check of the first revision (`d0f878a4`).** Each of the 27 rules the model enforced was disabled
in turn, and every one fails at least one test. The first pass was not clean:
- **Did not compile:** 2 mutations, rewritten.
- **Not applied:** 1 mutation, because my pattern had the wrong indentation.
- **Hidden:** 7 results. My output filter dropped the only failure line that tests without subtests print.
  Rerun unfiltered, two of the 7 were already killed.
- **Genuine survivors (5):** `TestChecksNoOtherRuleCovers` isolates each, and all five are now killed.
