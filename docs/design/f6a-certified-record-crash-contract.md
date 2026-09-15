# F6a (#14): the certified-block record and crash contract

Issue: #14, bounded prerequisite slice (claim issuecomment-5680242084). Base: `integration/enshrined-evm` at
`e2730083`. Status: **design and test-only executable model** (`docs/design/models/f6arecord`). No production
change.

This record defines what a node keeps durably for a certified EVM block B, so that after a crash it can become
ready for B's child without trusting anything it cannot re-verify. It fixes:

- the record's content, context and encoding;
- the separation between observed, executor-applied, witness-verified and durable-ready state;
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
  rollback (`f6b-quiet-uc-recovery.md` §6.1), so readiness for B's child also requires that the live
  certificate this process holds is the recorded block's (§6, `errStale`). No state here implies signing
  authority. The P-id gate and the signing authority's own admission are unchanged.
- **Durable readiness is never recovered without a verified witness.** A record without `witness(B)`, or one
  whose witness does not verify, is not a record this contract accepts.

## 3. The record

One record per certified EVM block. In the model its fields are `certifiedRecord` in `record_test.go`.

| Field | Content | Checked on reload against |
| --- | --- | --- |
| `Version` | `1` | the build's supported version; the envelope and payload versions must also agree |
| `Context` | network, partition and shard ids; `fullShardConfHash`; registry code hash; `genesisCommitment`; `evmGenesisHash`; shard and root epochs | the node's configuration, verified at startup (#153 §5.3); never taken from the record |
| `BlockHash`, `BlockNumber`, `StateRoot`, `PartitionRound` | B's identity | the certificate and the witness |
| `Certificate` | the CBOR bytes of the `UnicityCertificate` that certifies B | `verifyRestoredLUC` (UC.Verify against the configured trust base, partition, shard and `fullShardConfHash`); its input record's block hash, state hash and round must equal B's |
| `Technical` | the CBOR bytes of the bound `TechnicalRecord` | `TechnicalRecord.HashMatches(UC.TRHash)` |
| `Witness*` | `witness(B)`: RLP header, account proof, 22 storage proofs | `registryproof.Verify` under the configured context, at B's hash; the proven number and state root must equal the record's |

**Encoding.**
- The record is canonical CBOR (toarray). It is stored inside an envelope carrying the version, the payload
  and SHA-256 of the payload.
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

A durable record therefore never claims more than the node established (`TestPersistRefusesToClaimMoreThanItEstablished`).

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

## 6. Reload

A new process decides readiness from the store, its configuration, the executor's head and, for readiness for
B's child, the live certificate. In order:

1. **Head pointer.** Missing means no record (`errNoRecord`). If the head names a key that is not there, the
   record is untrusted (`errRecordUntrusted`).
2. **Envelope.** Size bound, CBOR, envelope version, digest, and payload version equal to the envelope's. Any
   failure is `errRecordUntrusted` or `errRecordVersion`.
3. **Context.** The record's context must equal configuration (`errWrongContext`).
4. **Certificate.** It must authenticate (`errCertificate`), be for this network, partition, shard and
   configuration (`errWrongContext`), and name B's block hash, state and round (`errWrongBlock`).
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

8. **Currency** (readiness for B's child only). The live certificate must authenticate and must be for B's
   block and round (`errStale`).

**Never a fallback.** An unreadable, foreign or unverifiable head record is not replaced by an older retained
record, the legacy certificate file, the executor's head, or a zero cursor. The executor, not the record,
decides where the node is, and an older record would present an older state as current.

## 7. Crash and fault cases

Record(P) is durable and the executor is at P. The node then processes B, P's child. Model tests are in
`contract_test.go`.

| # | Fault | Reload outcome | Test |
| --- | --- | --- | --- |
| 1 | crash after observing B, before the executor commits | ready for P locally; the live certificate for B makes it stale | `TestCrashBetweenPipelineSteps` |
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
| 12 | whole-store rollback, with the executor ahead or also rolled back | not ready, or locally consistent but stale for the live round | `TestWholeStoreRollbackCannotTestifyToCurrency` |
| 13 | empty replacement disk | no record: not ready | `TestReplacementDiskAndMigration` |
| 14 | a live certificate for the recorded block that the root chain did not issue; a future envelope version; an oversized stored value; an issued certificate for another network naming the recorded block; a block hash of the wrong width | `errCertificate`, `errRecordVersion`, `errRecordUntrusted`, `errWrongContext`, `errWrongBlock` | `TestChecksNoOtherRuleCovers` |

Rows 1 to 13 also pass through `TestHappyPathEndsDurableReady`, `TestRetentionIsPartOfTheWrite`,
`TestPersistRefusesToClaimMoreThanItEstablished` and `TestTheRecordHoldsNoSigningState`, and
`TestFixtureChainVerifiesAsFinalizedParents` checks the fixture chain itself.

**Mutation check.** Run locally, one mutation at a time, with the model files restored and compared after each.
Each of the 27 rules the model enforces was disabled in turn: 15 in the pipeline, retention, reload and readiness
(`contract_test.go`) and 12 in decoding and re-verification (`record_test.go`). Every one fails at least one test.

The first pass was not clean:
- **Did not compile:** 2 mutations, rewritten.
- **Not applied:** 1 mutation, because my pattern had the wrong indentation.
- **Hidden:** 7 results. My output filter dropped the only failure line that tests without subtests print.
  Rerun unfiltered, two of the 7 were already killed.
- **Genuine survivors (5):** live-certificate authentication, envelope version, the stored size bound, the
  certificate's context and block-hash width. In each case an earlier check refused the same input first.
  `TestChecksNoOtherRuleCovers` isolates each rule, and all five are now killed.

## 8. Limitations, stated explicitly

- **Whole-store rollback.** A restored backup or cloned disk is internally perfect, and nothing in the store can
  tell that it is stale. Only the executor's head and the live certificate expose it. This contract never makes
  durability a claim of freshness.
- **Replacement disk, retained executor.** With no record, the node is not ready for any non-genesis child.
  It must obtain the certificate and `witness(B)` for the executor's certified head from the network: the
  certificate from the live feed or #92 anchor evidence, the witness within the client's proof window or
  through #15.
- **Replacement host, fresh executor.** The executor must first reach a certified block, by execution-client
  sync that this contract does not define. Until then the executor is behind or empty and the node is not ready.
- **Genesis.** With a wiped store and the executor at genesis, the genesis record can be rebuilt from
  configuration. `registrygenesis` derives `witness(evmGenesisHash)`, and the genesis certificate comes from the
  network. It is then verified and persisted like any other record. Readiness for a payload whose parent is
  genesis still requires #153 §7.3 E1 to E4.
- **Migration from `FileStore`.** The legacy file holds only the latest certificate. After re-authentication a
  migration may treat it as an observed certificate. It carries no witness, so it creates no readiness
  (`TestReplacementDiskAndMigration`). The file is left in place, as `LoadLUC` already does for legacy formats.
  No public state exists yet, so no in-place conversion is defined.
- **Backend durability** is an assumption of this model (§4), not a property it demonstrates.
- **Signing.** Restored voting stays governed by ADR 0009 and the F6c contract. A durable record gives no
  signing history, and every authority restart still ends that voter's signing for the current assignment.

## 9. What the next units own

| Unit | Owns |
| --- | --- |
| storage implementation (#14) | the bbolt schema for this record; establishing the backend durability assumption; the retention parameters; fault injection against the real store |
| node wiring (#14, after the storage unit) | capturing at commit before the next block; writing the record; the reload sequence of §6 at startup; the readiness gate for B's child alongside P-id |
| #15 | serving retained records and witnesses to peers; obtaining `witness(B)` after the proof window has passed |

## 10. Not in this unit

No production code, store schema, migration, node wiring, peer protocol, activation, `v0` removal or
WithSealV1 advertisement. The signing record is untouched. #10, #11, #12 and #14 stay open.
