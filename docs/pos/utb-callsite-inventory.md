# Signed trust-base entries: call-site inventory (UTB PR2b/c)

Companion to `briefs/utb-signed-entries-design.md` §3, §8, §10. Source: bft-core at the head of this PR. The new profile (version-2 entries, `utb` builder,
`utbstore`) is not enabled; the V1 chain remains the only active lineage. "Switch" means: in the PR that enables the profile, the site derives the entry
through `utb.BuildUnsigned` (or reads `utbstore`) and uses `EntryID`, not a `RootTrustBaseV1.Hash`.

## 1. Where the pieces are now

| Piece | Location | Status |
|---|---|---|
| Entry type, strict decoder, `EntryID`, strict verification | `ristik/bft-go-base` `types.RootTrustBaseV2` (go.mod `replace`, #630) | merged |
| Canonical builder, V2/Q3/projection adapters, 16-member limit | `utb` | merged (#630) / extended here (`FromProjection`, unsigned predecessor) |
| Unsigned chain of a Q3 history | `q3format.History.UTBUnsigned` | this PR; test: projection path = body path, link = predecessor `EntryID` |
| Permanent entry store (append, replay rules, paging) | `utbstore` | this PR; nothing writes to it until the commit exchange carries signatures (PR3/4) |

## 2. Lineage and identity uses of a trust-base hash (V1 `Hash()` includes signatures)

| Site | Use | Class | Switch in |
|---|---|---|---|
| `rootchain/consensus/bootstrap.go:64,73,103` | V2 install: predecessor compare, `WithPreviousTrustBaseHash(oldID)` | lineage | PR4 (installer verifies the retained certificate, derives the entry via `utb`) |
| `rootchain/consensus/bootstrap_q3.go:76,107` | Q3 install: `projected.PreviousEntryHash = oldID` | lineage | PR4 |
| `rootchain/consensus/trustbase/verified_v2.go:25-38` | `InstallV2Projection`: link and replay equality use `PreviousEntryHash` | lineage | PR4 (replay = same `EntryID`; witness differences are not conflicts) |
| `q3format/history.go:155,176` | Q3 genesis ID = `genesis.Hash`; projection copies `PreviousEntryHash` | genesis identity | PR3 codec freeze: Q3 genesis binds the V2 genesis `EntryID` (new profile pin) |
| `evmroot/d3weights.go:246-262`, `d4handoff.go:413`, `d3vectors.go:318` | `V1Anchor.HashIncludingSigs` and `FirstV2PredecessorHash`: first V2 body bound to the exact V1 entry | genesis/first-body binding | PR3 (explicitly versioned binding to the V2 genesis `EntryID`; the old bytes are never reinterpreted) |
| `rootchain/consensus/storage/handoff_authority.go:162-167`, `handoff_operator.go:266,434`, `handoff_operator_v3.go:105` | predecessor hash for the first V2 handoff | first-body binding | PR3 |
| `trustactivation/verify.go:56-60`, `trusthistorystore/store.go:93-97,163`, `m2contract/contract.go:125-144` | M2 history anchor (`V1Anchor`) | genesis/first-body binding | PR3/4 |
| `shardnode/trustbase_history.go:93,156`, `cli/ubft/cmd/shard_node_q3.go:138`, `shard_node_run.go:555` | shard-side predecessor/activated hashes, genesis check | lineage, genesis | PR4 (shard restore reads `utbstore`/bundle-carried entries) |
| `cli/ubft/cmd/root_node.go:303`, `cli/ubft/cmd/trust_base.go:107,127,303` | genesis anchor hash at startup; the trust-base generation/inspection tool | genesis pin, tooling | PR1-tooling follow-up (null-signature genesis/pin tool) |
| `bridgeprofile/refb1.go:32`, `bridgeprofile/authority.go:83,127,191` | reference B1 identity; JSON import of `previousEntryHash` | identity / JSON input | PR7 (regenerated pins) |
| `rootinput/v2.go:37`, `frontierclient/collector.go:214-217`, `frontier_sampler.go:316` | size bounds counting `PreviousEntryHash` | not lineage (bytes bound) | stays; V2 entries add `PreviousEntryID` of the same length |
| `internal/testutils/*`, `scripts/h4-restore-pin/main.go` | fixtures / pin tool | test or tooling | with the sites above |

Not trust-base lineage (listed so they are not mistaken for it): `pdr.Hash`, `shardConf.Hash`, `VoteInfo.Hash`, `Block.Hash` call sites (`mintproof`,
`block_tree.go`, `block_executor.go`, `block_store.go`, `consensus_manager.go`, `posclosure`, `partitions`, `signingauthority`, `evmassign`, `s1ref`,
`q4replay`, `q4shim`) are other objects' identities and do not change.

## 3. Strict signature maps (D7)

`quorumweight.VerifySigned` is the lenient tally: an unknown signer rejects, but **an invalid signature from a known member is skipped**. `VerifySignedStrict`
refuses it. A V2 entry is verified only by `RootTrustBaseV2.VerifyQuorumSignatures` (strict), through `utbstore.Append` and `VerifySuccessor`.

| Site | Verifier today | Needs for D7 |
|---|---|---|
| `quorumweight.VerifyTrustBase` (`internal/quorumweight/quorumweight.go:205-219`) | lenient `VerifySigned` (V1 entry check) | V1 only; V2 uses go-base. Keep for legacy readers; a V1 caller in a V2 profile is a bug. |
| `Checked(tb)` UC verification: `shardnode/{anchorevidence,bftclient,node}.go`, `mintproof/verify.go`, `rootinput/{rootinput,v2}.go`, `abdrc/recovery.go`, `bridgeprofile/authority.go`, `frontier_sampler.go`, `certifiedstore/record.go`, `signingauthority/authority.go` | lenient (go-base `UC.Verify` calls `VerifyQuorumSignatures`, replaced by `VerifySigned`) | **Native UC/seal signing is outside this change** (design §1); ordinary UC bytes keep their rule. Strict parity for seals is a separate prerequisite decision. |
| `rootchain/consensus/types/quorum_certificate.go:334` (`VerifySigned`), `:423,427` (strict, scheme 2) | lenient scheme 1, strict scheme 2 | PR3: an H-committing QC's UTB signature map is strict in both schemes |
| `handoff/old_commit_proof.go:89`, `storage/handoff_authority.go:317`, `frontierclient/collector.go:601` | `VerifySignedStrict` | already strict |
| `evmroot/d4handoff.go:373,380` (`CommitQC.Verify(old)`) | go-base/QC verify through the old trust base | PR3/4: contextual binding to the committed H and the endorsement |

## 4. Entry store contract (`utbstore`)

- Open: genesis must be a valid genesis entry whose `EntryID` equals the deployment's pin; a database with another genesis, a gap, a corrupt, a non-chaining
  or an over-limit entry is refused; nothing may exist beyond the first gap.
- Append (only way in): strict decode, the 16-member deployment limit, `VerifySuccessor` from the stored predecessor, atomic write. Replay of a stored epoch:
  same unsigned bytes (same `EntryID`) and a valid witness is idempotent and keeps the first stored witness; different unsigned bytes is `ErrConflict`; an
  invalid witness is refused even when the `EntryID` is cached; a gap is `ErrGap`.
- Serving: `Get` returns the stored bytes; `Range` returns a contiguous ascending prefix within entry and byte budgets, the first unsent epoch, and
  `ErrBudget` (never an empty page with a continuation) when one entry does not fit.
- Separation: the store holds the finalized tip only; the locally activated root epoch is a different fact, tracked by the installer.
