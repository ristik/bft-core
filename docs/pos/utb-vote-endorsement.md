# Signed trust-base entries in the committing vote (UTB PR3)

Implements `briefs/utb-signed-entries-design.md` §4. Behind the per-epoch configuration bit `votesig.Config.UTB`; nothing is enabled until a deployment's
genesis or Q3 tuple says so (fresh deployment, new genesis: owner §29).

## Wire

- **Envelope version 3** `[3, inner, utb|null]`, for votes (`abdrc.VoteMsg`) and certificates (`drctypes.QuorumCert`). `inner` is the unchanged scheme 1 or
  scheme 2 encoding, so the signing scheme and the envelope are independent. A message is version 3 exactly when its epoch's authenticated configuration has
  `UTB`; a version 1/2 message in a UTB epoch, a version 3 message outside one, an endorsement outside the envelope and a nested envelope are all refused
  (`votesig.ErrEnvelope`). The genesis certificate is fixed by the software and exempt.
- `UTBVote{unsigned, signature}`: the voter's signature over `types.RootTrustBaseV2.SigBytes()` of the successor entry. `UTBCertificate{unsigned, signatures}`:
  the aggregate. The entry's identity is SHA-256 of `unsigned`. Strict decoding (duplicate map keys refused).
- Q3: the tuple `q3format.Q3ConfigUTB` (revision 3, vote codec 3) is the only other valid protocol tuple; `History.Signing` reports `UTB` from it.

## Who signs what

- Only a **committing** vote whose committed round's executed state is the committed handoff of the vote's epoch carries an endorsement
  (`UTBSuccessor.Entry`: the record of the executed block, the retained successor body (V2 or Q3, one builder, the record's actual `ActivationRound`) and the
  finalized entry of the voting epoch). Every other vote of a UTB epoch is version 3 with a null endorsement. Nothing is signed at Prepare, Freeze or any
  non-committing vote, so an abandoned attempt pins nothing.
- Scheme 1: a second signature next to the one over the seal bytes. Scheme 2: a third, independent signature next to the vote and seal signatures, over the
  same entry bytes.
- If the entry cannot be derived (executed state or body unavailable, no finalized predecessor) the node does not vote (`ErrNotSafeToVote`); with no source
  at all, `ErrNoUTBSource`.
- **Durable decision** (both schemes in a UTB epoch): the statement recorded with the complete signed vote includes the entry (or its absence). A restart
  returns the recorded message; another entry, or none after one, for the same (epoch, round) is `ErrDecisionConflict`. Scheme 1 votes of other epochs keep
  their unchanged, non-durable path.

## Aggregation and verification

- The register groups by (commit identity, envelope, endorsed `EntryID`): votes endorsing different entries, or endorsing and not, or of different envelopes,
  are never counted together, and a voter that changes its endorsement is an equivocator.
- `VoteMsg.Verify` / `QuorumCert.VerifyScheme`: envelope rule, then the scheme's signatures, then the endorsement: committing only, entry strictly decoded
  (`utb.DecodeUnsigned`), epoch = voting epoch + 1, the configured network, and for a certificate the endorsers are exactly the voters, every signature strict
  (`VerifySignedStrict`) and the weight reaches the voting committee's threshold.
- **Contextual binding** (`storage.UTBBinding`, applied in `BlockStore.ProcessQc` before the certificate is inserted, committed, published or installed): in a
  UTB epoch a committing certificate carries exactly the entry the node's own executed state implies, and no certificate carries one the state does not
  imply. Applied to live proposals and to the replay of recovery blocks (both go through `ProcessQc`).

## What the endorsement is not covered by

The endorsement sits outside the inner vote (the vote's own signatures do not cover it), so a relay can strip it from a vote. That costs liveness only: the
vote then regroups as "no endorsement", and the binding refuses a handoff-committing certificate without one. It cannot be forged or swapped, because the
endorsement is the voter's own signature over the entry bytes, which the register groups by (EntryID). Protocol revision 3 (`Q3ConfigUTB`) is admissible from
the PR that wires the entry store (PR4): before it nothing produces the tuple and the manager fails closed without the store.

## Not in this PR (PR4)

Retaining the finalized entry and certificate with the commit unit and the entry store feed (`utbstore`), the installers' verification of the retained entry,
bundle and closure carriage, and the first checkpoint. The manager is wired through `consensus.WithUTBPrevious`, which PR4 backs with the store; until
then no deployment sets it. Historical handoff proof verification (`handoff.VerifyOldCommitProofSigning`) is unchanged here.
