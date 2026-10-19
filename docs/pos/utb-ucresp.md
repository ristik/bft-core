# Signed trust-base entries in the certification response (UTB PR5)

Design §6. Continues `utb-retention.md`. Enabled on a root by `--utb-genesis`/`--utb-genesis-id` (the same flags enable it on a shard node); without them every
message is exactly what it was.

## Wire

- Protocol `/ab/certificates/0.0.3` (`network.ProtocolUnicityCertificatesV3`) carries `certification.CertificationResponseV3`, beside `/ab/certificates/0.0.1`
  (`CertificationResponse`) and upstream's `/ab/certificates/0.0.2` (the partition-view sidecar, `CertificationResponseV2`, which this deployment does not use
  for trust-base entries: the same protocol id with other bytes was the collision the combined version resolves). The presence of the entries and of the view
  is announced by the protocol and by the explicit version (the first field), **never by the array length**: a version 3 reader refuses every other form and
  the other readers refuse version 3. A deployment that publishes entries sends only this protocol to its UTB peers (no fallback to a format that would lose
  the entries or the status).
- `CertificationResponseV3 = [3, [partition, shard, technicalRecord, uc, status, message], partitionView | null, trustBaseUpdates]`. The wrapped response is the
  legacy response with the same meaning (the wrapped UC is the last-good certificate whatever the status; the view is optional, null when omitted or over its
  limit, never an empty string, and is never part of the UC). `trustBaseUpdates` is a list of **at most two**
  entries (`MaxTrustBaseUpdates`), each at most 64 KiB, each the canonical bytes of a `types.RootTrustBaseV2` (tag 39000, version 2) as the root's
  `utbstore` holds them, ascending by epoch. The genesis is never attached. Bounds are enforced when encoding and when decoding.

## Root side

- A node with `SetEntryOffers` answers every response, direct (handshake reply, rejection) or to its subscribers, on the version 3 protocol; one message per
  subscriber, because the entries differ per recipient.
- `StoreOffers.Offer(recipient, signerEpoch)` attaches the (at most two) **highest** finalized entries with epoch `<= signerEpoch+1` and above the
  recipient's hint, where `signerEpoch` is the epoch of the response's own UC seal. The attachments are therefore bound to the UC: a repeated old UC never
  carries an entry newer than its signer epoch's successor, whatever the store finalized since. The store is read at call time, so only finalized entries
  are ever attached.
- The hint is the highest epoch offered to the recipient **and sent successfully**: a failed send leaves the update pending. It is in memory and bounded, reset
  on a handshake and on restart. It is not an authority or an acknowledgement: a recipient that missed entries (more than two epochs) is repaired by
  GetTrustBase (PR6), never by attaching the chain.

## Shard side

`BFTClient` (with `BFTClientOptions.UTBStore`) ingests each version 3 response before the certificate is looked at, including the responses the queue later
drops as stale: every attached entry is appended to the client's `utbstore` (strict decode, member limit, `VerifySuccessor` from the stored predecessor, the old
committee's quorum). An entry that does not authenticate is dropped and stops the rest of that update; an entry that does not follow the store's tip calls
`OnTrustBaseGap(have, got)` so the consumer fetches the range; each newly appended entry calls `OnTrustBaseEntry` (derive the committee with `utb.Projection`).
The certificate is then judged by the unchanged checks under the client's own epoch rules: valid entries never make a rejected response accepted, and invalid
ones never affect the certificate. A client with no store ignores the entries and behaves as before.

## Reference fixture for aggregator-go

`network/protocol/certification/testdata/ucresp_v3_vectors.json` (frozen by `TestUCRespV3ReferenceVectorsAreFrozen`; regenerate with `-update-ucresp-vectors`):
a deterministic four-member chain (fixed keys, RFC 6979 signatures), the genesis entry and its EntryID (the pin), the entries of epochs 2–4 with their EntryIDs,
and encoded messages: `acceptedWithView` (OK, epoch 2 and a partition view) with `upstreamV2` (the same response and view in upstream's sidecar format), `acceptedTwo` (OK, epochs 2 and 3), `rejectedOne` (RequestInvalid carrying epoch 4), `acceptedNone`, and `legacyEquivalent` (the
0.0.1 encoding). An implementation passes when it (1) decodes each message strictly and re-encodes it byte for byte, (2) authenticates epochs 2 and 3 from the
genesis by the entry rules (`VerifySuccessor`: network, epoch+1, start, `previousEntryID` = predecessor's EntryID, strict quorum of the predecessor's members
over the unsigned bytes; EntryID = SHA-256 of the unsigned bytes), (3) finds that epoch 4 does not follow the genesis and asks for the missing range instead of
accepting it, and (4) treats the rejected message's certificate as a rejection regardless of its valid entry.

## Not here

The range protocol and the export (PR6, dev3), the SDK-facing API of the aggregator, and a shard node deriving and installing the committee a new entry names
(the callback is the seam). The shard-side integration is tested at the ingest function and through the real coalescing queue; the libp2p transport of the new
protocol is registered and covered by the network registration test, not by a live run.
