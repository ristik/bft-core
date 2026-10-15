# GetTrustBase peer protocol and the release bundle

Package `gettrustbase`. Design: briefs/utb-signed-entries-design.md §7 (PR6).

**Stream.** `/unicity/get-trust-base/1.0.0`, one request and one response per stream, each a uvarint length plus one tagged deterministic CBOR object. Tag numbers 39014 (request) and 39015 (response) are provisional until the registry assigns them (`gettrustbase.RequestTag`/`ResponseTag`, the only place they appear).

```text
Request  = [version=1, network, fromEpoch, toEpoch|null, snapshotEnd|null, snapshotEntryID|null, maxEntries, maxBytes]
Response = [version=1, network, status, fromEpoch, effectiveEnd, endEntryID|null, entries[], nextEpoch|null]
```

* The first page takes one snapshot of the finalized tip: `effectiveEnd = min(toEpoch, tip)`. Later pages echo `(effectiveEnd, endEntryID)` as the snapshot, so the end does not move while the tip grows and any peer whose history reaches it can continue. A peer behind it answers `NotYetAvailable`, one on another history `HistoryMismatch`. The cursor is a consistency hint; the client authenticates every entry from its latest held entry (`utbstore.Append`).
* `fromEpoch` ahead of the tip is `NotYetAvailable` with no entries; an end ahead of the tip is clamped. A page is a contiguous ascending prefix within the entry and byte budgets, never empty with a cursor (`LimitTooSmall` instead). A hole in finalized history is `Unavailable`.
* Caps: 64 entries and 1 MiB per page, 64 KiB per entry, 1 KiB request, 5 s deadline, two in-flight requests per peer and 32 node-wide (excess gets `Busy`). A client may lower the budgets, never raise the server's. The server refuses to start if one maximum entry plus the envelope does not fit.
* Entries are the stored canonical bytes, embedded verbatim.

**Release bundle.** The same response object with `status=OK`, `fromEpoch` = the genesis epoch, `effectiveEnd` = the release tip, every entry ascending and `nextEpoch=null`. `ubft trust-base utb-export` writes it from a root's store; `utb-verify` checks it offline against the pinned genesis EntryID (genesis pin, then every entry's strict quorum of its predecessor's members); `utb-import` loads it through the store's single append path (an older bundle neither truncates nor rolls back; a conflicting record is refused). A partial range is not a bundle. The 64-entry/1 MiB limits do not apply to bundles, which are bounded by an explicit file budget.
