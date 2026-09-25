# M2a certified frontier, version 1

This PR defines a frontier record and an inert advance planner. No production
reader, journal mutation, pruning, or replica transport uses them yet. The
configuredprogress journal remains the single recovery owner. Its existing
`LoadJournal` scan and progress transaction at `configuredprogress/journal.go`
must be extended in the later wired PR; a second recovery path must not be
introduced.

## Record and identity

The frontier identifies one certified anchor by round, EVM height, block hash,
state root, and a monotonic local sequence. Its archive request embeds the full
[archive context](m2-archive.md): network, partition, shard, epochs, genesis and
registry commitments, and canonical execution identity. The archive request's
block hash is the anchor hash. The identity field is supplied through the
archive `Identity` interface; the concrete WP1 identity is still pending.

The frontier stores two acknowledgements. Each names one configured replica,
its digest of the exact encoded archive request, and its digest of the complete
published manifest. Both manifest digests must match. Acknowledgements mean
durable availability of all recovery and export bytes at those configured,
independently stored replicas. They do not authenticate certification or grant
freshness. The later runtime must obtain them after each replica's durable
publication and verify the anchor's UC/TR association itself. A caller cannot
promote a local archive `Put` result or cached provider claim into an ack.

The version 1 codec has a domain tag, version, fixed-order big-endian fields,
bounded canonical archive request, configured replica names, two digests and a
SHA-256 checksum. Decode checks its version, canonical bytes, context, both
replica slots, ack binding and an independently supplied minimum sequence.
The checksum detects corruption; it is not a MAC. An authenticated journal or
checkpoint must supply the expected context and sequence floor. A copied or
stale file cannot set its own validation policy.

## Atomic advance and pruning

`PlanAdvance` requires both acknowledgements and strictly increasing sequence,
round and height. It rejects an unresolved certificate body, pending
execution authorization or non-equivocation obligation at or below the proposed
frontier. The planner returns a prune-through round and deletes nothing. The
later journal transaction must recheck these gates under its own lock and
atomically associate the frontier with certified progress before deleting any
hot entries. A planner result alone cannot authorize deletion.

The file store writes a temporary record, syncs it, renames it over the old
record and syncs the parent directory. A fault after rename may leave the new
record visible despite an error; a caller reloads before retry. The store is
inert and single-process. The wired design must coordinate its commit with the
journal's Bolt transaction so a crash cannot leave a prune decision ahead of
its certified association. Kill tests belong to that integration PR.

The hot journal retains a fixed suffix after the frontier, plus unresolved
bodies, pending authorizations and non-equivocation obligations regardless of
age. A normal restart authenticates the frontier and checks only that bounded
suffix; it does not replay from genesis. The existing journal remains the
recovery verifier and must validate continuity from the certified anchor.

If a local frontier is corrupt, stale, copied, or version-incompatible, the
node refuses ordinary recovery and never votes from it. Reconstruction uses an
independently authenticated checkpoint/trust pin and the two replica archives
to rebuild certified association, then writes a new frontier and suffix. The
archive cannot supply its own trust anchor. An archive outage or missing second
ack stops frontier advancement and pruning; bounded hot storage eventually
backpressures admission. It must never bypass certification or stop safety.
