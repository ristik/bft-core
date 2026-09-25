# M2a certified frontier, version 1

Status: the codec and planner remain in `frontier`; the opt-in M2a runtime
is wired through `configuredprogress` and `archivewiring` by PR B. The journal
is the only recovery owner. `--archive-prune` defaults to off and requires the
archive store and two configured replica peers.

The journal's first Bolt transaction stores every covered request, the
certified anchor record and its frontier together. A second transaction
deletes eligible hot candidates and observations and raises the prune floor.
On restart, the node authenticates the anchor with the configured trust base,
re-reads both replicas and loads only the suffix after that anchor. The
execution client's authenticated snapshot is the H4 restore input; archive
material never serves as a replacement trust pin. The worker audits covered
archive promises in bounded pages and repairs a missing replica from a
surviving verified copy. A missing copy halts further frontier work while
ordinary certification retains its independent journal path.

## Certified record and acknowledgement

A frontier names one certified anchor by root round, EVM height, block hash,
state root and a monotonic local sequence. Its archive request embeds the full
network, partition, shard, epoch, genesis, registry and execution identity
context. The `CertifiedBinding` adapter must verify those claimed fields
against the canonical header and resulting UC/TR, under an independently
trusted root/shard trust base, before an advance. The record is archive data,
not its own certificate. A local supplied height, round or state root cannot
establish the binding. The inert tests use a fake verifier; production
certification remains a child PR obligation.

Each `ARCHIVE1` manifest is single-subject. For an advance from height H to
height K, `PlanAdvance` therefore requires one `Coverage` item for **every**
height in `(H,K]`, in order and without gaps. Both configured replicas must
acknowledge every item's exact request and the digest returned by
`archive.ManifestDigest` for that canonical record. The helper is checked
against the manifest bytes actually published by `archive.Put`. Anchor-only
acknowledgements never license deletion of intermediate records. The selected
anchor must equal the last covered item, including sequence, round, height,
block hash and state root. The prune boundary includes the anchor's hot entry;
recovery uses the retained certified anchor and a fixed suffix after it.

The authentication choice is **local read-back**. Before planning an advance,
the future `ReplicaAvailability` adapter must contact each configured,
independently stored replica through its authenticated endpoint, re-read the
exact manifest and all chunks, validate `ARCHIVE1` checksums and compare the
manifest digest to the node's own canonical-record digest. A caller-created
`sha256(request)` receipt is insufficient. The names in an inert ack are only
slots; the trusted adapter binds each slot to its configured endpoint and
returns success only after durable publication and verified read-back.
`PlanAdvance` refuses a missing adapter or failed read. Re-read the current
frontier at restart and before each advance, and audit every still-promised
archived record on a paced cycle no longer than 24 hours; a missing copy
raises an alert, starts re-replication from the surviving verified copy, and
halts advance/prune until two replicas re-attest. If either copy is lost after
pruning, recovery is degraded and admission backpressures rather than claiming
two-copy availability. A single surviving copy is never a fresh prune basis.

The codec has a domain, version, fixed-order big-endian fields, bounded
canonical archive request, two configured replica names of 1 to 64 bytes,
two digests and a SHA-256 corruption checksum. The checksum is not a MAC.
Decode checks the configured context and a journal-supplied sequence floor;
it refuses trailing bytes and noncanonical NUL-padded names. `Save` decodes
its newly encoded bytes before replacing an existing good file. `Load` caps
file reading at `MaxBytes` and refuses a larger or nonregular file.

## Journal order, crashes and epoch change

The required runtime order is **both durable replica acknowledgements, then
frontier commit, then prune**. The first journal Bolt transaction stores the
frontier, certified association and covered-range evidence together. A later
Bolt transaction deletes eligible hot entries and raises the minimum sequence
and prune floors atomically with that deletion. Both transactions use the
existing journal recovery owner and lock. The separate `frontier.Store` file
is an inert codec/crash fixture only; it must not become an independent
recovery authority. The runtime rechecks certification, manifest, replica and
obligation gates under the journal lock before frontier commit, then rechecks
the durable frontier and obligations before prune. Prune is idempotent. Never
prune before the frontier commit or raise a floor without the corresponding
deletion.

A crash after acknowledgements but before the frontier write leaves the old
frontier and journal intact; the acknowledgements are discarded or re-obtained
and nothing is pruned. A crash after the frontier transaction but before
pruning restarts from the new durable frontier and repeats the planned prune.
A copied or rolled-back frontier below the journal's already-pruned round or
sequence floor is refused as `ErrStale`; the floor is committed in the same
Bolt transaction as the prune. `TestRecoveryOrderingAndReplicaLoss` exercises
both windows and the rollback check in the inert store model. The wired PR
must add SIGKILL tests at those Bolt boundaries.

The hot journal retains a bounded suffix plus unresolved bodies, pending
authorizations and non-equivocation obligations regardless of age. Any such
obligation at or before the proposed frontier blocks pruning. Normal restart
authenticates the frontier and bounded suffix, never replaying from genesis.
Corrupt, copied, stale or incompatible frontier state refuses ordinary voting;
reconstruction requires an independent checkpoint/trust pin and both replica
archives. The archive cannot supply its own trust anchor.

The archive context includes shard and root epochs. On an authenticated epoch
transition, close the old frontier at its last certified interval and start a
new frontier/sequence namespace under the new complete context and activated
trust interval. No cross-context `PlanAdvance` is valid; the journal commits
that context switch with the activated record and retains the old anchor for
historical export until its separate retention policy permits removal.
