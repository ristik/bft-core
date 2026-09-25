# M2a certified-record archive, version 1

This is the inactive contract and local store for M2 WP2a. It does not enable
publication, retrieval over a network, pruning, replacement recovery, or proof
export. The schema reserves extensions for the M2b proof bundle; no verifier is
provided here. The principles of exact context and typed responses follow
[F7's retrieval design](f7-parent-registry-witness-archive.md).

## Subject and record

The key is the **full context plus exact block hash**, never a height, head tag,
or shortened context digest. Context version 1 contains network, partition and
shard ID (the bounded, length-prefixed canonical `types.ShardID.Bytes()`
bitstring); shard and root epochs; full shard configuration hash; exact registry
address and code hash; genesis commitment and EVM genesis hash; and the canonical
versioned execution identity. WP1 must supply the complete identity, including
fee profile and collector, through `archive.Identity`. `RawIdentity` is only an
inert fixture adapter until WP1 merges. Different epochs or identities produce
different keys even when the block hash is the same.

TODO (WP1): answer whether the canonical identity bytes commit to the trust
set and its version; align this context with the trust binding in `rootinput/v2.go`.

A record retains the raw header and body, canonical root input, original UC/TR,
resulting UC/TR, and companion. The version 1 parent-accounting slot is present
with zero length; a later schema may carry it. The original pair derives the
block's root input; the resulting pair certifies the block hash and state root
(see [D2-A](d2a-execution-journal.md)). All nine slots are present; eight are
nonempty and parent accounting is empty in version 1. Versioned extensions can
later carry proofs and transition material.
This version does not interpret extensions or certify the retained bytes.

The execution client's parent accounting is reproduced by contiguous checked
seal-import replay: the payload and authenticated seal companion execute on the
exact certified parent state, using that parent's checked accounting token. The
configured genesis supplies the initial zero-system-gas token. A snapshot restore
starts with the parent accounting token from the independently authenticated
execution-client snapshot (H4 scope), then replays forward. Neither a header nor
an archive response alone establishes the gas split. A missing token is
unavailable and blocks import until its predecessor is restored or replayed.

## Publication and durability

The local store writes each chunk into a private temporary directory, syncing
each file. It writes a manifest with the full encoded request, ordered chunk
names, lengths, SHA-256 chunk digests, and a SHA-256 manifest checksum. It syncs
the manifest and temporary directory, renames the directory to its permanent
key, then syncs the parent directory. A prepublication failure leaves only an
ignored temporary directory. Published keys are immutable; an idempotent write
must match the complete existing record. The local key path is a SHA-256 index
of the full encoded request, not an authentication claim. A reader checks the
full request, manifest checksum, every required chunk and digest, and the
Keccak-256 hash of the retained header before returning any bytes. A missing
chunk yields unavailable, never a partial successful record. A damaged local
copy yields unavailable to the consumer so it can try the other replica; no
bytes are returned. Filesystem failures after rename can leave
the record published while the caller receives an error; callers must re-read
before retrying. A single process owns the store; cross-process writer locking
and recovery of orphan temporary directories belong to the later wiring.

There is **no durable availability acknowledgement** in this PR. The later
frontier may advance only after two independently stored, configured replicas
durably acknowledge the exact record and its complete manifest. A receipt of
durable availability is a retention claim, not evidence of certification,
freshness, authenticity, or future peer health. The frontier must bind those
acknowledgements to its own authenticated subject and policy before pruning.

## Request and response

The fixed-order binary codec uses distinct `archive/request` and
`archive/response` domain tags, each followed by version 1. Network ID uses
the bft-go-base 16-bit width, partition ID uses its 32-bit width. Integers
are big endian, and the shard ID, identity and chunks are length-prefixed.
There is a single requested subject. There are no batches,
ranges, redirects, latest tags, or server-selected identities. A response echoes
the exact request and has one outcome: `ok`, `unavailable`, `busy`, or `invalid`.
Only `ok` carries a complete record. `unavailable` means this provider cannot
serve it, including local copy damage; `busy` means bounded admission was
exhausted; `invalid` means the request was refused. None is a global verdict.
A refusal with payload or a
success with missing data is malformed. Consumers reject a wrong echo.

The hard codec ceilings are 4 KiB for execution identity, 8 MiB per chunk,
32 MiB for all record data, 16 extensions, and about 32 MiB for a response.
Decoders check lengths before allocation and reject noncanonical shard IDs.
A future peer transport must validate the request before `Serve`: a malformed
request has no canonical echo for an encodable refusal. It must enforce
frame, in-flight byte/work, concurrency and deadline limits **before** decode;
it must choose peers from a fixed configured list. Requests must be bounded
to one subject and chunks transferred with bounded byte ranges. These transport
limits and peer selection are requirements for later wiring, not implemented
by the inert store.

## Consumer authentication

The consumer starts with independently authenticated context, target hash,
certificate/trust history, and continuity anchor. It checks the exact response
echo, then re-verifies header, root input, original and resulting UC/TR roles,
companion and any required state witness against those local
pins. It must derive the header hash and state root from evidence, check the
resulting certificate's association, and reject missing or substituted evidence.
It cannot adopt a provider's stated trust set, checkpoint, freshness, or
availability verdict as authority. The archive is a source of bytes; it cannot
restore signing authority or establish a fresh PoA trust anchor.
