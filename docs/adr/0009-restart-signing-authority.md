# ADR 0009: independent signing authority for shard-process restart

Status: **Proposed**, #105 design review. No activation or runtime change.

## Context

#92 recovers an authenticated execution anchor. It cannot tell a restored shard
process what that validator previously signed. A valid older UC and an unchanged
executor through quiet rounds can both be replayed. A local signing file alone
has the same problem under whole-store rollback.

## Proposed decision

Adopt the narrowly supported private profile in
[the F6c signing-state contract](../design/f6c-signing-state-contract.md): an
independent key-owning authority, immutable enrollment scope, operator-controlled
generation fencing, complete-request reservation before signing and retained exact
response before release. Preserve legacy BCR signed bytes and standard Engine API.
Do not use authorizing root round or caller-selected epoch/config as a fresh
conflict namespace for the same assigned partition round.

The first profile survives shard-process restart only. Authority key custody is
volatile and non-exported; authority loss removes signing availability. No recovery
of that old key from a replayable journal or import endpoint exists. A fresh key
requires separately authorized genesis/assignment; this ADR authorizes neither.
Existing exported validator keys cannot be silently migrated. Authority host
snapshot/cloning/compromise is outside the profile and must be operationally
excluded. A recoverable authority requires a later, explicit trust contract.

## Consequences

This avoids making ordinary fsync a claim of anti-rollback freshness and avoids
new root-consensus or execution-client protocols. It introduces a trusted authority
and reduces availability on its failure. Deployments needing signer-host recovery
cannot use this profile as a complete solution. Restored voting stays disabled
until authentication, memory-state isolation, fencing, integration and private acceptance
work described in the contract has passed independent review.

The test-only model is design evidence, not proof of a storage backend, host
isolation or production certificate verification. #14 retains full crash-durability
scope. #105 remains open.

## Review disposition

Q2 (one statement per assigned round) and Q3 (no silent import of exported keys)
are accepted as the proposed design rules. Q1 is recommended only for disposable
private deployments: **every authority restart, including planned maintenance,
permanently loses that voter from the current assignment**. No key-replacement
procedure is implemented yet; the initial recovery option is separately authorized
fresh genesis, pending H-series/#10 replacement support. This is not a production
availability profile.

The signing record is now in memory, in the same process lifetime as the key.
A durable journal adds no safety to a non-recoverable key and must not add a
mandatory write-failure path. A future key-surviving profile must establish both
persistence and freshness anew. Optional diagnostic exports are not signing state.
Status remains Proposed; #126 merged the proposal, not its activation.
