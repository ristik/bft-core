# M2 H2/H3 handoff contract (PR 1)

Status: inert contract. D4 is the accepted model; this document maps its proof
boundary to the current root implementation. Nothing here enables transitions.
`rootinput/v2.go:245` continues to refuse them.

## Root ordering and proof

A candidate inserted through REST or local orchestration is a proposal only.
The existing root BFT path must order each handoff record in a committed root
block. Prepare closes admission of new incumbent governance work. Freeze commits
one `(predecessor, attempt)` slot, after the EVM pipeline is drained or
cancelled. It binds the full body ID, frozen state summary, last certified EVM
parent and candidate to `FrozenID`. Honest old validators endorse only that
root-ordered `FrozenID`, using a domain that excludes the unknown actual
activation round and successor TR. Their durable signing lock survives restart.
A conflicting freeze or competing successor cannot be selected by a local
endpoint or by a second leader.

The actual root proof comes from `rootchain/consensus/safety_module.go:184-194`:
a proposal in the consecutive round makes its certified parent a commit
candidate. `rootchain/consensus/vote_register.go:50-91` collects distinct
signed votes into a QC at the old trust base's quorum threshold.
`rootchain/consensus/types/quorum_certificate.go:83-116` checks the QC's
vote-info hash and old-quorum signatures. `rootchain/consensus/storage/block_store.go:123-149`
processes a commit-capable QC, and `rootchain/consensus/storage/block_tree.go:345-390`
commits its parent block. The handoff adapter must verify that exact block's
content, its committed state root, the old epoch/network, block ancestry, and
the signed QC under the historical old trust base. A D4 `QuorumWeight` field,
a naked 32-byte commit ID, and a local round counter are not proof.

Commit is a separate old-quorum ordered record over the endorsed `FrozenID`,
body, `A*` and successor TR. `A* >= A_min` and `A* >= commitRound + 3`;
the gap protects the pipeline but does not establish finality. The adapter
must show the commit record in the committed block and an authenticated
consecutive descendant commit before activation, matching D4's conservative
2-chain condition. Timeout gaps require another valid chain. No old quorum
before Commit means a safe stall; the new set cannot rescue the attempt.
A root-committed abort may end only an incomplete attempt. A late abort after
Commit has no authority. The next attempt increments the attempt number.

The first new proposal builds on the last finalized old root committed state;
its leader comes from the committed successor TR. Certified root rounds below
`A*` use the old assignment and rounds at or above `A*` use the new one, with
no overlap or gap. A replica missing the finalized commit keeps the old set
and cannot self-activate. The first certified new-set round at or above `A*`
installs the successor; elapsed time and `A_min` do not.

## Durable activation and EVM acknowledgement

The D3 body hashes `earliestActivation = A_min` and remains unchanged after
Freeze. The actual boundary lives in the WP1 `ActivatedTrustBase` value
`{bodyIdentity, epochStart: A*, activationCommitID}`. Persist it through
WP1's `m2contract.TrustInterval` encoding
`["UNICITY_ACTIVATED_TRUST_INTERVAL", 1, bodyIdentity, A*, commitID, end]`,
where `end` is null for the current interval. Its commit ID must resolve to
the verified root commit above. Root-round lookup uses the half-open
`[A*, end)` interval, never `A_min`; the prior interval ends at exactly `A*`.
The separate body identity excludes signatures and activation. Wrong lineage,
missing or reordered bodies, and partial intervals are refused. The M2 PoA
profile admits unit member weights only.

Before Freeze, the old EVM host stops admitting new proposals and cancels or
drains any in-flight block. It persists the last certified parent hash and its
state/input association, plus the successor TR selected at Commit. It must
not advertise a speculative payload as the frozen parent. The successor
imports the root finality evidence, WP1 activated interval, exact frozen
parent and successor TR. Its first block must carry an acknowledgement system
operation binding the commit ID, `FrozenID`, frozen parent, successor TR and
root context. The execution companion verifies that the block header parent
is exactly the frozen certified parent and that its first executable state
extends that parent; a hash supplied by a REST caller does not establish
extension. The acknowledgement is certified and persisted before the
successor admits user transactions. Absent, late, duplicate or wrong-parent
acknowledgement keeps execution unready.

Under D-M2-2, signing keys remain process-only. A lost key is replaced through
this certified rotation while the old quorum survives; it is never restored
from a disk copy. The retired host is fenced at the authenticated `A*` and
must reject signing new-assignment blocks. The new host cannot sign before
finalized activation and acknowledgement readiness. Run old and new hosts
concurrently in the integration test: old authorization ends exactly where
new authorization starts, including across delayed delivery and timeout.
Permanent old-quorum loss before Commit is outside the recovery promise.

## Review slices and evidence

This PR contains message/record codecs, stdlib-only independent vectors, and
an inert state machine conforming to D4 examples. Its verifier interface is a
boundary for a future real root adapter, not an implementation of QC
verification. Evidence class: **Model/API/Inert**. No production admission,
consensus or EVM path calls it.

Child PR 2 owns root ordering, authenticated freeze/endorsement, old-quorum
commit/abort and proof verification. Child PR 3 owns persisted activation and
WP1 interval installation at the actual root boundary. Child PR 4 owns the
EVM cancellation, frozen parent import and acknowledgement. Child PR 4
**requires ureth changes** for the execution admission/parent check. The
current SealRegistry has no handoff acknowledgement or successor-parent
operation; a **contracts change is required** if that registry is retained as
the source of the acknowledgement. That companion schema is to be fixed in
Child PR 4 before runtime activation.

The supported negative matrix covers forged, omitted or reordered bodies;
stale parent; wrong shard; competing successor; abort versus late activation;
unverified root proof; and REST insertion as authority. Each case asserts a
specific `errors.Is` sentinel. `python3 handoff/generate_vectors.py --check`
checks the independent encodings. No runtime gate is claimed by these tests.

| Scenario ID | Class | Command | Expected invariant |
| --- | --- | --- | --- |
| M2-WP3-WIRE | API/Inert | `python3 handoff/generate_vectors.py --check`; `TestVectors` | canonical context, freeze, commit and ack bytes |
| M2-WP3-D4 | Model/Inert | `TestD4ScenarioConformance` | D4 example terminal phases and single assignment per root round |
| M2-WP3-REFUSAL | Inert | `TestRefusals` and one-disabled-guard runs | invalid body, parent, shard, successor, proof, abort and REST proposals fail closed |
