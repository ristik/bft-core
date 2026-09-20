# F3 (#11): delivering the three `engine_*WithSealV1` methods

Issue: #11, with #10 and #12 consuming it. Base: `integration/enshrined-evm` at `ba590f3e`.
Companion repository: [`ristik/ureth`](https://github.com/ristik/ureth) at `8d53d286` (the #9 merge).

This is a delivery plan, not a design. The design is accepted and is
`d2-reth-system-call-fee-profile.md` §2, which fixes the three method signatures, their payloads and
their capability strings. Nothing here reopens it. What this adds is the split into reviewable units
and the order they land in, in the way `f6d-node-record-wiring.md` split node wiring into W1 to W3b.

## 1. Where the gap actually is

`f2-execution-prerequisites.md` §4 names the remaining execution-side capability. Read against
`ureth` as it stands after #8 and #9, most of the *rules* exist and none of the *reach* does:

| §4 requirement | State in `ureth` |
| --- | --- |
| consume an authenticated canonical input and parent registry snapshot | `BoundExecutionInput` carries `RootInputV2`, the block profile and the parent accounting. Authentication is a documented caller prerequisite |
| execute exactly one privileged `open` and one `finalize`, enforce failure invalidity and `g_sys`, reject every other `a_sys` transaction | implemented in `crates/unicity/execution` (the bounded kernel) |
| require the header commitment and the registry state and body outcomes | implemented: `context_for_block` checks `extra_data` against the derived commitment, and the parent hash, number, timestamp, `mix_hash` and beacon root; `validate_fixed_block` pins the Cancun profile |
| expose none of it until the whole method and capability contract is present | nothing is exposed. No `EngineTypes`, node, RPC module or capability references any of it |

So F3's remaining work is reach and exposure, not new validity logic. The one genuinely new piece is
the import path, because the rules currently run only where a caller already holds a
`UnicityEvmConfig`, and on import the companion has to arrive with the payload.

That also answers the question this plan was expected to have to solve. Historical re-execution does
not need the companion re-derived from the header: D2 §2 routes re-execution through
`engine_newPayloadWithSealV1` with a `sealCompanion` whose `provenance` says where it came from. The
caller supplies it, as it does for a follower.

## 2. The units

Each unit is one `ureth` pull request. None of the first five advertises a capability, so a running
node's Engine API surface is unchanged until U3e. That ordering is the D2 requirement to "expose
none of it as supported until the whole advertised method/capability contract is present", taken
literally: the methods become reachable one at a time, and become *advertised* only once together.

| Unit | Scope |
| --- | --- |
| **U3a** | the wire types: `sealBuildInput = {rootInput, transitions}` as a JSON envelope carrying canonical CBOR, `sealCompanion = {rootInput, witnesses, provenance}` likewise, the canonical `RootInputV2` decoder, and the conversion from a decoded `rootInput` plus a parent header into a `BoundExecutionInput`. No RPC, no node, no capability. Delivered as [`ureth` #12](https://github.com/ristik/ureth/pull/12) |
| **U3b** | the node: a Unicity `NodeTypes`/`EngineTypes` carrying `UnicityPayloadAttributes` end to end and using the existing `UnicityExecutionPayloadBuilder`, plus the bounded job registry the builder resolves against. Advertises nothing and adds no method |
| **U3c** | `engine_forkchoiceUpdatedWithSealV1`: the build path. Runs the system operation as step 0, writes `extraData`, starts payload building, returns `PayloadStatusV1` and a `payloadId`. `INVALID` on a failed `rootInput` or system operation, `SYNCING` on an unknown parent |
| **U3d** | `engine_getPayloadWithSealV1`: returns the payload, the block value and the `sealCompanion` the leader disseminates |
| **U3e** | `engine_newPayloadWithSealV1`: the import path, for followers, devp2p and re-execution. `VALID` only when every D2 predicate passes and reth's own execution reproduces the committed `stateRoot` and `blockHash`; `INVALID` with the rejection code on any predicate failure; `SYNCING` when the parent or a referenced trust-base body is not local. `ACCEPTED` is never returned. **It must also record the parent-accounting token for every block it imports** (§3) |
| **U3f** | capability advertisement of the three strings, the startup compatibility check, and the bft-core adapter change that negotiates and uses them |

**U3b is a correction to the first revision of this plan**, which went straight from the wire types to
the RPC methods. The methods have nowhere to attach without a node: `forkchoiceUpdated` has to start a
build on *this* node's payload builder, and the builder has to resolve the job the method created.
Discovering that during U3c would have meant either a speculative abstraction with no real consumer or
a rewrite, so the node lands first and the methods attach to something real.

Nothing about it requires editing upstream. reth's Engine API is a jsonrpsee trait in
`crates/rpc/rpc-api/src/engine.rs`, and a sibling trait in `crates/unicity` with the same `engine`
namespace is additive. `examples/custom-engine-types`, `examples/custom-payload-builder` and
`examples/node-custom-rpc` are upstream's own templates for exactly this, which is the reason the
divergence stays inside `crates/unicity`.

U3e is the largest and depends on U3a and U3b only. U3c and U3d are the flow the leader uses and are
naturally reviewed together but land separately, because `getPayload` returning a companion is a
distinct contract from `forkchoiceUpdated` accepting one.

## 3. A requirement U3c placed on U3e

`BoundExecutionInput` needs the parent's ordinary and system gas split, which the header does not
carry. U3c mints that as an opaque token from a block the executor actually finished, and refuses to
derive one from a header alone, which is the right safety property: a token that could be
reconstructed from public fields would not be evidence of anything.

The consequence is that the token exists only for blocks the node itself **built**. A validator that
follows round N, importing that block, and then leads round N+1 holds no token for its own parent, so
it cannot build. Leadership rotates in this shard, so that is the ordinary case rather than an edge
one, and as of U3c the build path works only for a node leading consecutively.

U3e closes it. The import path executes the block with the same executor, so it can mint and record
the same token, and a follower becomes able to lead. This is written down because the gap is invisible
from the build path alone: U3c's tests pass, and the limitation only appears under leader rotation,
which is an M1 scenario rather than a unit test.

Minting tokens from headers is not an alternative. `completed_parent_for` refuses it deliberately.

## 4. What each unit must not do

- No unit changes an existing standard Engine API method's signature, semantics or error codes. D2
  §2 is explicit that the siblings are versioned and negotiated, never silent changes to V3.
- No unit advertises a capability before U3e, and U3e advertises all three or none.
- No unit relaxes the fork's divergence constraint. The methods live in the `crates/unicity` tree
  and reach the node through reth's own extension points, as `crates/unicity/payload` already does.
  Any unavoidable edit to an upstream source file is recorded in `UNICITY.md`'s inventory, which is
  checkable and currently accounts for every touched file.
- No unit introduces a second codec. `rootInput` decoding reuses the accepted encoding; a second
  implementation of it would be the defect D2 §4 warns about.

## 5. Evidence each unit carries

Following the classes in `f2-execution-prerequisites.md` §0, each unit states which class it reaches
and does not overclaim. U3a to U3e are **API**: implemented and tested callable code with no
production call site, because nothing advertises them. U3f is the first that can claim **Wired**,
and only for the paths the bft-core adapter actually drives.

Real-client evidence (**Measured**) is not claimed by any unit here. It belongs to the M1 gate and
needs a running paired deployment, which is #41's subject and not this issue's.

## 6. Not in this plan

- Activation, `v0` removal and the switch that makes the seal methods the only accepted path. D2 §7
  and #10 own those.
- The genesis certification bootstrap, which is coordinated but distinct (#12, and
  `f4f-standard-genesis-json-bootstrap.md`).
- Anything in the Go adapter beyond U3f's negotiation. The carrier work is #10's.
