# F2 (#10): acceptance status and remaining execution prerequisites

Base: `integration/enshrined-evm` at `5e74dd9c` (the #162 merge). Documentation only. This
revision reconciles the earlier #151 snapshot with merged #141, #153 through #162,
[`ristik/ureth` #4](https://github.com/ristik/ureth/pull/4) and
[`ristik/unicity-pos-contracts` #1](https://github.com/ristik/unicity-pos-contracts/pull/1).
It changes no runtime behaviour,
wire format, Engine API, contract, deployment or activation.

F2 (#10), F3 (#11) and F4 (#12) remain open. Merged APIs and inactive artifacts establish
reviewed contracts and test evidence; they do not establish that a running node accepts canonical
input, executes the privileged registry operations, or rejects an invalid imported block.

## 0. Evidence classes

| Class | Meaning |
| --- | --- |
| **Model** | Accepted design model or deterministic vectors; no production caller. |
| **API** | Implemented and tested callable code, with no production call site. |
| **Inert** | Implemented artifact whose reachability is deliberately absent or has no effect on canonical-input execution. |
| **Wired** | A running shard-node path calls the code. This says nothing by itself about real execution-client evidence. |
| **Measured** | A named real-client process exercised the stated behaviour at a pinned revision. Scope is limited to the measured path. |

These classes compose. For example, the registry proof reader is an API reached by the opt-in record
path, and the proof-window record is a real-reth measurement; neither makes registry state an execution
prerequisite in a running shard round.

## 1. Revision ledger

| Revision | What it establishes | Boundary that remains |
| --- | --- | --- |
| bft-core #141, merge `59746d3d` | `rootinput.AcceptBlock` re-authenticates the historical authorization, derives canonical input, and checks the header parent and 32-byte `extraData`; repeat acceptance is memoryless | API only; no build, follower, sync or replay caller |
| bft-core #154, merge `693b3f91` | bounded canonical envelope and `/unicity/shard-input-witness/1.0.0` transport; caller-scoped admission; `Verify` reaches `AcceptBlock` | deliberately inert; `/unicity/shard-payload/1.0.0`, `Round`, `engineapi` and certification are unchanged |
| [`ristik/ureth` #4](https://github.com/ristik/ureth/pull/4), merge `7d529dcf` | `reth-unicity-payload` includes the commitment and domain tag in the payload-ID derivation and writes each job's commitment to its block `extraData`; the truncated 8-byte IDs remain build-job handles, not collision-free identifiers | inactive crate; no node registration, `EngineTypes`, RPC method, capability, system operation or import hook |
| bft-core #153/#155, merges `88998989`/`580fcaef`; [`ristik/unicity-pos-contracts` #1](https://github.com/ristik/unicity-pos-contracts/pull/1), merge `7dc63acd` | accepted `sealRegistry/v1` layout and proof contract, compiler amendment, and a tested Solidity implementation with pinned artifact/code hash | the contract cannot enforce call placement, block invalidity, gas rule, header binding, projection, or rejection of other `a_sys` transactions; those are execution-client duties |
| bft-core #156, merge `a92188fb` | `registryproof.Verify` authenticates the exact parent header, registry account and 22 storage values and returns an opaque snapshot | no round or executor consumes the snapshot |
| bft-core #157, merge `1f1e126e` | deterministic registry genesis and context verification; a pinned reth `189c0df3` local run matched genesis hash/state root and served a genesis proof | the existing genesis command is unchanged; generated configuration does not supply a genuine no-block genesis UC |
| bft-core #158, merge `e2730083` | exact-hash acquisition and bounded in-memory witness retention; pinned reth measured proof window `0` and `3`, including expiry while header lookup remains available | no running node acquired it at this revision; measurement did not cover restart, pruning or an Engine-API-driven head |
| bft-core #159/#160, merges `36427257`/`3ad216a3` | certified-record crash contract/model and durable store | store is reached only by the later opt-in CLI path and does not govern execution |
| bft-core #161/#162, merges `30084e5f`/`5e74dd9c` | opt-in deployment checks, reload comparison, exact-block witness capture and atomic publication after certified commit | default path constructs none of it; the round/executor do not consume the record; W3a inactive readiness machinery and W3b wiring are pending |

Historical note: the #151 document correctly described upstream reth `v2.5.0` and the then-current
`ristik/ureth` fork as code-identical. That observation is true only at the old fork point
`189c0df32617afc488e0f091dbface1bd72cceb4`. After
[`ristik/ureth` #4](https://github.com/ristik/ureth/pull/4), `unicity/main` contains the inactive
`reth-unicity-payload` crate and is no longer identical to upstream. The pinned upstream build remains
the client used by the #157 and #158 measurements.

## 2. #10 acceptance mapping at `5e74dd9c`

### 2.1 Work breakdown

| #10 item | Current evidence | Status |
| --- | --- | --- |
| Extend `RoundParams`/executor and adapter boundaries with canonical input plus a separate authentication witness | #154 supplies a separate authenticated-evidence envelope and verifier. ureth #4 supplies an inactive payload attribute and builder. `RoundParams`, the executor interface, `round.go`, `engineapi` and the live dissemination path still carry the v0 inputs and do not consume either artifact. | API/inert; live boundary not done |
| Validate origin, context, transition chain and header commitment before requesting certification | `rootinput.Derive` validates the supported single-configuration/single-root-epoch profile and refuses non-empty transitions; #141 checks the parent and header commitment; #154 composes those checks over a bounded carrier. No running round invokes them before certification. | API; not wired |
| Shared builder/follower/replay vectors and rejection diagnostics without trusting ambient state | `rootinput` and `inputcarrier` cover alternate quorum subsets, asymmetric delivery, historical cursor sourcing, named refusals and replay binding. ureth #4 covers builder job isolation only. There is no common running builder/follower/sync/re-execution lane. | API/model; integrated lane absent |

### 2.2 Acceptance lines

| #10 acceptance line | Established | Still required |
| --- | --- | --- |
| D1 vectors match an independent implementation | Go derives the published D1 vectors and checks an independently assembled deterministic-CBOR oracle. ureth #4 accepts a commitment as input; it does not independently derive canonical input. | An execution-side implementation must derive or validate the same canonical bytes/commitment in the real build/import path. |
| Different valid signer subsets produce identical input/state | `TestDerive_AlternateQuorumSubsetsAgree` establishes identical canonical input and commitment. | Identical execution state from real blocks built/imported from those authorizations. |
| Omitted, wrong-parent, stale, wrong-epoch, wrong-shard and tampered transition data are rejected before certification | The API suites distinguish incomplete context, stale committed cursor, unsupported epoch/handoff and transition bodies, configuration/partition mismatches, wrong header parent and wrong commitment. Existing live shard-configuration and stale-delivery checks remain separate v0 evidence. | The canonical-input checks must run on the live build/follower path before certification. A real transition chain is outside the fixed v1 profile; v1 must continue to refuse it by name. |
| Duplicate/repeat imports are idempotent | #141 establishes memoryless header acceptance for a genuine repeat and historical cursor sourcing. | A real execution import/re-execution path must apply the complete D2 predicate and show repeated import has no second effect. |

No #10 acceptance line is yet established end to end on a running canonical-input node. The merged
work removes missing API, carrier, registry-layout, proof and durability prerequisites; it does not
turn those pieces into execution validity.

### 2.3 D2 integration obligations carried by #10

| Obligation | Current position |
| --- | --- |
| Verifier-owned `VerifiedCert` and `ExpectedTransitions` | `rootinput.Derive` owns verification for the fixed profile; `inputcarrier` transports evidence rather than a peer verdict. Non-empty committed bodies and handoff remain explicitly unsupported. No execution importer constructs the complete D2 companion. |
| Real UC positives/negatives through build, follower import, sync and replay | API and model fixtures exist. ureth #4 tests its builder with reth providers; #157/#158 run a real pinned reth for genesis and proof-window behaviour, not canonical-input block validity. The required integrated paths remain absent. |
| Certified FIFO payload and cursor; verifier-derived gas and receipts | The fixed `sealRegistry/v1` profile pins an empty forced prefix and transition cursor. `evmroot.ValidateImport` remains a model/API. No reth execution hook enforces the privileged calls, `g_sys`, receipt derivation or body predicate. |

## 3. Execution prerequisites: current state

### G1. Per-block header commitment

**Current.** The Go side can derive and verify `SHA-256(CBOR(rootInput))` (#138, #141, #154).
ureth #4 can place a caller-supplied 32-byte commitment into each job's `extraData` without cross-job
reuse. Its crate is not registered with a node or exposed through a method/capability, and bft-core
still uses the stock Engine API types. Provision exists as inactive implementation evidence, not as a
running build path.

**Historical observation at `189c0df3`.** Stock reth copied process-wide
`EthereumBuilderConfig.extra_data` into built blocks, while stock payload attributes had no per-round
field. Import checked the Ethereum 32-byte maximum, not the Unicity commitment. ureth #4 adds an
isolated per-job builder without changing that upstream code or making it reachable.

### G2. Block-bound authorization on followers and replay

**Current.** #154 supplies the bounded envelope, separate protocol, admission rules and verifier. Its
inertness test confirms that no production package imports `inputcarrier`; the live shard payload
protocol is unchanged. #141 supplies the replay header predicate but no caller. The carrier and
predicate must eventually be fed from independently trusted configuration, certified parent and
parent-state registry snapshot; the block, peer, observed maximum and current replay-time cursor are
not substitutes.

**Historical observation at #151.** `disseminatedBlock` carried only round, block identity and raw
block data. That live message still has no certificate or technical record; #154 created a separate
inactive protocol rather than changing it.

### G3. Privileged execution semantics

**Current.** The accepted D2 model (`evmroot.ValidateImport`) and #153 specify the open step,
forced-prefix position, finalize step, failure invalidity, `g_sys`, forbidden `a_sys` transactions,
header binding and calldata projection. The merged Solidity registry enforces its O1–O10 and F1–F3
state transition rules, but no merged ureth code implements the client rules on builder, follower
import, sync and historical re-execution.

**Historical observation at `189c0df3`.** No Unicity privileged system operation existed in upstream
reth. That remains true of the upstream pin. ureth #4 implements only commitment provision.

### G4. Registry state, proof and availability

**Current.** The earlier claim that no registry, reader or proof acquisition existed is obsolete:

- [`ristik/unicity-pos-contracts` #1](https://github.com/ristik/unicity-pos-contracts/pull/1)
  provides the pinned `sealRegistry/v1` runtime artifact;
- #157 produces deterministic genesis state and verified context;
- #156 authenticates a snapshot from exact-parent header/account/storage evidence;
- #158 acquires that evidence by block hash and records real-reth proof-window expiry;
- #160–#162 can durably record and atomically publish a verified witness on the opt-in CLI path.

At `5e74dd9c`, the opt-in record path captures after a certified commit; it does not make a retained
parent snapshot a prerequisite for building or validating the child. W3a inactive readiness machinery
and W3b node wiring are pending, not current evidence. Even after those units, an execution caller must
consume the authenticated snapshot and apply the full D2 rules.

**Historical observation at #151.** The contracts repository then contained no registry and bft-core
called no `eth_getProof`. Those facts are preserved only as the pre-#153 baseline. They were superseded
by contracts #1 and #156–#158. The #158 pinned-reth measurement found exact-hash proofs available only
within the configured proof window; expiry is unavailable evidence, never permission to use the head or
a zero cursor.

### G5. Genesis certification bootstrap

The generated registry genesis and fixture-generated UCs do not supply the first live certification
authority. `rootchain/consensus/storage.NewShardInfo` initializes `IR` as only
`&types.InputRecord{Version: 1}`: its `Hash` and `PreviousHash` are nil. The accepted
`GenesisParentEligible` and certified-record genesis rules require a genuine no-block UC whose two
hashes equal the pinned EVM genesis state. No merged configuration or runtime path constructs or
certifies that record. This is missing bootstrap certification wiring, not evidence that genesis is
ready and not a license to adopt a fixture UC. The source and authorization of the genuine genesis UC
must be settled before activation.

### G6. Unsupported transitions and forced input

The fixed v1 profile deliberately supports one shard configuration, one shard epoch, one root epoch,
empty committed transitions and an empty forced prefix. Named refusals are implemented at the API and
registry boundaries. H-series transition authentication and a non-empty forced inbox remain later
profiles; no current evidence should be described as silently supporting them.

### G7. Activation and v0 removal

`v0` still governs the live executor path. #154, ureth #4 and the registry execution pieces were
explicitly merged inactive, while the #161/#162 record path is opt-in and has no execution effect. A
separately reviewed activation may replace v0 only after the same canonical-input and registry rules
govern build, follower import, sync and replay. This document neither selects that activation mechanism
nor moves it.

## 4. Exact remaining execution-side gap

After the inactive U2 builder and the merged registry artifacts, the next unresolved execution-side
capability is the **complete D2 execution-validity implementation**:

1. consume an independently authenticated canonical input and parent registry snapshot;
2. execute exactly one privileged `open` and one `finalize` in the accepted positions, project their
   calldata from that verified input, enforce failure invalidity and `g_sys`, and reject every other
   `a_sys` transaction;
3. require the header commitment and resulting registry state/body outcomes on builder, follower
   import, sync and historical re-execution; and
4. expose none of it as supported until the whole advertised method/capability contract is present and
   the bft-core caller can exercise it.

This names the missing behaviour, not a new slice, API shape or activation plan. D2 already accepts
versioned, capability-negotiated sibling methods; ureth #4 intentionally advertises none. Choosing the
implementation order and the point at which those accepted methods become reachable remains #11 work.
The Go carrier, record readiness and genesis-certification wiring are coordinated but distinct gaps;
none can substitute for execution-client validation.

## 5. Status conclusion

#141 closes the old missing replay-predicate statement. #154 closes the missing inert carrier statement.
ureth #4 closes the claim that the fork is identical to upstream and supplies inactive per-job provision.
contracts #1 and bft-core #153/#155–#162 close the claims that no registry artifact, proof reader,
genesis constructor, exact-block acquisition or durable capture path exists.

They do not close #10, #11 or #12. There is still no running canonical-input acceptance lane, no complete
execution-side system-operation/import implementation, no live genesis certification bootstrap, no
coordinated activation, and no evidence that builder, follower, sync and replay reach identical real
execution state under the accepted rules.
