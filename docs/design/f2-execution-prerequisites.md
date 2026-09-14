# F2 (#10): acceptance status, and the execution-side prerequisites it waits on

Base: `integration/enshrined-evm` at `88f59a0e` (the #150 merge). Documentation only. Nothing here
changes runtime behaviour, the Engine API, reth, the contracts repository, or any activation.

The owner's direction after #105 closed was to return to the foundation and enshrined-execution
backlog, starting from the outstanding F2 replay review and the execution-side commitment and
seal-registry prerequisites, while keeping Engine API and execution-client divergence minimal (#1,
"Owner design constraints"). This document does three things:

1. It maps #10's own work breakdown and acceptance lines to the merged and open evidence.
2. It lists every prerequisite that the merged contracts (#138, #139) and the open replay predicate
   (#141) name as gating activation, with what exists for each today.
3. It proposes an order for the next bounded units, with the divergence each one adds, and names the
   decisions that belong to the owner.

It re-derives nothing already accepted. D1 (#3), D2 (#4, ADR 0004) and the F2 child contracts stand
as merged. Where this document states a fact about reth, it refers to the pinned revision
`189c0df32617afc488e0f091dbface1bd72cceb4` (tag `v2.5.0`), which is also the fork point of
`ristik/ureth`.

## 0. Evidence classes

| Class | Meaning |
| --- | --- |
| **API** | a pure-Go fixture over `rootinput` or `evmroot`, with no call site in a running node |
| **Wired** | a test over code that a running shard node executes |
| **Model** | the accepted D1/D2 reference model and its vectors (`evmroot/`) |
| **None** | no evidence exists |

Merged F2 children: #102 and #103 (F2a #93, `a3a5f001` and `0a4b5ec6`), #135 (F2a #134, `92c935a1`),
#138 (F2b #136, `c0a3ef5d`), #139 (F2c contract, `377a0089`). Open: #141 (F2d replay predicate,
head `ec6a8c73`, reconciled against `88f59a0e` on the PR).

## 1. #10 line by line

### 1.1 Work breakdown

| #10 item | Status | Evidence | Class |
| --- | --- | --- | --- |
| Extend `RoundParams`/executor and adapter boundaries with canonical input plus a separate authentication witness | **not done** | `TestWiring_TodaysRoundParamsCannotAuthenticate` establishes why today's parameters cannot carry authentication; the `v1` parameter contract is specified in `f2c-root-input-wiring-contract.md` §4 but not implemented | API (negative only) |
| Validate origin, context, transition chain and header commitment before requesting certification | **API done, not wired** | `rootinput.Derive` (#138): `TestDerive_Refusals`, `TestDerive_OwnsItsInputs`; header binding `rootinput.AcceptBlock` (#141, open) | API |
| Shared builder/follower/replay vectors and rejection diagnostics without trusting ambient state | **API done** | `TestDerive_SameForBuilderFollowerAndReplay`, `TestWiring_RefusalsStayDistinct`, `TestWiring_AsymmetricDeliveryAgreesOnTheBoundCertificate`, `TestWiring_CompanionEvidenceIsReVerifiedNotTrusted` | API |

### 1.2 Acceptance lines

| #10 acceptance line | What is shown | What is not shown | Class |
| --- | --- | --- | --- |
| D1 vectors match an independent implementation | `TestDerive_IndependentCBOROracle` builds the canonical array from the certificate, technical record and context and encodes it with bft-go-base's deterministic encoder; `TestPublishedVectorsUseTheSameCommitmentRule` ties the derivation's commitment rule to the published `evmroot/testdata/vectors.json` | a second client implementation (for example the reth side) producing the same bytes, which cannot exist until F3 | API, Model |
| Different valid signer subsets produce identical input/state | `TestDerive_AlternateQuorumSubsetsAgree`: identical canonical input and commitment | identical **execution state**, which needs a block built from that input | API |
| Omitted, wrong-parent, stale, wrong-epoch, wrong-shard and tampered transition data are rejected before certification | omitted: `TestDerive_Refusals/incomplete context`; stale: `…/stale against the seal-registry cursor`, and on the live path `TestUCDisposition`, `TestStaleDeliveryDuringRoundSequence` (#102/#103); wrong epoch: `…/unknown root epoch`, `…/unsupported: epoch handoff`; wrong shard: `…/wrong configured shard configuration`, `…/wrong configured partition`, and on the live path `TestLiveDeliveryIsBoundToTheConfiguredShardConfiguration`, `TestRestoredCertificateIsBoundToTheConfiguredShardConfiguration` (#135); wrong parent: `TestAcceptBlock_RefusesABlockThatIsNotTheOneAuthorized/a parent that is not the certified one` (#141, open) | **"before certification" in a running node**: no call site derives or checks the canonical input, so nothing is rejected before certification except the live shard-configuration and delay classification. **Wrong parent at derivation**: `TestWiring_ExecutorHeadIsAcceptedAsTheCertifiedParent` shows `Derive` cannot detect a wrong pinned parent; only the sourcing rule (contract §3) and the header check prevent it. **Wrong shard identifier** as distinct from wrong configuration has no dedicated subtest. **Tampered transition data** is refused only because any non-empty `D` is unsupported (`…/unsupported: pending committed bodies`); no authenticated transition path exists to tamper with | API; Wired only for #102/#103/#135 |
| Duplicate/repeat imports are idempotent | `TestAcceptBlock_IsMemoryless` (#141, open): the same genuine block is accepted on every offer; `TestDerive_RoundTypes/a repeat at a higher root round derives, and the older one is refused once applied` | an **import path**: no executor import checks the commitment, so idempotency of a real duplicate import under the canonical input is unshown | API |

Reading of the table: F2's verifier-owned derivation, its contract and its replay predicate exist as
pure APIs with negative fixtures. None of #10's acceptance lines is demonstrated on a running node,
and §2 shows why that cannot change inside F2 alone.

## 2. The prerequisites that gate activation

Each row is a guarantee that a merged contract names as a precondition for activating the canonical
input. "Source" is where the requirement is stated; "D2 row" refers to the deviation inventory in
`d2-reth-system-call-fee-profile.md` §3a.

### G1. Provision of the `extraData` commitment on the build path

- **Required guarantee.** Every successful block's header `extraData` is exactly
  `SHA-256(CBOR(rootInput))` for the round's block-bound authorization. Source: D1 §3, D2 §2,
  contract §5. D2 rows 2 and 6.
- **What exists.** The check exists in Go: `ExecutionPayloadV3.ExtraData` is readable
  (`engineapi/types.go:29`) and `TestWiring_ExtraDataIsCheckableButNotProvisionable` pins that the
  commitment can be compared but not supplied. The adapter requires only
  `engine_forkchoiceUpdatedV3`, `engine_getPayloadV3` and `engine_newPayloadV3`
  (`engineapi/client.go:110`), and `PayloadAttributesV3` has no `extraData` field
  (`engineapi/types.go:67`).
- **What the pinned client does.** The stock Ethereum payload builder copies one process-wide value,
  `EthereumBuilderConfig.extra_data` (`crates/ethereum/payload/src/config.rs:18`), into every block it
  builds (`crates/ethereum/payload/src/lib.rs:204`). That value is set once from the command line and
  capped at 32 bytes (`crates/node/core/src/args/payload_builder.rs:200`). A per-round commitment
  therefore cannot be supplied through stock configuration. On import, reth's header validation
  enforces only the 32-byte maximum (`crates/consensus/common/src/validation.rs:273`), so a block
  carrying the commitment is accepted by stock import without being checked against anything.
- **What is missing.** The whole provision mechanism. `ristik/ureth` `unicity/main` is byte-identical
  to upstream `v2.5.0` (its `UNICITY.md`).
- **Owner.** F3 (#11), in `ristik/ureth`, with the adapter side in bft-core.

### G2. The block-bound authorization reaching followers

- **Required guarantee.** A follower authenticates the certificate and technical record the proposer
  bound to the block, under its own trust base, configuration and committed cursor; it never
  re-selects from its own observed set. Source: D1 §5, contract §3.1 (review of #139).
- **What exists.** `TestWiring_AsymmetricDeliveryAgreesOnTheBoundCertificate` and
  `TestWiring_CompanionEvidenceIsReVerifiedNotTrusted` fix the rule as API fixtures.
- **What is missing.** A transport for the witness. The shard-internal dissemination message
  `disseminatedBlock` (`shardnode/net_dissemination.go:25`, protocol `/unicity/shard-payload/1.0.0`)
  carries round, number, hash, state root, parent hash, raw block and sizes, and no certificate or
  technical record.
- **Divergence.** None in the execution client for the shard-node-to-shard-node leg: the message is
  bft-core's own protocol and would need a new protocol version. Separately, reth's own import paths
  (devp2p synchronization, historical re-execution) need the companion through D2 row 6
  (`engine_newPayloadWithSealV1`) and row 7 (retention), which is F3 and F7 work.
- **Owner.** bft-core for the shard protocol leg; F3 (#11) and F7 (#15) for the client leg.

### G3. The privileged system operation

- **Required guarantee.** An open step first and a finalize step after the forced prefix, from
  `a_sys` to `a_sr`, with no key, nonce or value, and failure invalidating the block. Source: D2 §1.
  D2 rows 1 and 3.
- **What exists.** The accepted model only: `evmroot.ValidateImport` with the `system_*` and
  `seal_finalize_*` rejection codes, and the `a_sr` constant (`evmroot/d2import.go:48`).
- **What is missing.** All execution-side code.
- **Owner.** F3 (#11).

### G4. The SealRegistry contract and the committed cursor

- **Required guarantee.** `lastAppliedRootRound` is committed state, read identically by every node,
  never the node's observed maximum. Source: D1 §5, contract §6, `TestWiring_ObservedMaximumIsNotTheCommittedCursor`,
  `TestWiring_ArbitraryLowCursorRemovesARefusal`.
- **What exists.** `Derive` takes the cursor as a caller-pinned input and names it as such. No
  registry exists: `ristik/unicity-pos-contracts` holds only its README, toolchain pin and empty
  `src/` and `test/` directories.
- **Reading it.** ADR 0004 places registry values in contract storage, authenticated by the block's
  `stateRoot` and provable with `eth_getProof`. That is a standard method. The adapter calls no
  `eth_getProof` today (its `eth_*` calls are `eth_chainId`, `eth_getBlockByNumber`,
  `eth_getBlockByHash` and `eth_config`), so reading the cursor adds a standard call and a proof
  check to the trusted path, not a client deviation.
- **Constraint to carry.** The storage layout is protocol surface (ADR 0004; the contracts
  repository pins solc for that reason). A layout needs its own reviewed statement before a contract
  is written against it.
- **Owner.** F4 (#12), in `ristik/unicity-pos-contracts`, after F3 per the roadmap.

### G5. Committed trust-base bodies and handoff acknowledgements

- **Required guarantee.** A non-empty `D` and the epoch handoff boundary are authenticated against the
  ordered committed-body sequence. Source: D1 §8, F2b mapping §4.
- **What exists.** Named refusals (`ErrUnsupported`) for both.
- **What is missing.** An authenticated feed of committed bodies to a shard node.
- **Owner.** H-series. Not required for the single-configuration, single-epoch private profile, and
  the refusal must survive wiring (contract §8).

### G6. Removing `v0`

- **Required guarantee.** `v0` and `v1` never both govern a block. Source: D1 §4, contract §9,
  `TestWiring_V0AndV1DisagreeForTheSameRound`.
- **Dependency.** Replacing `DeriveAttributes` changes build and verify together, and a `v1` builder
  without G1 produces no valid block. `v0` removal therefore lands with G1, not before it.

## 3. Dependency order, and the decision it forces on #10

The roadmap orders F2 before F3 (F3 depends on F2 and D2) and F3 before F4. The merged contract puts
F2's activation after G1 (F3) and G4 (F4). Both statements are correct, and together they mean that
**#10's remaining acceptance lines cannot be demonstrated inside F2**: rejection before
certification on a running node, and idempotent imports, both need blocks that carry the commitment.

This is a decision for the owner, not something to settle by closing or relabelling the ticket:

- **(a)** Close #10 on the pure API, the contract and the replay predicate, and move the wired
  acceptance lines explicitly into F3's and F4's acceptance.
- **(b)** Keep #10 open as the owner of the wired acceptance lines, delivered by the F3/F4 slices
  below and recorded back on #10.

Recommendation: **(b)**. Closing under (a) would leave "rejected before certification" satisfied by
fixtures with no call site, which is the gap §1.2 records. Under (b) nothing is claimed that has not
run.

## 4. Proposed next bounded units

Each is a proposal for the owner to accept, amend or reorder. None is claimed.

| Unit | Repositories | Adds divergence? | Delivers |
| --- | --- | --- | --- |
| **U1. Canonical input on the shard protocol, inert** | bft-core | none in the execution client; a new version of the shard-internal dissemination protocol | G2's shard leg: the proposer binds its authorization to the disseminated block; followers authenticate it with `Derive` and check the header with `AcceptBlock` against `ExecutionPayloadV3.ExtraData`. The check is exercised with a test executor that writes the commitment (the existing `executortest` fake would need that ability added, which this document has not checked), and stays disabled against `engineapi`, because enabling it there halts the builder (contract §5). The cursor rule stays inactive and is refused by name until G4 exists (contract §6, first option). |
| **U2. Build-path provision (first F3 slice)** | ureth, bft-core | yes: D2 row 6 (`engine_forkchoiceUpdatedWithSealV1` and `engine_getPayloadWithSealV1`, capability-negotiated) | G1 and G6 together: reth writes the commitment it is given; the adapter negotiates the capability at startup, derives through `v1`, and deletes `v0`. A real-reth lane shows builder provision and follower acceptance through the U1 check. It must also state, as a measured gap, that reth-only import paths still accept any 32-byte `extraData` until the import hook exists. |
| **U3. SealRegistry storage layout** | bft-core (design), unicity-pos-contracts | no client change | a reviewed layout statement for G4 before any contract or system call writes to it |
| **U4. System operation and registry (F3 then F4)** | ureth, unicity-pos-contracts, bft-core | yes: D2 rows 1, 3 and the import side of row 6 | G3 and G4: open and finalize steps, the committed cursor read through `eth_getProof`, and the cursor rule activated |

Two observations about minimizing divergence, recorded for the owner rather than acted on:

- **U1 needs no client change.** The shard-node leg of the commitment check runs in Go over a
  standard payload field. Only provision (U2) and reth's own import validation (U4) require the
  client.
- **Provision has a reth-native extension point.** reth's engine payload types choose their
  `PayloadAttributes` type (`crates/payload/primitives/src/lib.rs:49`, trait at
  `crates/payload/primitives/src/traits.rs:71`), so a node can define attributes that carry the
  build input. Exposing those attributes over RPC is still an Engine API change. D2 accepted explicit,
  versioned sibling methods, which matches #1's requirement that any extension be "explicit,
  bounded, versioned and capability-negotiated". This document does not reopen that choice. U2 should
  record which reth mechanism implements the accepted methods and its exact upstream delta, as
  `ureth`'s `UNICITY.md` requires.

## 5. What this document does not do

It does not merge, review or supersede #141. It changes no code, no Engine API, no reth revision and
no contract. It does not close or re-scope #10, #11 or #12. It does not claim any of #10's acceptance
lines on a running node, and it does not authorize activation, deployment or PoS work. Durable
certification storage (#14), signing-authority durability, and the unexplained proposal-timeout
failure from the #148 review remain where #105's closing comment left them.
