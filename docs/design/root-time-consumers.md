# Root time consumer audit

Audited 2026-10-08 after bft-core #479 (`e261a488`), against the source snapshots below. This is a static consumer audit and documentation change, not a runtime acceptance test or a proof of every external application's clock use. Scope: root consensus/storage/handoff, rootrecords and record delivery, shard input/Engine API, ureth's Unicity execution/bridge paths, PoS contracts, native bridge plug-ins and aggregator-go. Generated historical vectors and vendored dependencies were not exhaustively re-audited; no code was changed.

Categories: **A** = strict-time assumptions or equal-root-time compatibility; **B** = elapsed-time, round/time conversions and deadlines; **C** = authenticated floors across timeout, recovery, restart and epoch boundaries. “Compatible” means no #479 equality regression was found in the cited path, not a claim of stronger wall-time guarantees.

## Source snapshots

- `bft-core`: [ristik/bft-core@7fc088cea656](https://github.com/ristik/bft-core/tree/7fc088cea65615231f20b1e157e3e465f0f7ff77).
- `ureth`: [ristik/ureth@9d61e63762a1](https://github.com/ristik/ureth/tree/9d61e63762a1b0863a3d54519e8de55310748f87).
- `contracts`: [ristik/unicity-pos-contracts@0ff11cda865f](https://github.com/ristik/unicity-pos-contracts/tree/0ff11cda865fb66427a3a00ef21f90f3c545adaf).
- `bridge`: [ristik/native-bridge-plugins@76040989c330](https://github.com/ristik/native-bridge-plugins/tree/76040989c33006fa636404670d4f747fa77e887b).
- `aggregator`: [unicitynetwork/aggregator-go@ae081651ac74](https://github.com/unicitynetwork/aggregator-go/tree/ae081651ac7443496b5397baa8748e0b4280ba72).

## Findings that need dispatch

- Correct the stale strict-increase source comment and make synthetic aggregator clocks exercise equality (A2, A8).
- Keep the EVM timestamp rule separate; resolve the Go/Rust overflow boundary mismatch (A5). This is pre-existing, not a new root-time regression.
- #85 UC-time holds do not establish a minimum real-time hold without an anchor-freshness bound. Do not promote them into the D6 enforced floor without that proof (B3, B6).
- Recalibrate the D6 advisory two-second estimate/wording; it is not a physical or protocol minimum (B6).
- Confirm whether T2 and client expiry requirements are intended as protocol-clock requirements or actual wall-time guarantees before dispatching any semantic change (B9–B12).

No inspected production consumer requires consecutive UC/root seconds to be distinct. EVM header time is deliberately distinct from UC time. The stale root/governance spec claims are corrected in the docs PR; code comments, stubs, boundary hardening and any stronger timing mechanism are left for separate work.

## Consumer inventory

### A1. Root-time documentation

[bft-core/docs/pos/specification/bft.tex:1748](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/docs/pos/specification/bft.tex#L1748); [bft-core/docs/design/h3-evm-assignment.md:305](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/docs/design/h3-evm-assignment.md#L305).

**Bug now?** Stale specification: bft.tex still required strict increase after #479; the design note was partly corrected.

**Minimal fix / action:** Fixed in this docs PR: non-decreasing time, conditional guarantees, deadline limits and coordinated activation. Links here identify the audited base.

### A2. Rootrecords source and log checks

[bft-core/rootrecords/state.go:184](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/state.go#L184); [bft-core/rootrecords/records.go:143](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/records.go#L143); [bft-core/rootrecords/records.go:175](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/records.go#L175).

**Bug now?** No equality bug: all checks reject only decreases. The state.go comment incorrectly says committed timestamps are strictly increasing.

**Minimal fix / action:** Dispatch a comment correction to non-decreasing and add consecutive equal-time source/log cases; preserve record-index and predecessor checks.

### A3. Root clock import

[bft-core/rootrecords/clock.go:32](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/clock.go#L32).

**Bug now?** Compatible: equal time at a later position is allowed; a repeated position with a different time and backward lineage/time are refused.

**Minimal fix / action:** No code fix. Preserve separate lineage and time checks; include equal-time epoch transitions in coverage.

### A4. Records feed, import model and execution hook

[bft-core/recordsfeed/feed.go:84](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/recordsfeed/feed.go#L84); [bft-core/rootrecords/importbuild.go:64](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/importbuild.go#L64); [bft-core/rootrecords/importbuild.go:82](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/importbuild.go#L82); [bft-core/rootinput/b1.go:179](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootinput/b1.go#L179); [ureth/crates/unicity/execution/src/records.rs:368](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/unicity/execution/src/records.rs#L368); [contracts/src/SealRegistry.sol:372](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/SealRegistry.sol#L372); [contracts/src/SealRegistry.sol:399](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/SealRegistry.sol#L399).

**Bug now?** Compatible: feed/model/registry accept non-decreasing UC time; the hook carries it as a separate value from EVM time.

**Minimal fix / action:** No code fix. Add a joined import/maturity test with advancing record indices and unchanged UC seconds.

### A5. EVM timestamp derivation and validation

[bft-core/evmroot/derive.go:41](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/derive.go#L41); [bft-core/engineapi/params.go:46](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/engineapi/params.go#L46); [ureth/crates/unicity/execution/src/lib.rs:935](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/unicity/execution/src/lib.rs#L935); [ureth/crates/unicity/execution/src/block_executor.rs:864](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/unicity/execution/src/block_executor.rs#L864); [ureth/crates/unicity/execution/src/block_executor.rs:917](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/unicity/execution/src/block_executor.rs#L917); [ureth/crates/unicity/payload/src/consensus.rs:54](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/unicity/payload/src/consensus.rs#L54); [ureth/crates/consensus/common/src/validation.rs:352](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/consensus/common/src/validation.rs#L352).

**Bug now?** Compatible with equal ROOT timestamps: max(root reference time, parent EVM timestamp + 1) supplies strict EVM time. This derived clock can still run ahead at subsecond EVM cadence; the root future bound does not bound it. Separate pre-existing boundary mismatch: Go adds unchecked at MaxUint64, Rust returns overflow.

**Minimal fix / action:** Keep the EVM rule for this repair; never use its value as bounded UC wall time. Dispatch checked-add/fail-closed parity at the Go adapter boundary and an equal-root-time cross-language case. A true wall-time EVM clock needs a separately reviewed protocol change.

### A6. Shard input records and root origin transport

[bft-core/shardnode/inputrecord.go:84](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/shardnode/inputrecord.go#L84); [bft-core/rootchain/consensus/storage/sharding.go:752](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/storage/sharding.go#L752); [bft-core/rootinput/v2.go:258](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootinput/v2.go#L258); [aggregator/internal/bft/client.go:940](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/bft/client.go#L940).

**Bug now?** Compatible: exact equality to the authorizing seal is required, not strict increase over the previous input record; root origin carries the authenticated seal timestamp.

**Minimal fix / action:** No code fix. Retain exact binding; test successive different rounds with identical seal seconds.

### A7. Aggregator reference-time caches

[aggregator/internal/round/round_manager.go:1394](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/round/round_manager.go#L1394); [aggregator/internal/round/parent_round_manager.go:80](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/round/parent_round_manager.go#L80).

**Bug now?** Compatible: <= returns from the scalar-clock update, leaving the same value; this is not rejection of the new round. Round identity remains separate.

**Minimal fix / action:** No code fix. Exercise advancing rounds at equal reference time in parent and child modes.

### A8. Synthetic aggregator certificates

[aggregator/internal/bft/client_stub.go:112](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/bft/client_stub.go#L112); [aggregator/internal/bft/client_stub.go:138](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/bft/client_stub.go#L138); [aggregator/internal/sharding/root_aggregator_client_stub.go:56](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/sharding/root_aggregator_client_stub.go#L56); [aggregator/internal/sharding/root_aggregator_client_stub.go:118](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/sharding/root_aggregator_client_stub.go#L118).

**Bug now?** Test/development fidelity gap: both increment their synthetic reference clock and manufacture referenceTime + 1 seals, so their normal paths hide equal-second operation. They do not impose this rule on live certificates.

**Minimal fix / action:** Dispatch an injectable clock or explicit next-seal time using max(now,parent), plus equal-time cases; keep historical fixtures stable unless deliberately regenerated.

### A9. Handoff certificate relations

[bft-core/handoff/old_commit_proof.go:131](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/handoff/old_commit_proof.go#L131); [bft-core/evmroot/d4handoff.go:273](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d4handoff.go#L273).

**Bug now?** Compatible: seal time greater than vote time is rejected where that relation is checked; equality is valid. Distinct rounds still identify the committing relation.

**Minimal fix / action:** No code fix. Preserve signature verification and add equal seal/vote-time handoff coverage.

### B1. Canonical rootrecords progress

[bft-core/rootrecords/progress.go:18](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/progress.go#L18); [bft-core/rootrecords/state.go:117](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/state.go#L117); [bft-core/rootrecords/projector.go:57](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootrecords/projector.go#L57).

**Bug now?** No seconds conversion: progress uses epoch offsets and ordinary round differences, including skipped ordinary rounds, and freezes at H until successor progress. It counts neither seconds nor committed blocks.

**Minimal fix / action:** No code fix. Keep progress and UC-time fields distinct in policies and APIs.

### B2. #85 evidence and round holds

[contracts/src/p85/P85Types.sol:6](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/P85Types.sol#L6); [contracts/src/p85/StakeCustody.sol:785](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/StakeCustody.sol#L785); [contracts/src/p85/StakeCustody.sol:901](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/StakeCustody.sol#L901); [contracts/src/p85/Evidence.sol:223](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/Evidence.sol#L223); [contracts/src/p85/Evidence.sol:335](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/Evidence.sol#L335); [contracts/src/p85/PolicyBounds.sol:35](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/PolicyBounds.sol#L35).

**Bug now?** No equality regression or round-to-seconds conversion: holds/evidence windows use canonical progress, separately from the UC time gate. Their magnitude alone promises no calendar protection window.

**Minimal fix / action:** No code fix for the stated units. If evidence submission needs a real-time window, specify and enforce that additional requirement rather than multiplying these round counts by a nominal period.

### B3. #85 relative withdrawal time floor

[contracts/src/p85/StakeCustody.sol:801](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/StakeCustody.sol#L801); [contracts/src/p85/StakeCustody.sol:905](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/StakeCustody.sol#L905); [contracts/src/p85/Evidence.sol:338](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/Evidence.sol#L338); [contracts/src/p85/PolicyBounds.sol:53](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/PolicyBounds.sol#L53).

**Bug now?** Equality-compatible; a guarantee gap if timeFloor is claimed as an enforced real-time hold after closure/retirement. Code uses T_now >= T_anchor + d. The root rule bounds future time but not anchor staleness, so even adding 30 seconds cannot establish a full relative wall-time hold. This predates #479.

**Minimal fix / action:** Keep the current UC-seconds claim explicit. To promise a real hold, dispatch a separately specified authenticated anchor-freshness mechanism (or independently enforced real-time floor) and budget both anchor staleness sigma and future error Delta+eps; until then do not advertise timeFloor as that floor.

### B4. #85 delegation expiry

[contracts/src/p85/ElectionPolicy.sol:152](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/ElectionPolicy.sol#L152); [contracts/src/p85/P85Types.sol:83](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/p85/P85Types.sol#L83).

**Bug now?** Compatible: expiry is inclusive in UC seconds. It is not a guarantee of rejection by an absolute UTC deadline while UC time is stale.

**Minimal fix / action:** No code fix for UC semantics. Document the clock and boundary; any strict UTC-expiry requirement needs freshness assumptions/admission, not a round conversion.

### B5. Vesting allocation

[contracts/src/ImmutableVestingVault.sol:50](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/ImmutableVestingVault.sol#L50); [contracts/src/ImmutableVestingVault.sol:54](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/ImmutableVestingVault.sol#L54); [bft-core/docs/pos/specification/evm-partition.tex:37](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/docs/pos/specification/evm-partition.tex#L37).

**Bug now?** No #479 regression: the chosen schedule explicitly consumes EVM block.timestamp. It can vest faster than wall time at subsecond EVM cadence; the existing specification already discloses this.

**Minimal fix / action:** No change to the chosen schedule. A calendar-duration requirement would require a new clock/policy and migration decision; substituting root time alone still needs relative-anchor freshness.

### B6. Checkpoint freshness policy and advisory conversion

[bft-core/evmroot/d6checkpoint.go:93](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d6checkpoint.go#L93); [bft-core/evmroot/d6checkpoint.go:119](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d6checkpoint.go#L119); [bft-core/evmroot/d6checkpoint.go:132](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d6checkpoint.go#L132); [bft-core/evmroot/d6checkpoint.go:146](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d6checkpoint.go#L146); [bft-core/evmroot/d6checkpoint.go:168](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d6checkpoint.go#L168); [bft-core/docs/design/d6-historical-trust-proof-custody.md:86](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/docs/design/d6-historical-trust-proof-custody.md#L86).

**Bug now?** RoundBasedAdvisorySeconds really multiplies rounds by seconds, but is explicitly excluded from the safety bound. Safety uses EnforcedRealTimeFloorSeconds. The advisory two-second minimum and physical-minimum wording are stale for the observed subsecond profile. No production binding from #85 timeFloor to the enforced floor was found in these snapshots; vectors supply example values.

**Minimal fix / action:** Dispatch renaming/recalibration of advisory limits and their documentation; do not call two seconds a physical guarantee. Require provenance and a real-time proof for EnforcedRealTimeFloorSeconds; #85 UC-seconds alone do not qualify.

### B7. Governance checkpoint-protection wording

[bft-core/docs/pos/specification/governance.tex:108](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/docs/pos/specification/governance.tex#L108).

**Bug now?** Documentation bug: it inferred minimum real-time protection from configured round pacing and collateral retention.

**Minimal fix / action:** Fixed in this docs PR: require an independently enforced real-time floor, classify round estimates as advisory, and refer to anchor-freshness limits.

### B8. Legacy D5 retirement and inbox model

[bft-core/evmroot/d5retire.go:112](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d5retire.go#L112); [bft-core/evmroot/d5inbox.go:431](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/evmroot/d5inbox.go#L431).

**Bug now?** No seconds conversion: both are explicitly root-round predicates. The forced-inbox track is deferred by ADR 0012, so this model is not evidence of a deployed wall-time hold.

**Minimal fix / action:** No equality fix. Keep model scope/units explicit; do not reuse these predicates as a real-time protection proof.

### B9. Shard T2 timeout conversion

[bft-core/rootchain/consensus/ir_change_req_verifier.go:73](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/ir_change_req_verifier.go#L73); [bft-core/rootchain/consensus/ir_change_req_verifier.go:93](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/ir_change_req_verifier.go#L93); [bft-core/rootchain/consensus/ir_change_req_verifier.go:146](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/ir_change_req_verifier.go#L146); [bft-core/rootchain/consensus/ir_change_req_verifier.go:153](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/ir_change_req_verifier.go#L153); [bft-core/rootchain/consensus/ir_change_req_verifier.go:196](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/ir_change_req_verifier.go#L196).

**Bug now?** Related reverse conversion: a configured duration becomes a round threshold using BlockRate/2, then elapsed root rounds trigger timeout. Equality does not break it, but the result is not proof that T2 wall seconds elapsed.

**Minimal fix / action:** Keep it documented as a protocol round threshold if that is intended. If T2 is required to guarantee elapsed real time, dispatch a separate timing-rule change; changing one constant is not a proof.

### B10. Aggregator admission and leaf deadlines

[aggregator/internal/service/service.go:194](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/service/service.go#L194); [aggregator/internal/round/leaf_add.go:22](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/internal/round/leaf_add.go#L22); [aggregator/pkg/api/types.go:459](https://github.com/unicitynetwork/aggregator-go/blob/ae081651ac7443496b5397baa8748e0b4280ba72/pkg/api/types.go#L459).

**Bug now?** Compatible: explicit and default TTLs are measured against pinned consensus reference time, with strict t < deadline. Equal-time rounds remain admissible until that clock reaches the deadline. Neither prompt real-time expiry nor a wall-clock service TTL follows during a stall.

**Minimal fix / action:** No equality code fix. State consensus-time semantics in client-facing TTL/expiry descriptions; a real-time service timeout must be separately defined without rewriting historical leaf time.

### B11. Native bridge explicit deadlines (Go/Rust/TypeScript)

[bft-core/bridgeprofile/token.go:511](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/bridgeprofile/token.go#L511); [ureth/crates/unicity/b2/src/semantics.rs:315](https://github.com/ristik/ureth/blob/9d61e63762a1b0863a3d54519e8de55310748f87/crates/unicity/b2/src/semantics.rs#L315); [bridge/packages/native-bridge-plugin/src/history.ts:234](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/packages/native-bridge-plugin/src/history.ts#L234); [bridge/crates/native-bridge-sdk-ext/src/history.rs:425](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/crates/native-bridge-sdk-ext/src/history.rs#L425); [bridge/protocol/interop.md:105](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/protocol/interop.md#L105).

**Bug now?** Compatible: t < explicit deadline is a comparison with the original authenticated leaf reference time, not a requirement that successive root times increase. Null deadlines remain null. This does not prove real-time certification before the deadline.

**Minimal fix / action:** No code fix. Preserve historical time and exclusive boundary; document that current wall time, EVM time and current round must not be substituted.

### B12. Bridge leaf-to-anchor time bound

[bft-core/bridgeprofile/compose.go:58](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/bridgeprofile/compose.go#L58); [contracts/src/bridge/TokenVerifier.sol:137](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/bridge/TokenVerifier.sol#L137); [contracts/src/bridge/InputRecord.sol:23](https://github.com/ristik/unicity-pos-contracts/blob/0ff11cda865fb66427a3a00ef21f90f3c545adaf/src/bridge/InputRecord.sol#L23); [bridge/packages/native-bridge-plugin/src/envelope.ts:219](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/packages/native-bridge-plugin/src/envelope.ts#L219); [bridge/packages/native-bridge-plugin/src/verifier.ts:179](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/packages/native-bridge-plugin/src/verifier.ts#L179); [bridge/crates/native-bridge-sdk-ext/src/envelope.rs:337](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/crates/native-bridge-sdk-ext/src/envelope.rs#L337); [bridge/crates/native-bridge-sdk-ext/src/token.rs:246](https://github.com/ristik/native-bridge-plugins/blob/76040989c33006fa636404670d4f747fa77e887b/crates/native-bridge-sdk-ext/src/token.rs#L246).

**Bug now?** Compatible: t <= authenticated anchor InputRecord.timestamp explicitly accepts equality. Authentication and an upper relation to historical anchor time provide no current freshness guarantee.

**Minimal fix / action:** No code fix. Keep B1/IR authentication before interpreting the bound and preserve equal-time proof cases.

### C1. Proposal parent floor, including timeout rounds

[bft-core/rootchain/consensus/safety_module.go:228](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/safety_module.go#L228); [bft-core/rootchain/consensus/safety_module.go:233](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/safety_module.go#L233); [bft-core/rootchain/consensus/consensus_manager.go:1473](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/consensus_manager.go#L1473).

**Bug now?** Correct after #479: max(now,parent); rejects only below-parent or too-future time. TC does not supply a replacement timestamp. No increment remains.

**Minimal fix / action:** No code fix. Preserve authenticated QC-parent lookup, inclusive skew boundary and overflow-safe subtraction; retain the subsecond regression.

### C2. Store replacement, incoming QC and recovery trigger

[bft-core/rootchain/consensus/consensus_manager.go:310](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/consensus_manager.go#L310); [bft-core/rootchain/consensus/consensus_manager.go:1122](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/consensus_manager.go#L1122); [bft-core/rootchain/consensus/consensus_manager.go:1222](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/consensus_manager.go#L1222); [bft-core/rootchain/consensus/consensus_manager.go:1669](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/consensus_manager.go#L1669).

**Bug now?** Compatible: lookup follows the replacement store; QC proof authenticates executed parent time; the live recovery trigger is checked against the current floor and clock after replay. A live refusal is separated from incomplete persistence.

**Minimal fix / action:** No code fix. Preserve the ordering of proof verification, store installation and live admission; never reset the floor to now.

### C3. Recovered timestamps and historical scheme 2

[bft-core/network/protocol/abdrc/recovery_timestamp.go:15](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/network/protocol/abdrc/recovery_timestamp.go#L15); [bft-core/rootchain/consensus/types/timestamp_proof.go:12](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/types/timestamp_proof.go#L12); [bft-core/rootchain/consensus/types/quorum_certificate.go:59](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/types/quorum_certificate.go#L59).

**Bug now?** Compatible: compares block time with matching authenticated proof, not with a distinct previous timestamp. Old timestamp-less QC history needs the independent commit-seal proof. Signature validity alone does not establish a historical clock-admission bound.

**Minimal fix / action:** No code fix. Keep proof checks before writes and keep current-clock cutoffs out of historical verification.

### C4. Epoch-anchor installation and recovery

[bft-core/rootchain/consensus/storage/bootstrap_anchor.go:62](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/storage/bootstrap_anchor.go#L62); [bft-core/rootchain/consensus/storage/bootstrap_anchor.go:243](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/storage/bootstrap_anchor.go#L243).

**Bug now?** Compatible and necessary: synthetic successor anchor copies the old committed timestamp, and recovery cannot replace the locally installed floor. Equal time at the boundary is expected.

**Minimal fix / action:** No code fix. Preserve the floor even when ahead of local time; test equal-time first successor proposals and clock catch-up.

### C5. Committed UC sealing

[bft-core/rootchain/consensus/storage/block_executor.go:708](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/storage/block_executor.go#L708); [bft-core/rootchain/consensus/safety_module.go:214](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/safety_module.go#L214).

**Bug now?** Compatible: the seal copies the committed block timestamp instead of sampling certification time. A newer seal/round does not imply a larger time.

**Minimal fix / action:** No code fix. Retain exact signed-time propagation; consumers must use position for progress.

### C6. Durable vote retry after restart

[bft-core/rootchain/consensus/safety_module.go:267](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/safety_module.go#L267); [bft-core/rootchain/consensus/timestamp_test.go:139](https://github.com/ristik/bft-core/blob/7fc088cea65615231f20b1e157e3e465f0f7ff77/rootchain/consensus/timestamp_test.go#L139).

**Bug now?** Compatible: live timestamp admission precedes vote issuance, including retry after restart; clock rollback can temporarily prevent a retry. This preserves the live bound rather than manufacturing a new timestamp.

**Minimal fix / action:** No code fix. Retain rollback/retry regression coverage and the recorded vote identity.

## Relative-time proof obligation

For a current certified timestamp `T_B`, the root rule establishes `T_B <= t_B + Delta + eps`, assuming the certificate has an honest signer enforcing the live rule and honest clocks satisfy the upper error bound. A withdrawal gate `T_B >= T_A + d` therefore gives `t_B >= T_A + d - (Delta + eps)`. To turn that into a duration after anchor certification at `t_A`, one also needs `T_A >= t_A - sigma`, giving `t_B - t_A >= d - sigma - (Delta + eps)`.

There is no such finite `sigma` in the current root validity rule: a stale timestamp is allowed. A Byzantine proposal can repeat a stale parent time and later honest proposals can refresh time abruptly. Even perfectly synchronized honest clocks do not supply the missing lower bound on a Byzantine-proposed anchor. Equal seconds are not the cause of this gap. Increasing `d` by 30 seconds alone does not repair it. Separately enforced round/evidence holds still apply, but cannot be translated into calendar seconds without their own timing proof.

For expiration, the converse direction is also unavailable: `T_B < D` does not prove real-time certification before `D`. Historical bridge checks must retain their original reference-time semantics; stricter real-time expiry requires a separately specified freshness mechanism.
