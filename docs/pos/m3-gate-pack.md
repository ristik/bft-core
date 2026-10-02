# M3 gate pack (T7, skeleton)

Status: **skeleton, not a decision.** This is the assembly point for [#46 T7](https://github.com/ristik/bft-core/issues/46) and the gate of [#72 M3](https://github.com/ristik/bft-core/issues/72). It links the evidence each M3 criterion needs and says what is missing. Technical readiness is not issuance authorization: launch is a separate, authorized deployment action. Every PR and issue reference was resolved with `gh` at the snapshot below; statuses are the manifest's (`MET`, `MET-WITH-LIMIT`, `MISSING` with a size, `OWNER` = needs owner input) and must be re-checked when the pack is finalized.

**Snapshot:** bft-core `origin/integration/enshrined-evm` `f3f2955b`, 2026-10-02 (refreshed from `626b6ebd`; the T1 export below is still the one made on `626b6ebd`). Scope decisions: M2a accepted with limits (decision on [#43](https://github.com/ristik/bft-core/issues/43), 2026-09-30); M3 requires M2a, H6, F9, H5 policy-only and H3 [#20](https://github.com/ristik/bft-core/issues/20); broad F7 moved to the bridge track [B5 #66](https://github.com/ristik/bft-core/issues/66).

**Marking.** `OWNER DECISION` boxes are for the maintainer or owner and are left empty on purpose. Nothing in this file records a decision.

## 0. Release identity (assembled last)
| Item | Value | Source |
|---|---|---|
| bft-core build | _commit and `ubft` binary SHA-256 of the release_ | OWNER DECISION: pin the release commit |
| ureth build | _commit and `unicity-reth` SHA-256_ | OWNER DECISION |
| Contracts | unicity-pos-contracts `e7eb3216549b772a9e1df2b1214976d7dd9e6e62` (WUCT, FeeCollector, vesting vault); SealRegistry v2 artifact at `ce3e40b479de0a0ef8787d8830ba77189aa11171` (byte-identical to the earlier pin `8b30801a`) (code hash `0x7787f3166565c8e5ebd73801bf71cbacf0cf69f6bcfb8dea8bedbef8198caf38`) | `registrygenesis/artifact.go`; T5 dossier |
| Genesis, full shard configuration, manifest hashes | synthetic v2 export on `626b6ebd`: genesis `3a183dc4…9fd6`, full shard conf `a9902b87…5979`, manifest `29eefe02…bad` (full hashes in `docs/pos/t1-final-export.md`, [#369](https://github.com/ristik/bft-core/pull/369)); production export pending | T1 export record |
| Production chain ID, S0, allocations, addresses, fee parameters | **not selected**: every manifest value is a synthetic example | OWNER DECISION |

## 1. M2 recoverable PoA service ([#43](https://github.com/ristik/bft-core/issues/43))
Evidence: M2a accepted with limits (`docs/pos/m2-closure-status.md`; run `m2a-final-merged-20260930T071819Z`). Children closed: #41 M1, #15 F7 (with limits), #16 F8, #17 F9, #18 H1, #19 H2, #22 H5. Open: #20 H3, #21 H4, #23 H6, #42 X1. Failure matrix: `docs/pos/x1-failure-matrix.md` (#351, independently reviewed). Fault model: `docs/pos/poa-fault-model.md` (#352). Status: MET-WITH-LIMIT for M2a; M2 pending H3, H4, H6, X1.
Known limits to carry: equal-weight PoA; handoff and abort need a live old quorum; lost signing key means rotation, not restore; single archive-plus-replay route with two replicas.
OWNER DECISION: accept M2 evidence (the named readiness decision on #43 covers M2a only).

## 2. H3 EVM assignment change ([#20](https://github.com/ristik/bft-core/issues/20))
Evidence so far: code and design #325, #328 (coupled only), #329, #332, #345, #338, #356, #362, #343, #348, #349, #357, #358, #360, #361, #363; ADR 0012 (#341); runbook `docs/operations/h3-evm-assignment-runbook.md`. Also merged since: #365, #367 (fixes the root-restart stall [#366](https://github.com/ristik/bft-core/issues/366)), #368, #373, #374, #376 (frontier latch and head commit QC). The lane scripts are merged in #375 and the authority-backed H3 acceptance lane passed all steps at `h3-assignment-run9d` (earlier runs `run8a` to `run8g` did not). Open: the confirmation rerun at current integration (with dev), audit finding 2 (#363 refuses a later trust anchor; full-history restore from one is still open), and the audit-2 fixes in review: #377 (round-1 QC pinned to the local genesis QC), #378 (terminal-history repair), #379 (typed restore-replay and refusal errors). Status: **MISSING (S)** until the rerun passes. Closing evidence: the confirmation rerun, independent review, the closing summary on #20.

## 3. H6 upgrade and recovery rehearsal ([#23](https://github.com/ristik/bft-core/issues/23))
Evidence: runbook drafts `docs/operations/m2-runbook.md` (#299), abort `docs/operations/root-handoff-abort.md` (#301), H3 runbook (#325). Natural abort then retry in the M2a run. Status: MET-WITH-LIMIT for procedures.
OWNER DECISION: name the second operator, set the interruption objectives, and accept the rehearsal; the live abort-after-H check is pending.

## 4. F9 resource bounds ([#17](https://github.com/ristik/bft-core/issues/17))
Evidence: collector #316, limits `docs/operations/f9-resource-limits.md` (#322), runs `f9-load-valid-20260930T1258Z`, `f9-malformed-20260930T1315Z`. Status: MET-WITH-LIMIT (one host, four validators).
OWNER DECISION: select the production resource and timeout limits; a sustained-load run at those limits is [X1 row X-39](https://github.com/ristik/bft-core/issues/42).

## 5. H5 checkpoint production and client verification, operator trust-pin policy only ([#22](https://github.com/ristik/bft-core/issues/22))
Evidence: `docs/operations/bootstrap-trust-pin.md` (#315); the F7 verifier takes the epoch trust base explicitly. Status: MET-WITH-LIMIT.
OWNER DECISION: accept the trust-pin policy and the key governance it names (recorded as open in `docs/pos/m2-closure-status.md`).

## 6. T1 genesis manifest and funded first claim ([#28](https://github.com/ristik/bft-core/issues/28))
Evidence: #295, #297, evidence #313; run `t1-handoff-refresh-20260930T072750Z`. Final export on `626b6ebd`: two clean-environment builds byte-identical, record `docs/pos/t1-final-export.md` ([#369](https://github.com/ristik/bft-core/pull/369), merged). Status: MET-WITH-LIMIT (synthetic manifest); the production export repeats once the owner's inputs are selected.
OWNER DECISION: production manifest values (chain ID, supply S0, allocations, addresses, fee parameters, activation profile).

## 7. T2, T3 contracts ([#29](https://github.com/ristik/bft-core/issues/29), [#37](https://github.com/ristik/bft-core/issues/37))
Evidence: unicity-pos-contracts #3 and #4 (merged), pin `e7eb3216`; linear `block.timestamp` vesting; collector is revenue-only, T8 disabled. Status: T2 MET; T3 MET-WITH-LIMIT (T8 off by design).

## 8. T4 supply and custody invariants ([#38](https://github.com/ristik/bft-core/issues/38))
Evidence: #298, #312, #321; run `t4-auditor-fixes-20260930T0857Z`; `docs/pos/t4-supply-auditor.md`. Status: MET-WITH-LIMIT (CREATE and SELFDESTRUCT not exercised; zero WUCT supply in the run). Rerun on the final genesis.

## 9. T5 immutable-code review and signoff ([#39](https://github.com/ristik/bft-core/issues/39))
Evidence: dossier `docs/pos/t5-immutable-code-dossier.md` (#314; pins refreshed in #369). The SealRegistry v2 section is in (#371, read from the contracts at `ce3e40b4` and the export; the artifact was regenerated from source and matches), and #372 replaced its note on root-round ordering. The two remaining reviewer findings are addressed in #382: `ArtifactSourceV2` names the merge `ce3e40b4`, and `inbox.consumed` is kept as a reserved v1 field in the pinned 30-name layout, refused when non-zero by the reader (the code hash does not depend on it). The execution-client rules the contract cannot enforce are for the reviewer to assess in ureth. Status: dossier MET; signoff **OWNER**.
OWNER DECISION: an independent reviewer signs off the genesis manifest and code permissions against the exact hashes in §0 and §6; record name, date and artifact hashes here.

## 10. T6 reproducible public rehearsal ([#44](https://github.com/ristik/bft-core/issues/44))
Evidence: harness #323; placeholder run `t6-rehearsal-20261002T033706Z` PASS. Status: MET-WITH-LIMIT for the harness; real key-replacing rotation in the lane **MISSING (M)** (needs §2).
OWNER DECISION: provide the production inputs and approve the pins for the production rerun.

## 11. X1 failure matrix ([#42](https://github.com/ristik/bft-core/issues/42))
Evidence: `docs/pos/x1-failure-matrix.md` (#351), `docs/pos/poa-fault-model.md` (#352), #353, #356. Status: MET-WITH-LIMIT; open rows X-32 (second operator, = §3) and X-39 (production-limit load, = §4).

## 12. X2 full-stack audit and remediation ([#45](https://github.com/ristik/bft-core/issues/45))
Evidence: scope `docs/pos/x2-audit-prep.md` (#314); internal H3-chain audit (rev, 2026-10-02) findings 1 (resolved, #357), 3 (resolved, #360), 4 (resolved, #365), 5 (resolved, #361); 2 partial (#363). Audit-2 fixes: #376 merged; #377, #378, #379 in review. Status: **OWNER** (external auditor); remediation MISSING (L).
OWNER DECISION: engage the auditor, accept the report, and decide for each finding affecting public funds or finality whether it is closed or the feature disabled with a rechecked gate. A contracts-only audit does not satisfy this scope.

## 13. Disclosures and policies recorded for the release
| Item | Where | Status |
|---|---|---|
| PoA authority disclosure (one validator is one entity; co-hosted trust; coupled set changes; key separation) | ADR 0012 (#341), `docs/pos/poa-fault-model.md` | MET |
| Aggregator shards run centrally with `proof_type` none: the trust assumption | ADR 0012, "Trust-assumption disclosure" | MET; OWNER DECISION: accept for launch |
| Proof-retention policy (receipt-complete archive, two replicas, offline mint-reason bundle; broad F7 on B5 #66) | `docs/pos/m2-closure-status.md`, `docs/operations/f9-resource-limits.md` | MET-WITH-LIMIT |
| Hosted CI and real-reth fault evidence ([#90](https://github.com/ristik/bft-core/issues/90)) | not an M3 requirement; depends on CI capacity | OWNER |

## 14. Feature state of the rehearsed release
PoS, bridge, forced inbox (I-track deferred 2026-10-01), absence proofs and unfinished reward functions (T8) are disabled. Status: MET-WITH-LIMIT (the final list is part of T7). OWNER DECISION: confirm the final enabled and disabled list matches the rehearsed release.

## 15. Operational signoffs and the readiness decision
- Named readiness decision for M3: **OWNER DECISION** (name, date, evidence set).
- Residual assumptions accepted: **OWNER DECISION** (list from §1, §13).
- Separate deployment authorization: **OWNER DECISION**; none is implied by this pack.
- Do not close #72 or #46 automatically when a PR merges.
