# X2 full-stack audit preparation

**Preparation dossier only; no independent security audit has been performed.**
The owner should commission a qualified independent reviewer after T6 fixes the
production manifest and deployment pins. This document is a navigation and
evidence index, not an assurance statement.

## Source pins and comparison baseline

| Component | Review pin |
|---|---|
| BFT Core | ristik/bft-core integration/enshrined-evm d2332e10878aefe1c98fab423024491468de3218 |
| Ureth | ristik/ureth unicity/main 055a314f759f78f045d55ceddfeb7e14b3b6a2f7; T4 lane used 0f0fc02924d98f92c1eee0326c7a39766254315f |
| Genesis contracts | ristik/unicity-pos-contracts e7eb3216549b772a9e1df2b1214976d7dd9e6e62 |
| Aggregator in F8 evidence | rugregator dd5b1406a17fdeb415799045c5e81609619a870a |
| Upstream BFT baseline | unicitynetwork/bft-core main ceceacd11b7a735de74ce17884a3a45e0db1748d |
| Upstream Reth baseline | fork merge base 3a83ccc546bca3a90eb492fc0d115e6065aecb1a; upstream main snapshot 43a93dbcffd5d5cd41664ad6d29fc58291a22c13 |

The upstream refs were fetched on 2026-09-30 for this comparison. The reviewer
should repeat the comparison against the exact release commits selected at T6;
the Reth fork has a large Unicity-specific delta and this table is not a line by
line upstream review.

## Attack surface and review questions

| Surface | Source entry points | Questions for the auditor |
|---|---|---|
| Epoch trust and offline mint reasons | mintproof/verify.go:29-84,87-168; mintproof/bundle.go:35-52,91-181 | Does the proof bind network/partition/shard/configuration, the UC epoch and signatures, canonical header, transaction/receipt trie roots, successful status, log index and expected event? Are byte/node/work limits adequate? |
| Trust distribution boundary | docs/pos/m2-closure-status.md; trustactivation/verify.go:1-89; mintproof/verify.go:29-56 | The verifier accepts an epoch RootTrustBase input. Under the accepted owner premise it does not prove ancestry or a trust-body chain. How is this pin authenticated and distributed to users, and how are wrong-network/epoch pins refused? |
| Root BFT and handoff | rootchain/consensus/handoff_operator.go:40-128,153-210,570-645; rootchain/consensus/storage/control_records.go:96-160; rootchain/consensus/safety_module.go:51-110 | Are prepare/freeze/commit/abort ordering, old-quorum approval, reordering, restart/cache loss, leader change and abort-behind-H behavior safe? Do persisted vote/high-QC locks prevent conflicting commits? |
| Signing authority | signingauthority/authority.go:335-409,411-479,482-520; signingauthority/record.go | Are enrollment, request context, fencing, round high-water, signed-response retention, session replacement, crash persistence and operator socket permissions sound? Can cancellation or a stale session release a second signature? |
| Paired execution | Ureth crates/unicity/execution/src/block_executor.rs:295-318,327-365,640-695; BFT shardnode restore and certification paths | Is the exact parent, authenticated system prefix, replay, receipt/state root and companion data bound on every enabled route? Are generic EL P2P, snap and pipeline sync actually refused? |
| Receipt archive and replicas | archive/store.go:77-103,273-305; archivewiring/receipts.go:14-103; archivewiring/publisher.go; archivewiring/peer_gate.go:16-107 | Are immutable versioned records complete and bounded; are header transaction/receipt roots, counts, bloom and typed receipts checked; can replica loss, restored identities or retries stall pruning or acknowledge incomplete data? |
| Genesis and custody contracts | registrygenesis/manifest.go:352-509,512-568; registrygenesis/export.go:49-220; T5 dossier | Are artifact hashes, constructor immutables, balances/storage, allocations, beneficiary, reserved addresses, chain ID and standard genesis output bound exactly? Are immutable recipient failures and post-deployment recovery understood? |
| System contract and privileged calls | BFT registrygenesis/artifact.go:58-90, registryproof/registryproof.go:61-86; pinned SealRegistry.sol:13-35,96-170; Ureth system executor above | Does the client enforce all rules the contract deliberately does not enforce: system-call order/count, revert handling, gas, authenticated input projection, reserved sender, phase and post-state checks? |
| Supply and accounting | supplyaudit/audit.go:20-31,68-127,501-610; docs/pos/t4-supply-auditor.md; Ureth source pin above | Are full-state and receipt/trace assertions authenticated at the boundary? Are ordinary-receipt base-fee burns separated from system gas, and are blob, withdrawal, CREATE/SELFDESTRUCT, WUCT and collector-liability cases covered? |
| Operator and recovery | docs/operations/m2-runbook.md; docs/operations/root-handoff-abort.md; archivewiring/operator_status.go | Are commands safe to copy, do STOP conditions avoid signing on stale trust or data, can restore avoid generic EL sync, and are remaining read-only parent, replica lifecycle and supported-version gaps explicit? |

### Explicit limits and disabled behavior

- mintproof.Verify is pure with respect to network, filesystem and historical
  databases, but its caller must supply the authentic epoch trust base and expected
  claim. The accepted F7 premise requires no ancestry proof or trust-body chain.
- The T4 auditor is an offline accounting tool. fullState, certification and
  trace-completeness fields are source assertions; it does not authenticate the
  state dump, certificate, or trace provider.
- Forced inbox, PoS and bridge features remain disabled. Review the refusal gates
  and ensure no incomplete path is reachable through startup configuration.
- H6's independent operator rehearsal and X2 itself remain open. Lane evidence and
  implementation tests are not independent assurance.

## Deviations from upstream implementations

| Baseline | Fork-specific behavior to review | Source and evidence |
|---|---|---|
| BFT Core upstream main ceceacd11b7a735de74ce17884a3a45e0db1748d | This integration branch adds ordered profile-2 root handoffs with quorum-authorized operator abort, a separate signing-authority service, certified journal/archive replica wiring, mint proofs, and manifest/genesis/supply tooling. These are not inherited guarantees from upstream BFT Core. | rootchain/consensus/handoff_operator.go:40-128,570-645; signingauthority/authority.go:347-479; archivewiring/receipts.go:14-103; registrygenesis/export.go:49-220; current fork pin above. |
| Reth merge base 3a83ccc546bca3a90eb492fc0d115e6065aecb1a; upstream snapshot 43a93dbcffd5d5cd41664ad6d29fc58291a22c13 | Ureth adds crates/unicity/{execution,payload,store}: certified-parent build/replay, a reserved system-call prefix, companion data, durable recovery and a separate store. It uses a NoopNetworkBuilder to keep generic EL P2P admission off. | Ureth crates/unicity/payload/src/node.rs:219-239; execution block_executor.rs:640-695; lane-pinned route tests crates/unicity/payload/tests/sync_route_refusals.rs:59-91 at Ureth 055a314f759f78f045d55ceddfeb7e14b3b6a2f7. Tests refuse P2P admission/pipeline sync and snap account-range sync. |
| Upstream OpenZeppelin ERC20/ReentrancyGuard primitives | WUCT, FeeCollector and ImmutableVestingVault compose standard libraries with project-specific custody logic, no proxy and no privileged repair method. The exact compiled versions and immutable substitutions are project artifacts, not upstream-library assurances. | Contracts e7eb321..., source line references in t5-immutable-code-dossier.md, and compiler artifact SHA-256 values there. |

The comparison identifies review targets, not a claim that every changed file is
security-sensitive or that upstream code is a drop-in replacement. In particular,
Reth's ordinary sync architecture is intentionally unavailable on this profile;
the supported recovery route is archive/checkpoint plus paired seal replay.

## Evidence index A–G

The run records are under
/Users/risto/uni/agre/briefs/devnet-runs/ and are not committed in this source
tree. The external audit package should include each log, adjacent checksums,
binary/source pins, commands and generated JSON outputs.

- **A — M2a recovery lane:** m2a-final-merged-20260930T071819Z/; lane tree
  6e300cc1, Ureth 055a314f. Handoffs, abort/retry and replacement recovery
  passed. Limits: only one interruption measured; missing final frontier/ack
  snapshot and mutation result; H6 second-operator work remains.
- **B — F8 mixed lane:** f8-mixed-dd5b-20260929/lane.log; BFT #286/#291 and
  rugregator dd5b1406. The acceptance topology/handoff passed; independent
  timeout and invalid RSMT cases are in-process tests.
- **C — F7 proof demo:** f7-20260930T064902Z/; BFT #288/#293/#294 and Ureth
  #41/#42. Typed receipt, archive extraction, inclusion/absence verification,
  handoff and pruning passed. Existing verifier run was network-stripped env,
  not sandboxed; the later runner change is commit 034f2966 and was not
  exercised in a new lane here.
- **D — T1 genesis/claim:** t1-handoff-refresh-20260930T072750Z/; BFT #295/#297.
  Default synthetic manifest genesis, bootstrap transfers and a paid first claim
  passed; independent clean-environment builds are still absent.
- **E — T4 controlled reconciliation:** t4-auditor-fixes-20260930T0857Z/;
  BFT #298/#312 and Ureth 0f0fc029. B20 reconciled exact supply, ordinary paid
  gas and base-fee burn; an injected +1 wei error failed. The run had no
  CREATE/SELFDESTRUCT, WUCT supply or collector liabilities.
- **F — contract tests/artifacts:** unicity-pos-contracts #3/#4 at
  e7eb3216549b772a9e1df2b1214976d7dd9e6e62; reproducible code and stateful
  invariant evidence for WUCT, collector and vault.
- **G — sync/frontier tests and reconciliations:** Ureth #44 and BFT #306/#308/#309;
  m2-ticket-reconcile-261-262.md and backlog-reconcile-older.md. This evidence
  covers named refusal/timing residuals; it does not close all F9/H5/H6/X1 work.

## Finding template

~~~text
Finding ID:
Title:
Severity and confidence:
Affected component, source commit and artifact/runtime hashes:
Threat actor and preconditions:
Security property and impact:
Affected file:line:
Minimal reproduction and expected/actual result:
Evidence (logs, fixture, transaction/block, trust base, checksums):
Root cause:
Recommended fix or feature-disable action:
Owner decision required:
Regression test / independent retest:
Disposition and residual risk:
~~~

## Actions before commissioning / closing

- **Owner:** freeze production S0, allocations, chain ID, treasury, fixed addresses,
  fee profile and trust-pin governance at T6. The owner has accepted M2a with limits
  by the named decision on #43; M3 still requires H6, F9 and H5 policy-only. The
  owner closed #16/#19/#29/#37 and closed #15 with limits; broad F7 public RPC,
  SDK and account/storage proof work moves to bridge-track B5 (#66).
- **Owner:** commission qualified independent X2 scope after T6, including
  remediation retest and explicit treatment of PoA trust-pin assumptions.
- **Independent reviewer:** review T5 exact code/layout/immutables and sign the
  genesis permissions and immutable-defect boundary. No signoff is implied here.
- **Second operator:** complete H6 upgrade, key rotation, abort/attempt+1, restore,
  replica lifecycle and restart evidence with the runbook's parent refresh before
  every proposal. The stable parent-query CLI and replica service procedure remain
  operator-tooling gaps.
- **Release evidence owner:** make the A–G log/checksum pack durable and accessible
  to reviewers before audit work starts.
