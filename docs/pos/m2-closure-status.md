# M2 closure evidence and decision status

**Snapshot:** 2026-09-30. This is a status record, not a gate decision or a production
authorization. The current BFT integration source is
`d2332e10878aefe1c98fab423024491468de3218`. M2a recovery evidence passed, but the
full M2 gate and H6 remain open.

## Recorded decisions

- **Epoch trust:** a verifier is given the authentic trust base for the UC's epoch.
  Under the accepted F7 premise it verifies that UC directly, with no ancestry proof
  and no trust-body chain. Authenticity of that input is an operational trust
  distribution responsibility. An archive is never its own trust anchor.
- **Operator pin:** retain the PoA checkpoint policy from D-M2-1: an independently
  provisioned checkpoint authority or currently trusted pin, monotonic sequence,
  expiry and refresh, and documented key governance. H5 policy/CLI work and owner
  acceptance remain open.
- **T2 vesting:** the immutable vault uses linear EVM `block.timestamp` vesting with
  fixed start, cliff, duration, principal and recipient. This timestamp is a
  deterministic, increasing EVM input and may advance faster than wall time; it is
  not a wall-clock service guarantee.
- **T3 collector:** all unallocated revenue is split at the immutable 100/0 ratio to
  the fixed treasury pull balance; the reward share is zero. The collector is
  revenue-only, has no assignment attribution or settlement loop, and T8 remains
  disabled. The FeeCollector is the configured fee beneficiary.
- **T4 burn:** base-fee burn is `baseFeePerGas × ordinary paid-transaction receipt
  gas`. Reserved system-call gas is excluded. This follows Ureth's ordinary-gas
  accounting at `crates/unicity/execution/src/block_executor.rs:303-318,348-365`
  and `crates/unicity/execution/src/block.rs:138-140,166-175`, at
  `055a314f759f78f045d55ceddfeb7e14b3b6a2f7`. The T4 lane used
  `0f0fc02924d98f92c1eee0326c7a39766254315f`.

## Status

| Scope | Evidence status | Remaining boundary |
|---|---|---|
| F7 receipt-complete archive and mint-reason proof | Demo passed: typed-receipt inclusion and absence bundles were extracted from archive and verified offline after handoff/pruning. | Broad public account/storage export and permanent-storage service remain outside the completed core. The demo's verifier used a network-stripped environment, not a network sandbox. Evidence runner hardening is at `evidence/post-m2a-lanes` commit `034f2966`; no lane was rerun for this docs change. |
| F8 mixed cadence | Lane passed with the EVM plus three aggregator shards, non-default shard ID reconnect, EVM stop/restart, counters and a root handoff; independent timeout and invalid-proof checks are in-process tests. Aggregator pin: `dd5b1406a17fdeb415799045c5e81609619a870a`. | The evidence is the agreed F8 scope; it is not a sustained F9 resource benchmark. |
| M2a recovery core | Final lane passed two handoffs, natural abort/retry, disk replacement across epochs 2/3, authority high-water 9→21, and B768. | First interruption measured 22.830s; second was not measured. Final frontier/ack snapshot and the mutation result are absent. H5, H6 second-operator rehearsal and F9 measurements remain open. |
| T1/T4 supporting evidence | T1 default manifest genesis and funded first paid claim passed. T4 B20 reconciled exact supply and a paid-fee burn; injected +1 wei error was rejected. | T1 has no two independent clean-environment builds in the evidence set. T4 did not exercise CREATE/SELFDESTRUCT and had zero WUCT supply and collector liabilities; certification authentication is an input assertion. |

The F7 verifier consumes its epoch trust base explicitly in
`mintproof/verify.go:29-56`; it verifies the UC signature, network, partition,
shard and configuration context. It does not build trust ancestry. The verifier
has no network, filesystem or historical-database access (`mintproof/verify.go:29-32`).
The operations policy for how an authentic pin reaches the verifier remains H5.

## Evidence index A–G

The run evidence below is retained in the shared rehearsal archive
`/Users/risto/uni/agre/briefs/devnet-runs/`; it is not embedded in this source
repository. Publish or attach the evidence pack to the release record before using
it as an external audit artifact.

- **A — M2a:** `m2a-final-merged-20260930T071819Z/run-summary.md` and adjacent
  `logs.sha256`; lane tree `6e300cc1`, Ureth `055a314f`. Two root handoffs, natural
  abort/retry, disk replacements across epochs 2 and 3, high-water 9→21, B768 PASS.
- **B — F8:** `f8-mixed-dd5b-20260929/lane.log`; BFT #286/#291 and rugregator
  `dd5b1406`. Three shards, stopped EVM, reconnect under a non-default shard ID,
  root handoff and per-shard counters.
- **C — F7:** `f7-20260930T064902Z/lane.log`, `verify-locked.json`,
  `verify-absence.json`, `operator-status.json`; BFT #288/#293/#294 and Ureth
  #41/#42. The bundle/verify demo passed after a typed-receipt transaction,
  handoff and pruning past the subject block with two replica acknowledgements.
- **D — T1:** `t1-handoff-refresh-20260930T072750Z/lane.log` and
  `t1-claim.json`; BFT #295/#297. Manifest-built genesis, bootstrap transfers,
  paid first claim and two handoffs.
- **E — T4:** `t4-auditor-fixes-20260930T0857Z/audit-result.json`, `lane.log` and
  injected-error result; BFT #298/#312. B20, 144,968 paid gas, 110,072,456,998,720
  wei ordinary base-fee burn, and rejection of a +1 wei accounting error.
- **F — contracts:** unicity-pos-contracts #3/#4, source/artifact pin
  `e7eb3216549b772a9e1df2b1214976d7dd9e6e62`; Foundry tests and reproducible
  artifacts for WUCT, FeeCollector and immutable vesting vault.
- **G — sync/frontier:** `m2-ticket-reconcile-261-262.md` and
  `backlog-reconcile-older.md`, with merged Ureth #44, BFT #306/#308/#309.
  These close listed route-refusal and timing residuals, not every parent-ticket
  acceptance.

## Owner and external actions

- The maintainer decides whether M3 accepts M2a plus named service slices; this
  snapshot does not waive H5, H6, F9 or broad F7 requirements.
- A second operator must execute the H6 recovery/upgrade/abort procedures and
  report interruption against owner-set objectives. `docs/operations/m2-runbook.md`
  is still a rehearsal draft; the abort-after-H live check is pending.
- The owner selects production chain ID, S0, allocations, fixed contract addresses,
  fee parameters and authority policy at T6. All current manifest numbers are
  synthetic examples.
- The owner commissions X2 after T6. T5 needs an independent reviewer signoff;
  this document and local tests are not that review.
