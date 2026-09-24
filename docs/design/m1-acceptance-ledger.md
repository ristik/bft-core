# M1 acceptance ledger — current scope and evidence

This ledger supersedes the current-status conclusions in the historical [F2 execution prerequisites](f2-execution-prerequisites.md), [F3 acceptance ledger](f3-acceptance-ledger.md), and [F6 acceptance ledger](f6-acceptance-ledger.md). Those documents preserve the decisions and evidence available at their pinned revisions; this document records the later M1 implementation and retained run. It does not erase or retroactively revise that history, close an issue, or claim that hosted CI or maintainer approval was verified.

## Accepted M1 profile

M1 is a private, paired PoA execution profile with one fixed root epoch and one configured shard origin. Four independent shard/reth pairs, the root, and signing authorities participate. The paired JWT boundary authenticates the root input and technical record, derives canonical root-input v2, and forwards the checked seal companion to the execution client. The execution client re-executes before accepting/importing the payload.

The accepted operational limits are:

- **Fixed epoch:** no live epoch replacement, multi-epoch trust-base selection, or authority replacement is established.
- **Seal-only execution:** ordinary Engine API payload import and generic EL/P2P synchronization are not claimed. Bounded authenticated shard-journal suffix fetch is the scoped catch-up path.
- **Direct transaction submission:** transaction gossip is not enabled; clients must submit to the participating nodes.
- **Retained state and live authorities:** the experiment uses retained node directories and keeps roots and signing authorities alive. This is not general replacement-host, authority-loss, or power-loss recovery.
- **Proof window:** local archive state and proof retention are assumed. Recovery after the required proof expires is outside scope.
- **Journal capacity:** the execution journal is capped and stops at capacity; it is not an indefinitely running service. Full-journal verification remains linear in retained history.

These boundaries match the accepted M1 gate assessment (2026-09-24, scope section) and the D2 operational limits in `docs/design/d2b-execution-recovery.md`.

## Evidence and verdicts

Repository-relative source references identify code and tests. Retained run artefacts are named by run ID and file name; they are stored outside this repository. A test source establishes that a check exists; it does not by itself establish a process measurement.

| Area | Current evidence | M1 assessment |
|---|---|---|
| Canonical input and paired system-call boundary | M1 gate assessment §1 F2 and §2; `engineapi/adapter_v2_review_test.go`; `rootinput/v2_test.go`; retained D1/D2 reports | Wired and measured for the fixed profile. No general epoch-transition claim. |
| Idle progress and registry projection | M1 gate assessment §1 F4; D1 lane report and per-height transcript; `ureth@39d7e59d:crates/unicity/execution/src/lib.rs` | Measured idle progress for the fixed PoA profile. No live epoch replacement claim. |
| Restart and replay | D2 acceptance run `round5-dac80389`, scenario transcript `20260923T235605Z-all-kill.log`, and per-node logs in the `all-kill` run record | Retained-dir restart/rejoin and nonempty replay measured. The run recovered matching B1–B5 payload hashes/root inputs after all nodes returned to B0, then advanced to B10. |
| Proof acquisition and fault refusals | D2 acceptance run `round5-dac80389`: `proof-outage`, `proof-corrupt`, `missing-body`, and `wrong-genesis` scenario transcripts | Local acquisition and fail-closed cases measured. Peer witness transport and expired-proof realignment are not established. |
| Hostile execution payload | PR #253, head `6c620721`; hostile-builder run `20260924T011805Z` (see pinned bundle below) | PASS — one leader-built payload was mutated. All four validators returned `INVALID` at round 14 with no same-round signature or certificate; finality held at the hostile proposal's parent B10. After rotation, all four admitted and finalized the new B11 certificate within the bounded wait. D1 observed ten consecutive canonical blocks without divergence/equivocation. The leader reth reported `block gas used mismatch: got 110478, expected 110479`. A stateRoot/system-call mutation variant remains future work. |
| Fees and base-fee floor | PR #251 merged as `7f87eebd`; fee-floor run `fee-floor-lane-f1c80655.log` and per-node logs | PASS — all three paid-transaction receipt/balance equations passed. Base fee reached the 1,000,000 wei floor at B1 and held through B10 and a reth restart through B13; all four nodes admitted B11–B13. |
| CI smoke and hosted checks | PR #249 merged as `675d333c`; `item1-smoke-final` transcript and run record | PASS — the supported monitor minimum is used; the full smoke/preflight path, including startup negatives, passed with pinned ureth. D1 observed ten consecutive blocks with a fresh canonical survivor quorum and no divergence/equivocation. |
| Consensus authority and journal | M1 gate assessment §1 F6; `configuredprogress/journal_test.go`; `configuredadmission/journal_test.go`; `configuredadmission/recovery_test.go`; Go suite output artefact `d248-ced55-full-test.log` | Retained-dir M1 admission/replay/fault behavior is covered and measured in the recorded Go suite. Authority death and replacement-host recovery remain out of scope. |

The D2 acceptance run `round5-dac80389` contains ten scenario transcripts and per-node logs. Its pins are BFT `dac80389` and ureth `39d7e59db3054811d0b4020bf182a2e23f8a3b38`; the corresponding BFT integration base assessed was `e4eb999a219769f30ee44a52a2b6e5bb42b9f71d`. The retained run includes later harness hardening relative to that base, so it must not be described as an exact run of the base commit. Full source, binary, artifact, and genesis pins are recorded in the D2 acceptance run summary and scenario transcripts.

The evidence bundles are named `d2-round5-dac80389.tar.gz` (SHA-256 `7e1130fe732b2ffaf9b718cb2b6bab122fc72e68c8bad9ac3999ae61af6844c8`), `item1-smoke-675d333c.tar.gz` (SHA-256 `2d6dc02dbe899653871e1a02b1ed007bdaa9dc94e37f1a579d571be28da85541`), `item2-fee-floor-7f87eebd.tar.gz` (SHA-256 `aa21010a86c53d2f2372b2876291d8e9b6c8a4b9674106a95cdef04f0fc69baf`), and `hostile-builder-20260924T011805Z.tar.gz` (SHA-256 `0ef71b6cb37c5b3e2be724edc489838388a0fbc104df0544fd237bbfd4af44e4`). They will be published and linked in the #41 gate comment.

## Items still needed for a full gate decision

The M1 acceptance recommendation remains **partial**. Remaining gate actions are to publish these evidence bundles and link them in the #41 gate comment, then obtain maintainer sign-off on the gate decision. The M1 scope limits above continue to apply.
