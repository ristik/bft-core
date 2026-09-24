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
| Restart and replay | D2 acceptance run `round5-dac80389`, scenario transcript `20260923T235605Z-all-kill.log`, and per-node logs under the `all-kill` run record | Retained-dir restart/rejoin and nonempty replay measured. The run recovered matching B1–B5 payload hashes/root inputs after all nodes returned to B0, then advanced to B10. |
| Proof acquisition and fault refusals | D2 acceptance run `round5-dac80389`: `proof-outage`, `proof-corrupt`, `missing-body`, and `wrong-genesis` scenario transcripts | Local acquisition and fail-closed cases measured. Peer witness transport and expired-proof realignment are not established. |
| Hostile execution payload | Assessment §1 F3 and §5 | API/fixture refusals exist, including wrong-root and malformed-payload tests; no live-process hostile-builder run is retained. |
| Fees and base-fee floor | Assessment §1 F5 and §5 | Positive-fee blocks were measured, but exact receipt/balance assertions and reaching/holding the positive floor through idle blocks and restart remain incomplete. |
| CI smoke and hosted checks | Assessment §1 F1 and §5; `.github/workflows/reth-smoke.yml`; `scripts/reth-smoke.sh` | Smoke caller/monitor threshold mismatch remains a concrete defect. Hosted CI and reviews were not verified in the assessment. |
| Consensus authority and journal | M1 gate assessment §1 F6; `configuredprogress/journal_test.go`; `configuredadmission/journal_test.go`; `configuredadmission/recovery_test.go`; Go suite output artefact `d248-ced55-full-test.log` | Retained-dir M1 admission/replay/fault behavior is covered and measured in the recorded Go suite. Authority death and replacement-host recovery remain out of scope. |

The D2 acceptance run `round5-dac80389` contains ten scenario transcripts and per-node logs. Its pins are BFT `dac80389` and ureth `39d7e59db3054811d0b4020bf182a2e23f8a3b38`; the corresponding BFT integration base assessed was `e4eb999a219769f30ee44a52a2b6e5bb42b9f71d`. The retained run includes later harness hardening relative to that base, so it must not be described as an exact run of the base commit. Full source, binary, artifact, and genesis pins are recorded in the D2 acceptance run summary and scenario transcripts. The bundle `d2-round5-dac80389.tar.gz` has SHA-256 `7e1130fe732b2ffaf9b718cb2b6bab122fc72e68c8bad9ac3999ae61af6844c8`; it will be published and linked in the #41 gate comment.

## Items still needed for a full gate decision

The M1 acceptance recommendation remains **partial**. The remaining evidence work is the smoke/preflight repair and run, process-level fee/balance and floor assertions, and a live hostile-payload process test (or a documented minimal hook if impossible). Before closing the gate, reconcile the current GitHub issue text and obtain CI, independent review, and maintainer sign-off. The assessment could not reach the GitHub API and did not verify those external states. The close-out assessment records the ordered work and proposed gate comment.
