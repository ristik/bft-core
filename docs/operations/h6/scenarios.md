# Native lanes for what the container stack cannot do yet

Return to the [entry point](README.md). Everything on the fresh-B1 layout (registry layout 3): one handoff flow, the Q3 flow
(candidate, a readiness receipt from every successor entity, propose, install, authority advance). Each lane is a fresh,
self-contained devnet that prints `PASS:`/`FAIL:` per step and ends with its own pass line; take the evidence from `lane.log`.

## Inputs every lane needs

Build once per checkout (Go and Rust toolchains as in [OPERATOR.md section 2](../testnet/OPERATOR.md#2-prerequisites)):

```sh
make build        # build/ubft; the lanes run their other tools (evmtx, the F7 proof tools, h4-restore-pin) with `go run`/`go build` themselves
```

- **Ureth** carrying the fresh-B1 profile (`--unicity.*` bindings) at the commit your owner approves; the lanes refuse a binary whose
  `--version` does not print `Commit SHA: <commit>`. Do not use stock reth.
- **Rugregator** (the aggregator in the H3/F8 lanes) at the pin in `scripts/f8-rugregator-pin.sh`: `RUGREGATOR_SOURCE` the checkout,
  `RUGREGATOR_BIN` its `aggregator` binary.
- The lanes default their lock lookup to a developer-workspace helper that is not in this repository. On a host you own set the lane's
  `*_LANE_LOCKED=1` (below); on a shared host run it under `scripts/h6/devnet-lock.sh` first. Never set the flag without one of the two.
- Evidence goes where the lane's `*_EVIDENCE_DIR` says; choose a fresh absolute directory outside the checkout (the lane deletes `test-nodes/`).

Record the commit of this checkout (`git rev-parse HEAD`), the Ureth and rugregator commits and the binary SHA-256s next to the
evidence; the lane prints its own in `heads.txt`.

## 1. Coupled key rotation, joiners, stalled successors and supersession (H3)

```sh
H3_URETH_BIN=... H3_URETH_COMMIT=... RUGREGATOR_BIN=... RUGREGATOR_SOURCE=... \
H3_LANE_LOCKED=1 H3_EVIDENCE_DIR=/abs/fresh/dir  bash scripts/h6/run-h3.sh
```

`scripts/h6/run-h3.sh` wraps `scripts/h3-assignment-lane.sh` (it adds a time budget and drains the lane's extra authority and
restore children after the final PASS). Require `H3 acceptance lane: all steps PASSED` and no `FAIL:` line in `lane.log`.

| Step in `lane.log` | What it proves (record the lines) |
|---|---|
| baseline, configuration-only epoch | EVM and the three aggregators progress; root epoch 2, shard epoch 0. |
| joiner evm5 + root 5 start before the Commit | the joiner root is a follower, its shard node staging-only, no authority session yet. |
| bad proof of possession | the tampered candidate is refused (`invalid proof of possession`) before any Prepare; epoch unchanged. |
| coupled rotation s=1 (root 4→5, evm4→evm5) | committed with an old proposal in flight and the acknowledgement held; a transaction already gossiped must have a successful receipt by hash. |
| root quorum restart; retired key | roots and aggregators keep progressing; evm4's requests are rejected. |
| acknowledgement; paid mint; offline F7 proof | authority advance, joiner restore, certified paid transaction at the new epoch; the proof verifies offline against the epoch trust base and PDR. |
| H4 restore at s=1 | a retained validator loses BFT and EL state and restores through its surviving authority, replays across both epochs, resumes signing. |
| coupled s=2 (root 3→6, evm3→evm6) | a joiner that is **behind** restores from a retained validator's archive and gives readiness before the Commit; after the Commit evm5 and evm6 fail, leaving the successor set below quorum. |
| derived recovery K supersedes s=2 | exactly the s=1 set again, without receipts; the folded acknowledgement certifies; s=2's late acknowledgement is refused (root-level where the node reaches one, otherwise at the archive: the log says which). |
| paid mint under s=3; aggregators progressed | certified paid transaction under the final epoch; the aggregators kept progressing throughout. |

The procedure behind these steps, with the exact commands: [H3 runbook](../h3-evm-assignment-runbook.md).

## 2. Same-members handoffs and restore across epochs (M2)

```sh
M2_URETH_BIN=... M2_URETH_COMMIT=... M2_LANE_LOCKED=1 M2_EVIDENCE_DIR=/abs/fresh/dir  bash scripts/m2-lane.sh
```

Four validators, a paid certified block, two root handoffs through the Q3 flow with the same members, then validator 1 is wiped
and restored across both epochs from an archive replica under the D1 monitor. Require the wrapper's final PASS, `D1 PASS`,
`RESTORE PASS` and no `FAIL:`. Procedure: [M2 runbook](../m2-runbook.md) (sections 1 and 3, and "Shard-node restart after handoffs").

## 3. Weighted activation (Q3)

`scripts/q3-weight-activation-lane.sh` moves a unit-weight PoA chain to mirrored weights 6,1,1,1 in one coupled handoff and runs the
heavy-validator crash, the recovery/rebroadcast and the pair-refusal controls. Its pins have no defaults: run `--dry-run` first, then name every
pin it prints. Require `all steps PASSED`. It is the evidence that a weighted epoch certifies; it is not a rehearsal of OPERATOR.md.

## 4. Monetary history and fresh-build cross-check (T6)

`scripts/t6-rehearsal.sh` builds a clean isolated BFT/Ureth/contracts toolchain, compiles the fixture allocation, exercises claims,
WUCT deposit and withdrawal and treasury withdrawal, performs configuration-only handoffs and a cross-epoch restore, and watches wallet
finality. Run it with `T6_LOCKED=1` and `T6_EVIDENCE_DIR=/abs/fresh/dir` (same lock rule) and the pins its header names. On failure
it keeps its checkout and partial evidence; on success it removes the build checkout. Check its final summary and every evidence row.
T6 still uses the older (layout-2 era) handoff helpers and has not been ported to or run on the B1 layout: it is not B1 evidence until it is.

## 5. Ureth execution-version activation

Stop all shard producers, keep every signing authority alive and the roots on the same BFT commit, stop the four execution clients
with INT and wait for clean exit, start the new binary on the same data directories, and require identical hash, `stateRoot`,
`receiptsRoot` and receipts at every saved certified height before the shard nodes restart. No chain file or database changes. Record the
exact source diff between the two Ureth commits and both execution test logs before authorizing the swap, and do a full swap on
disposable state before treating a pair as approved. After any new client has opened persisted state there is no downgrade: fix
forward or restore from authenticated archive history; never restore an older database to resume signing. There is no lane for this;
it is a manual procedure and counts only with a named independent operator's record.

## 6. Abort before and after H

[root-handoff-abort.md](../root-handoff-abort.md) is the procedure. The manual rehearsal helper `scripts/h6/prepare-handoff.py`
plans a V2 handoff, which a fresh-B1 chain refuses by name (`ErrHandoffNeedsV3Plan`), so **the manual Abort rehearsal is not available
on this layout until the helper is ported to the Q3 flow** (tracked separately). Do not use it, and do not substitute the H3 lane's
"late acknowledgement refused", which is a different assertion. Record Abort as not rehearsed.
