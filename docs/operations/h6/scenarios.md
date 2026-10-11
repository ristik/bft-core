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
  `*_LANE_LOCKED=1` (below). On a shared host run the lane under `scripts/h6/devnet-lock.sh`, which takes `OWNER COMMAND [ARG...]` and needs
  `H6_BASE`, an absolute, writable directory that every operator sharing the fixture ports uses (the lock is `$H6_BASE/.h6-devnet-lock`);
  it does not set any `*_LANE_LOCKED` itself, so pass it in the command:
  `H6_BASE=/abs/shared/dir bash scripts/h6/devnet-lock.sh "$USER" env H3_LANE_LOCKED=1 H3_EVIDENCE_DIR=/abs/fresh/dir bash scripts/h6/run-h3.sh`
  (the same form works with `M2_LANE_LOCKED=1 M2_EVIDENCE_DIR=... bash scripts/m2-lane.sh` and `T6_LOCKED=1 ... bash scripts/t6-rehearsal.sh`).
  Never set a `*_LANE_LOCKED` flag without a lock held or a host of your own.
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

`scripts/t6-rehearsal.sh` builds a clean isolated BFT/contracts toolchain and runs the single B1 layout (Q3 flow, layout-3 slots, operator
endpoint, fresh-B1 genesis). It compiles the fixture allocation, exercises claims, WUCT deposit and withdrawal and treasury withdrawal,
performs configuration-only Q3 handoffs and a cross-epoch restore of a validator, then a coupled key-replacing rotation (evm4 and its root
retire, evm5 and its root join; the joiner, which sits behind the chain's two earlier activations, restores its shard node from a survivor's
archive at its readiness turn) after showing an over-budget candidate (two of four replaced, D = 1 > 1/2) refused with the weight distance
named, and finally compares the deployed registry with an independent regeneration (`b1genesis --verify`). It watches wallet finality
throughout. Run it with `T6_LOCKED=1` and `T6_EVIDENCE_DIR=/abs/fresh/dir` (same lock rule) and the pins its header names. For Ureth,
either the cold source build, or an ATTESTED prebuilt binary (`T6_URETH_ATTESTED`, `T6_URETH_ATTESTED_SHA256`, `T6_URETH_ATTESTED_PROVENANCE`:
the digest, the provenance directory's commit and digest and the binary's reported commit must all agree with the pin); `T6_URETH_BIN` and
`T6_TEST_SKIP_OVER_BOUND` are development overrides and mark the run NOT EVIDENCE. The preflight checks every tool before the devnet lock is
taken. On failure it keeps its checkout and partial evidence; on success it removes the build checkout. Check its final summary and every
evidence row; `run-mode.txt` says which mode ran. Evidence: `briefs/devnet-runs/t6-rehearsal-20261011T044434Z` (attested Ureth 47f5146b, #534).

## 5. Ureth execution-version activation

Stop all shard producers, keep every signing authority alive and the roots on the same BFT commit, stop the four execution clients
with INT and wait for clean exit, start the new binary on the same data directories, and require identical hash, `stateRoot`,
`receiptsRoot` and receipts at every saved certified height before the shard nodes restart. No chain file or database changes. Record the
exact source diff between the two Ureth commits and both execution test logs before authorizing the swap, and do a full swap on
disposable state before treating a pair as approved. After any new client has opened persisted state there is no downgrade: fix
forward or restore from authenticated archive history; never restore an older database to resume signing. There is no lane for this;
it is a manual procedure and counts only with a named independent operator's record.

## 6. Abort before and after H

[root-handoff-abort.md](../root-handoff-abort.md) is the procedure. The rehearsal helper `scripts/h6/prepare-handoff.py` plans the **Q3 handoff**
(a V3 plan with one `q3-readiness` receipt per successor entity; a V2 plan is refused by name, `ErrHandoffNeedsV3Plan`), has one old root
endorse, and leaves the exact target on disk for `root handoff abort`; with `--endorse-all` it lets H commit and expects `too_late`.

Per attempt, on a running Q3 devnet (a lane's functions: `q3_derive_candidate` for the candidate, `q3_receipts` for the receipts):

```sh
python3 scripts/h6/prepare-handoff.py --old-trust-base test-nodes/trust-base-epoch1.json --next-trust-base test-nodes/trust-base-epoch2.json \
  --receipts RECEIPT_1.json,...,RECEIPT_N.json --v3-body-id v3-body-id.txt --root-rpc URL1,...,URLN --out EVIDENCE_DIR [--endorse-all] [--dry-run]
# then, immediately (a Prepare lapses after 24 root rounds): the documented ubft root handoff abort with EVIDENCE_DIR/target.json
```

`--dry-run` checks every input (successor is the next epoch of the old trust base, exactly one receipt per successor entity, loopback URLs, one
RPC per old member, and that one endorsement cannot reach the old quorum) and contacts nothing. Checked in process, with no devnet:
`python3 -m unittest discover -s scripts/h6 -p test_prepare_handoff.py` (fake roots) and `go test ./cli/ubft/cmd -run TestPrepareHandoffHelper`
(the real operator routes). The live rehearsal is one lane, `scripts/h6/abort-rehearsal-lane.sh` (`--selftest` and `--prep-only` need no devnet; the run needs the attested Ureth of the pin): Abort before H (committed Abort record, a paid transaction shows the EVM unfroze, attempt+1 installs), then Abort after H (refused "too late", the handoff still installs). **It is not recorded as rehearsed until a run's `lane.log` and `q3/h6-*` evidence say so;** do not substitute the H3
lane's "late acknowledgement refused", which is a different assertion.
