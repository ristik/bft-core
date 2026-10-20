# CI lanes: the combined UTB / P85 / any-age lane on GitHub-hosted runners

`ristik/bft-core` is public, so every job runs on a **standard** GitHub-hosted runner (ubuntu-24.04: 4 CPU, 16 GB RAM, a disk of which about 14 GB is
free before pruning). Nothing larger is assumed. This page is the operator's guide to `.github/workflows/ci-lane.yml`; the plan it implements is
`briefs/ci-lane-migration-plan.md` (step 1).

## What it runs

`scripts/utb-lane.sh`, the same script and the same assertions as on the Mac: one fresh genesis, the P85 recovery machinery, the signed trust-base
(UTB) profile from the first voting epoch, the aggregator of its pin, the reference client and the JS SDK client, the any-age L1 token and its one
vault release, and the evidence-pack checker. Nothing is relaxed for CI. The differences are the inputs (pins, below), Linux portability, and where the
evidence goes.

## Dispatching it

Actions -> `ci-lane` -> Run workflow (`workflow_dispatch`), inputs:

| input | values | meaning |
|---|---|---|
| `lane` | `combined` / `build-only` | build everything and run the lane / the builds and their provenance checks only |
| `inject_failure` | `none` / `after-builds` / `in-lane` | a harness failure to test the failure path: fail after the builds are verified (no lane started) / fail the lane deliberately after step `utb_step_u1`. Honoured only by this workflow (`CI_INJECT_FAILURE`, and `CI_INJECT_FAIL_AFTER` which `p85-recovery-steps.sh` honours only when `GITHUB_ACTIONS=true`); it adds a failing step and weakens no check. |

A `workflow_dispatch` workflow has to exist on the default branch to be dispatchable (dispatching a workflow that exists only on a branch answers HTTP 404;
checked 2026-10-20 with `gh workflow run --ref`). Until the file is on `main`, a lane run is started by pushing a branch named `ci-lane-run/<name>`:
the push event reads its inputs from `scripts/ci/run-inputs.json` of that branch. There is no schedule and no `pull_request` trigger.

## Jobs and artifacts

| job | does | publishes |
|---|---|---|
| `plan` | resolves the inputs | - |
| `build-ureth` | clean checkout of the pinned ureth commit, locked release build of `unicity-reth` (`scripts/ci/build-ureth.sh`) | `ureth-linux`: the binary, `commit.txt`, `sha256.txt`, toolchain, flags, `Cargo.lock` hash, workflow run identity |
| `build-tools` | `make build` (ubft), the Go lane tools (`dnb-tool`, `utb-evidence`, `evmtx`, ...), the aggregator from its pin (VCS stamped, provenance directory), the lane's chain-free self-tests | `bft-tools` |
| `build-sources` | pinned contracts (with `forge build` output and solc), NBP driver (`npm ci`), JS SDK (`npm ci`, build, production dependencies only) | `sources` (three `tar.zst` with digests) |
| `run-lane` | downloads **only those artifacts**, verifies each against `scripts/ci/lane-pins.json`, starts Mongo, runs `scripts/utb-lane.sh --prep` and the lane, finalizes | `lane-evidence`, `resources-*` |

The run job has no Rust target, no Go build cache and no Go or Rust toolchain; the Go tools it needs are prebuilt binaries (`LANE_TOOLS_DIR`, and
`lane_go_run` / `lane_buildinfo` in `scripts/lib/portable.sh` replace `go run` and `go version -m`). The lane's self-test compiles Go test binaries, so it runs
in `build-tools`; the run job's preflight checks its recorded result for this very commit (`LANE_SELFTEST_LOG`).

## Pins

`scripts/ci/lane-pins.json` is the reviewed input manifest: full commits of ureth, aggregator-go, contracts, native-bridge-plugins and the JS SDK, the
Rust / Go / Node versions, the Foundry release and its archive digest, the Mongo image digest. It is **not** `deploy/testnet/pins.json`.
`scripts/ci/check-pins.sh` verifies each downloaded or built component against it and refuses a wrong pin (`check-pins.sh selftest` is the negative test);
`LANE_PINNED=1` makes `utb-lane.sh`'s preflight use these checks instead of live `gh pr view` queries and branch-tip ancestry
(`HEAD` is the recorded commit under test; an unpinned checkout is refused). The ureth binary is re-verified on download: its sha256 against
`sha256.txt`, and the commit it reports against the pin.

## Resources and the free-disk gate

Every job samples `df`, `free` and the largest resident process every 5 s (`scripts/ci/sample-resources.sh`) and publishes the series as
`resources-<job>` with a summary. Measured on ubuntu-24.04 standard runners (4 CPU / 16 GB / `/dev/root` 145 GB, 85 GiB free before and 115 GiB after `prune-runner.sh`; image 20261018.339.1):

| job | wall time | peak disk growth | lowest free | peak memory used |
|---|---|---|---|---|
| `build-ureth` (cold, rustc 1.97.1, locked release) | 18 min 38 s (acceptance run: 12 min 38 s) | 3.79 GiB | 110.6 GiB | 4.62 GiB (4.99 GiB), no swap |
| `build-tools` (ubft, Go tools, aggregator, self-tests) | 3 min 32 s | 3.72 GiB | 81.9 GiB | 1.86 GiB |
| `build-sources` (contracts + forge, NBP, JS SDK) | 4 min 27 s | 0.97 GiB | 84.0 GiB | 3.74 GiB |
| `run-lane` (prep + the lane) | 10 min 8 s (acceptance run: 10 min 29 s) | 3.88 GiB (3.90 GiB) | 109.9 GiB (110.4 GiB) | 2.36 GiB (5.31 GiB) |

**The free-disk gate** (`runner.minFreeDiskGiB` in `lane-pins.json`, passed as `UTB_MIN_FREE_GIB`, checked by the lane's preflight after the inputs are unpacked) is
**8 GiB**: 2.06 times the lane's measured peak growth, so a run twice as chatty as the measured one still fits; the Mac default of 25 GiB also covers building ureth
and contracts there and does not apply to a prebuilt run. A runner with less free after unpacking is refused. The runner's disk is far larger than the 14 GB the
plan assumed, and nothing here depends on that margin: the largest single consumer, the cold ureth build, grows the disk by 3.8 GiB.

## Evidence and what a failed run leaves

`scripts/ci/publish-evidence.sh` builds the publishable copy of the run directory (keys, JWTs, credentials, execution-client data and sockets are left out by
name and listed in `removed.txt`), scans it with the repository's existing `reth-pin.sh select-upload` pattern (by name, by `privateKey` field and by value
against every secret under `test-nodes`), recomputes `SHA256SUMS` over the final published directory, and uploads a tar plus its outer digest. A secret
found by value makes the archive unpublishable: it is quarantined and only a `REJECTED.txt` naming the file (never the value) is published.
A run that did not complete (non-zero status, missing completion sentinel, or `utb-lane.sh --check-evidence` refusing the pack) carries `INCOMPLETE.txt` and is
**not** acceptance evidence. A failed run still uploads: `run-lane.log`, the lane's stdout, the evidence directory as far as it got, the Mongo log, the host and
OOM records (`host-before/after.log.gz`, `oom-lines.txt`, cgroup counters), and the resource series. Retention 30 days. If the runner is lost the upload may
not happen; such a run is never evidence-complete.

There is no Mac power log on a runner and none is claimed: `host-*.log.gz` is runner metadata, UTC and monotonic times, and the kernel's OOM lines where readable.

## Local use

All scripts keep working on the Mac: `AGRE_ROOT` (default: the parent of the checkout) names the root of `builds/`, `briefs/devnet-runs` and `.devnet-lock`; the
lock script is `$AGRE_ROOT/briefs/devnet-lock.sh` when present, else the repository copy `scripts/ci/devnet-lock.sh`.
