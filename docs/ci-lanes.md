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
| `lane` | `combined` / `overbound` / `abort` / `t6` / `ureth-targeted` / `all-live` / `build-only` | one kind, or `all-live` = combined + overbound + abort + t6 (each on its own VM), or the builds and their provenance checks only (see Step 2 below) |
| `inject_failure` | `none` / `after-builds` / `in-lane` | a harness failure to test the failure path: fail after the builds are verified (no lane started) / fail the lane deliberately after step `utb_step_u1`. Honoured only by this workflow (`CI_INJECT_FAILURE`, and `CI_INJECT_FAIL_AFTER` which `p85-recovery-steps.sh` honours only when `GITHUB_ACTIONS=true`); it adds a failing step and weakens no check. |

A `workflow_dispatch` workflow has to exist on the default branch to be dispatchable (dispatching a workflow that exists only on a branch answers HTTP 404;
checked 2026-10-20 with `gh workflow run --ref`). Until the file is on `main`, a lane run is started by pushing a branch named `ci-lane-run/<name>`:
the push event reads its inputs from `scripts/ci/run-inputs.json` of that branch. There is no `pull_request` trigger. The nightly `schedule` (below) is in the file but fires only from the default branch's copy of it.

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

## Step 2: T6 on Linux, the focused controls, targeted ureth, nightly

`briefs/ci-lane-migration-plan.md` section 4 item 2. The same workflow, the same pins file and publisher; each kind is its own VM and its own verdict (`fail-fast: false`).

| kind | what it runs | evidence |
|---|---|---|
| `combined` | `scripts/utb-lane.sh` (above) | `lane-evidence-combined` |
| `overbound` | `P85_MODE=overbound scripts/p85-lane.sh`: the election's refusal of an over-bound candidate, from a fresh genesis with the prerequisite steps (`election_refused` is a completion sentinel) | `lane-evidence-overbound` |
| `abort` | `scripts/h6/abort-rehearsal-lane.sh`: an Abort before H committed and one after (`abort.status` files are sentinels) | `lane-evidence-abort` |
| `t6` | `scripts/t6-rehearsal.sh` (`scripts/ci/run-t6.sh`): independent genesis/artifact checks, authority-backed rotation, over-bound control, acknowledgement, paid execution under the new set, offline F7 verification | `t6-evidence` |
| `ureth-targeted` | `scripts/ci/test-ureth.sh`: `cargo test -p` the four Unicity crates of the ureth pin (`components.ureth.targetedPackages`: `reth-unicity-b1`, `-execution`, `-payload`, `-store`), not `--workspace` and no generic Ethereum suites; an empty selection fails | `ureth-targeted` (cargo log, per-binary results, summary) |

`overbound`, `abort` and `combined` share the builds and the run job (`run-lane.sh`, `CI_LANE_KIND`); the non-combined kinds skip Mongo, the aggregator, NBP and the SDK and check ureth, contracts and Foundry (`check-pins.sh env-core`). T6 builds its own helper tools and the four allocation contracts in an isolated checkout, so its job has Go (setup-go) and the ureth artifact, nothing else from the build jobs. `inject_failure` is honoured by every kind (`after-builds`; `in-lane` fails after a named step: `utb_step_u1` / `p85_joiner_nodes` / T6's build step; the Abort lane has no step hook, so there it adds a failing harness step after the lane ran).

**T6 pins.** T6 keeps its own pins (contracts `e7eb3216`, Foundry **1.8.3**; the lane's are contracts `316203f4`, Foundry 1.8.1). They are recorded under `t6` in `lane-pins.json` and `check-pins.sh t6` refuses a `t6-rehearsal.sh` whose defaults differ (negative cases in `check-pins.sh selftest`). The Linux Foundry asset is `foundry_v1.8.3_linux_amd64.tar.gz`, sha256 `7ca48e6c...c228568` (the release API's digest and `sha256sum` of the download agree). The default ureth of T6, H6 Abort and the lane runner is the attested `6e59b68c` (#679).

**Linux portability added for T6.** The offline F7 verification needs a real network denial: `lane_net_deny_run` (`scripts/lib/portable.sh`) uses macOS `sandbox-exec` or, on Linux, a fresh network namespace (`sudo -n unshare -n`, back to the calling user: the runner image restricts unprivileged user namespaces). Where neither exists `h3_verify_mint` refuses instead of claiming an offline verification, and the T6 script keeps its labelled stripped-environment fallback. `m2_advance_authorities` keeps a validator's planned-restart marker until its RPC listener accepts connections (on a fast runner stop, advance and start completed between two samples of the T6 finality monitor, which then read an unmarked refusal as a finality failure; reproduced twice before the change). A failing T6 puts the nodes' logs (flattened, because the publisher leaves whole `evm*/reth*/auth*` directories out by name) into the evidence as `failed-node-logs/`.

### Measured (run 39452732284, ubuntu-24.04 standard runners, 4 CPU / 16 GB, 115 GiB free after `prune-runner.sh`, no swap)

| job | wall time (job) | peak disk growth | lowest free | peak memory |
|---|---|---|---|---|
| `run-lane (combined)` | 15.3 min | 4.21 GiB | 110.0 GiB | 5.48 GiB |
| `run-lane (overbound)` | 6.7 min | 2.75 GiB | 111.5 GiB | 2.92 GiB |
| `run-lane (abort)` | 6.1 min | 2.67 GiB | 111.6 GiB | 3.00 GiB |
| `run-t6` (attested ureth supplied; its own Go build, forge, four contracts) | 9.6 min | 3.38 GiB | 111.3 GiB | 4.28 GiB |
| `ureth-targeted` (304 tests, cold compile) | 11.9 min sampled | 10.75 GiB (11.15 GiB in the first run) | 103.6 GiB | 7.77 GiB (8.21 GiB) |
| `build-ureth` (cold) | 15.7 min | 3.90 GiB | 110.5 GiB | 4.52 GiB |

**Gates from these numbers.** `runner.minFreeDiskGiB` 8 (the P85-family kinds, growth at most 4.21 GiB: 1.9 times the combined lane, 2.9 times over-bound/Abort); `minFreeDiskGiBUrethTargeted` **24** (2.15 times 11.15 GiB, checked by `test-ureth.sh` before it builds); T6's own gate before its clean build is now **7 GiB** (2.07 times its 3.38 GiB growth; it was 5.5 GiB, below twice the measurement). Every gate refuses a runner with less free space; none is a reason to skip a check.

### Nightly

`schedule` (01:17 UTC) runs `nightly` = all-live + `ureth-targeted` at the tip of `integration/enshrined-evm`, and so does a `workflow_dispatch` (the file GitHub runs for both is the default branch's copy, and `main` is not the code under test): `plan` checks the integration branch out once, records the SHA in the job summary (every job checks that SHA out). A push of a `ci-lane-run/**` branch tests that very commit. GitHub fires a schedule only from the **default branch's** copy of the workflow file (this repository's default branch is `main`), exactly as `workflow_dispatch` is only dispatchable from it; until the file is on `main` the schedule is inert, and runs are started by pushing a `ci-lane-run/<name>` branch whose `scripts/ci/run-inputs.json` names the lane. Putting the file on `main` is the owner's decision (nothing is pushed to `main` from here).

### Failures that were not the check

A run once failed only at `actions/upload-artifact` (five `CreateArtifact` request timeouts, after all 304 tests passed): GitHub infrastructure. It is recorded, not hidden, and the kind is rerun on the final head; no result is accepted from a rerun of a failing check.

## Step 3: pull requests, and the stock-reth controls

### Pull requests

`ci-lane` also runs on `pull_request` (opened, synchronize, reopened, ready for review) to `integration/enshrined-evm` and `main`. Nothing here is path-filtered at the workflow level:
a filtered-out workflow leaves its checks absent, and a required check that is absent stays pending forever. Instead `plan` classifies the change itself:

- `scripts/ci/classify.py` reads the changed paths (`git diff BASE HEAD`) against `scripts/ci/pr-paths.json` and selects lane jobs. Docs, briefs, markdown and the trees the lanes do not exercise select nothing; `go.mod`, `go.sum`, `Makefile`, this workflow, `scripts/ci/**` (the rules and the pins included) and the shared lane libraries select **every** lane; the other paths select the lanes that depend on them (over-bound, Abort, T6, targeted ureth); any other code selects the umbrella `combined` lane. It errs toward running, never toward skipping, and it is read from the PR's own tree, so a PR that edits the rules selects everything and cannot narrow what it is judged by. Its cases are tested (`classify.py selftest`).
- `lane-gate` **always reports** and is the check to require. It passes when everything the plan selected succeeded; a not-selected job is skipped and never blocks, and a selected job that failed, was cancelled or never ran (a build it needs failed) fails it (`gate.sh selftest`). A docs-only PR therefore gets a green gate in about a minute with no lane run; a draft PR is reported with a note and runs no live lane until it is ready for review.
- `selftests` (chain-free, minutes): the classifier, the gate, `check-pins` and the publisher's self-tests, selected when `scripts/ci/**`, a workflow or `scripts/lib/reth-pin.sh` changes.
- A newer push to a PR cancels its older run (one concurrency group per PR); nothing else cancels.
- The token is read-only, no job uses a secret, the Actions are pinned by commit, and every job runs on a standard runner. A pull request from a fork runs the same jobs under the same read-only token (GitHub asks for approval before the first run of a new contributor).

Making `lane-gate` a required check of `integration/enshrined-evm` is a branch-protection setting and is the owner's decision; this change does not touch protection.

### The stock-reth controls

`real-reth-smoke` and `real-reth-fault` ran the Go adapter against the **upstream stock reth** release the scripts pin, and their names read like evidence about our execution client. They are renamed `stock-reth-control` and `stock-reth-fault-control` and are manual-dispatch only (no PR trigger); their job names and the evidence artifact names say STOCK and not the Unicity profile. The useful parts are kept: their refusal and collection paths (`scripts/reth-smoke-selftest.sh`, now the first step of the control; `scripts/lib/reth-pin.sh select-upload`, which the lane publisher uses) and the scripts for local runs. What the Unicity profile needs is tested by `ci-lane`: the attested Linux ureth, the combined, over-bound, Abort and T6 lanes, and the targeted `reth-unicity-*` crate tests.
