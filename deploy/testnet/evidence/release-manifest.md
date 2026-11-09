# PoS release manifest: DN-S / TN-S re-run (DRAFT)

**Status: DRAFT. Every `PENDING(...)` marker below must be resolved, or the row explicitly narrowed, before this merges.** `grep -n 'PENDING(' deploy/testnet/evidence/release-manifest.md` must print nothing at freeze. Plan: `briefs/pos-release-rerun-plan.md` (revision 2, arch-approved as preparation plan, §9). Nothing in this file is a run result.

## 1. Identity

| Name | Value |
|---|---|
| manifest revision | the commit of this file (cited from outside: a file cannot contain its own SHA) |
| harness SHA | the bft-core commit this PR lands on (scripts, `rehearse.py`, lane scripts): PENDING(merge commit) |
| host driver | `briefs/host-track-c.sh`, **revision 2, sha256 `b06158ceb0e28499edefc98a047e5f4ea4a23e2050b703db192dfe975994e487`** (outside any repository; any edit changes this hash and is recorded with the run) |
| run SHA | per run: the checked-out commit plus image and binary hashes, recorded in that run's evidence. A `ci-lane-run/*` run may be an **audited inputs-only child** of the manifest commit (diff = `scripts/ci/run-inputs.json` only) |

## 2. Scope

**A-only.** Aggregator A = ristik/aggregator-go `integration/enshrined-evm`. The upstream-facing aggregator B and the UTB feeder (aggregator-go #16/#17, bft-core #967's variant) are **not accepted by this release**; `aggregator-go-upstream` in `deploy/testnet/pins.json` (12ab9074) is the image variant #967 added and is not exercised by any stage listed here. An A pass does not accept B. B needs a merged feeder pin, its own manifest revision and the affected live-source and bridge reruns.

Bridge across a PoS transition (#430 row 2): the §4.1 preflight **passed in CI** (bft-core#979 run 42546603859 at 4baaca59, GitHub-hosted runner, `--pos --utb`, aggregator A, epoch 1→2; dev4's summary `briefs/dev4-bridge-pos-preflight-2026-11-09.md`, with arch's review pending). A second CI run, **42555135158 at 6a88e290** (nbp d352e88a), redeemed a separate epoch-1 token on the per-SID path after activation, with both anchors sealed at root epoch 1 (receipt succeeded, vault credited exactly the lock); run 42546603859 stays separate evidence with its original pins. That is CI evidence only: not a host run, and not the accepted bridge-on-PoS row. arch (dev4's brief): host execution/reservation not yet at the published pins; still to do before it: 2→3, the epoch-3 gap, public SDK clients with controls, restarts, replay negatives, a recorded fresh-process reload. Still PENDING(arch's review of the preflight; owner merge of ristik/native-bridge-plugins#67; #979 re-pinned to #67's merge commit and out of draft). If any of them slips, this release is the PoS-only manifest and #430's bridge row stays open for a later manifest revision.

## 3. Components

| Component | Commit | Source | Why this one |
|---|---|---|---|
| bft-core (product) | `ecb67b1f8542bae014c532d064c205306451b7c2` | `pins.json: bft`; images and host tools are built from it | retained; the `ecb67b1f..` delta has no production Go change (arch), and its script/workflow/helper changes are the harness, recorded above. PENDING(re-read the delta at freeze: `git diff ecb67b1f..<harness SHA> -- ':!*_test.go'` file list) |
| ureth | `10552af21b31b2118c51d6215cd23cfb80faf33c` | `pins.json`, `lane-pins.json` | retained; `unicity/main` 7b2bc1b6 differs by corpus files only |
| unicity-pos-contracts | `7b510f6b5a9cf3987ccc5d7dc77d39f33de12330` | `pins.json`, `bridge/pins.json`, `lane-pins.json` | retained; `main` 4a32df9d adds golden-reference files, `src/` unchanged since be6e86fb |
| aggregator-go A | `009974a72560c1f224fef99ada9fbf475f1488a7` | `pins.json`, `lane-pins.json` | integration head |
| native-bridge-plugins (corpus and joined checks) | `838b08ce4304428c9ebcb9b0fbd4b55b260a99d4` | `bridge/pins.json`, `lane-pins.json` | retained; `main` f1c4a6a8 changes joined-test pins only |
| native-bridge-plugins (**bridge consumer**) | PENDING(merge commit of **nbp#68**, stacked on #67; both rev-approved, merged by the owner; #67 carries the trust-refresh wiring, #68 the accepted-prefix persistence fix. The preflights ran on unmerged heads: 948d429a (#67), d352e88a (#68 on #67 1442ba2e). SDK pin unchanged at 75c5be7) | `bridge/pins.json` | until it merges, 838b08ce is not that consumer's complete source |
| Foundry | 1.8.1, sha256 `37b45855232e57624d90113b049ca54f0c92055bb5c1997fcbdc3076c7b89c10` | `bridge/pins.json` | unchanged |

Reference updates ureth #95, contracts #79, nbp #64: **not taken**. If taken before freeze, their exact revisions replace the rows above and the affected corpus and joined checks are re-run; old evidence is not relabelled.

## 4. The three pin files (they differ on purpose)

| File | Role | Change in this PR |
|---|---|---|
| `deploy/testnet/pins.json` | node images | none (PENDING(confirm at freeze)) |
| `deploy/testnet/bridge/pins.json` | bridge tools (built from their own pins; `dnb-tool` from the package's own bft-core checkout, recorded in `artifacts/bridge-images.json`) | PENDING(nbp bridge-consumer pin once #67 merges) |
| `scripts/ci/lane-pins.json` | CI lanes | none (PENDING(decide whether the lane's nbp row follows the bridge consumer pin)) |

A changed package contract pin does not reach the bridge tools.

## 5. SDKs: two named consumers

| Consumer | Revision |
|---|---|
| public SDK fetch/cache acceptance clients | JS `main` 41cb7ddb; Rust `main` 4be1330d; Java `main` 9fe6bf8 (PENDING(re-read heads at freeze)) |
| the bridge's own SDK | `75c5be7f` via nbp's vendored tarball; PENDING(tarball sha256 and lockfile identity of the bridge-consumer nbp commit) |

The bridge does not use JS `main` and has no `TrustBaseSession` cache here; that is a separate port, not assumed.

## 6. Parameters per generation

| Generation | UTB | Election cadence | Caps |
|---|---|---|---|
| core (G1), crash, owner, resources | off | 400 rounds / 300 s (rehearsal) | 16,1,6 |
| crash e1, crash e2, join | off | as above | as above |
| bridge generation (bft-core#979 recipe) | on (`--pos --utb`, aggregator A integration) | 1500 rounds / 1200 s (declared in its `generation-recipe.json`) | PENDING(read from `generation-recipe.json`) |
| campaign (lane `x4-exit`) | per lane | per lane | per lane |

Test values, recorded, not testnet decisions. Each generation records its own setting in `generation.txt` (driver revision 2). Results from different cadences are not cross-read.

## 7. Builds

Every binary is built from the pinned source at the manifest, on Linux; a binary of an earlier build is **not** reused unless its sha256 is identical and recorded. Commands as the package runs them (`deploy/testnet/build-images.py` checks each source against `pins.json` and refuses a dirty tree):

| Component | Command (cwd = pinned source) | Toolchain |
|---|---|---|
| ubft (node images and host tools) | `make build` (host: in `tn1-builder:bookworm`, host tools `go build ./scripts/b1genesis ./scripts/h4-restore-pin ./cli/ubft` and `./deploy/testnet/keygen`) | Go 1.25.14 (`lane-pins.json` toolchains; the builder image's version is recorded in `build-ubft.log`) |
| ureth | `cargo build --locked --release -p unicity-reth` | Rust 1.97.1 per `lane-pins.json` toolchains (the ureth repo's own nightly pin applies to its fmt gate, not to this build): PENDING(confirm against the build log) |
| aggregator-go A | `CGO_ENABLED=1 go build -trimpath -o build/aggregator ./cmd/aggregator` (no rocksdb tag: memory SMT backend, state in MongoDB) | Go 1.25.14 |
| node image and the faucet/rpc images | `build-images.py --bft-source … --ureth-source … --aggregator-go-source …` (tags `tnops-*:verified`, or `trackc-<bft8>` on the host driver) | Docker; base images by digest in `pins.json` (`runtime`, `python`, `mongo`) |
| bridge tools | `deploy/testnet/bridge/build-bridge-image.py` from `bridge/pins.json` (contracts, nbp, node, go, Foundry 1.8.1) | recorded in `artifacts/bridge-images.json` |

Results recorded **from the run, not from this PR**: PENDING(`artifacts/images.json` and `artifacts/bridge-images.json` of each build: binary sha256 of `ubft`, `unicity-reth`, `aggregator`, and the image ids; copied to the evidence directory as `images.json`).

## 8. Features

Enabled: PoS profile (`--pos`), caps 16,1,6, unit weights. Disabled: `--utb` on every generation except the bridge preflight; B/feeder; unequal genesis weights (the `pos-join-heavy` stage is the refusal control only). `--utb` on the bridge generation. Bridge-client trust refresh (`withTrustRefresh` through the pinned SDK's `fetchTrustBaseEntries`, nbp#67) once #67 is merged. PENDING(final list after arch's review of the preflight).

## 9. Runs this manifest covers (filled as they complete)

| Run | Evidence | Result |
|---|---|---|
| R1 campaign refresh (lane `x4-exit`, run-9 inputs) | PENDING | PENDING |
| host: core, crash e3, owner, resources, e1, e2, join | PENDING | PENDING |
| bridge across a PoS transition | PENDING | PENDING |

4 Nov results stay side by side with these; neither replaces the other, and neither closes #437/#59 alone.

## 10. Residual assumptions

- The independent release review/readiness decision (Q26) is unanswered and is not satisfied by this manifest.
- No whole-host reboot in this refresh; the prior destructive-reset result and its limit (memory-only authority keys, owner Q23) stand as they are.
- `utb-live` (bft-core #978) has run once on a live `--utb` generation: the #979 preflight (run 42546603859, GitHub-hosted runner) verified the served history 1..2, the replay matched, and both controls failed as they should. That is one CI generation at two epochs; the checker does not page histories over 64 entries and does not compare against the roots' own store.
- Not covered by the campaign: a membership change on the accumulated chain, a non-offender exit there, a separate collector-restart fault.

## 11. Acceptance checklist (what each row must show before it is cited as passed)

A row is cited only with its evidence path, the manifest revision, the run SHA and the limits. A missing item is stated as missing, never rounded to pass. PoS host rows (a-f) are dev3's; the bridge row (g) is dev4's stage, listed here so the final summary has one place.

| # | Row | Pass requires | Negative / control |
|---|---|---|---|
| a | core (G1) | every stage of `up … pos-recreate` PASS; `pos-restart-2` shows every root at epoch 3; no `finalized-branch conflict` (if one occurs: logs kept, classified on the evidence, whatever #916's state) | the `pos-abort` / `pos-too-late` stages are part of the list; their expected refusals are asserted, not skipped |
| b | crash at epoch 3 | `pos-crash`, `-ureth`, `-shard`, `-root`, `-ureth-shard` PASS (records in `pos-crash-<tag>.json`, logs of the entity kept) | convergence after the first restart is asserted; a failure keeps the #843 evidence |
| c | owner | `pos-owner` PASS after the crash stages | |
| d | crash at epoch 1, crash at epoch 2 | each on its own fresh generation; `pos-crash-e1` at epoch 1, `pos-crash-e2` at epoch 2 | |
| e | join 4->5 | `pos-joiner … pos-advance`, `pos-restore-repeat`, `pos-join-signs`, `pos-join-heavy`, `pos-restart` PASS (epoch 2) | the low-limit restore run is an **expected negative control** and must reproduce `pthread_create failed` at the lowest limit, or the experiment is reported invalid, not passed; `pos-join-heavy` records the WeightChurn refusal |
| f | resources | >= 1 h on G1 at verified epoch 3, `--no-faucet`, no external load: 0 sampler alerts; peak memory and disk reported against 4 Nov (53 samples, peak <= 34% of limits, disk 4.9%) | the load-free window is stated |
| g | bridge across a PoS transition (#430 row 2) | dev4's list (plan §4.2-4.3): epoch-1 artifacts redeemed after 1->2 and 2->3 on the per-SID path with their actual epoch-1 anchors; the epoch-3 gap repaired on a separate lagging consumer (`maxEntries=1`); public SDK clients cold / warm / restarted; restarts; a recorded fresh-process reload; `custody` L = D = P | fetch disabled fails with the typed error and the vault state is identical before and after; missing middle entry, signatures below `floor(2W/3)+1`, wrong network; duplicate redeem/claim, conflicting burn, tampered proof with whole-state checks |
| h | `utb-live` on each `--utb` generation | served history verifies 1..tip from the pinned genesis, replay idempotent, both controls fail as they should | |
| i | campaign refresh (R1) | `complete=yes`; accounting span >= 14400 s; second handoff K->K', unpublishable result rejected, governance activation, 4 reward intervals, faults executed; pack complete, scans clean; frontier lag reported (not thresholded) | failed attempts kept with run id and attempt number; an injected negative is interpreted only with a passing positive control |

Cross-cutting: for every stop/kill stage the full transition, certification and receipt timestamps are kept; "awaiting round N block from leader" names a shard leader, and the root leader/collector come from the root logs; one measured network on the host; host lock entry `~/host-lock/dev3-<generation>`.

## 12. Evidence layout

Host evidence (driver revision 2): `~/evidence/430-437-pos-host-<DAY>/`

| Path | Content |
|---|---|
| `driver.log` | every driver line with a UTC timestamp, including the running-container count after each teardown |
| `pins.json`, `checkouts.txt`, `images.json`, `host-env.txt`, `build-*.log` | what was built: the pin file copy, `git rev-parse` of every checkout, image ids, tool versions |
| `network/`, `network.sha256`, `manifest.json`, `verify-genesis.log`, `generate*.log` | public generation material only (never `pos-owner-keys/` or `faucet-secrets/`) |
| `core/`, `crash/`, `owner/`, `e12-a/` (epoch 1), `e2/`, `join/` | each: `rehearse.log`, `result.json`, `generation.txt` (name, `utb` on/off, cadence), per-stage JSON and kept logs, `compose-ps.txt`, `docker-stats.txt` |
| `resources/` | `compose-limits.txt`, `sample/samples.jsonl`, `sampler.log` |
| `NOT-RUN.txt` | what did not run (written by `finish`) |

Bridge evidence: `~/evidence/430-bridge-pos-<date>/` (dev4: `result.json`, `generation-recipe.json`, the redeem envelopes and hashes, `utb-history-<label>.cbor`, wallet histories). Campaign evidence: the `ci-lane-run/<name>` run's pack (run id, attempt number, the pack's checker output). The final summary on #437 / #59 / #430 cites: the manifest revision (commit of this file), the harness SHA, the driver sha256, each run SHA and id, the evidence directories above, and the limits of section 10.
