# PoS release manifest: DN-S / TN-S re-run (DRAFT)

**Status: DRAFT. Every `PENDING(...)` marker below must be resolved, or the row explicitly narrowed, before this merges.** `grep -n 'PENDING(' deploy/testnet/evidence/release-manifest.md` must print nothing at freeze. Plan: `briefs/pos-release-rerun-plan.md` (revision 2, arch-approved as preparation plan, §9; **§10 (arch, 2026-11-09) supersedes the product-pin direction of §1.3: ONE full rerun on a newer, explicitly frozen product SHA**, no preliminary rerun at `ecb67b1f`). Nothing in this file is a run result.

## 1. Identity

| Name | Value |
|---|---|
| manifest revision | the commit of this file (cited from outside: a file cannot contain its own SHA) |
| **product SHA** | **`3d4fa198639c1a47d12c09171a1d2ea53d660e45`** (`integration/enshrined-evm`, squash of bft-core#979), frozen 2026-11-09 after #979 merged and the pins PR #1002 landed (aggregator-go `009974a7` -> `b3909de4`, `a0193e2a`). It contains §58 step 1 (#1001 `53be38dab`), #984 (`724b93fa3`) and #994 (`91d66c389`), checked with `git merge-base --is-ancestor`. #1003 (SDK acceptance client pins, deploy files only) is not in it and changes no product file. bft-core itself is pinned to this SHA, for the package and for the CI campaign (§4) |
| harness SHA | `983102b73bcb7d3877f99818bf914d68bea9fb39` (integration tip after bft-core#1003; dev4: supersedes `3d4fa198`, the #979 squash recorded at the freeze). It contains #1005 (`5e07f210`) and differs from the product `3d4fa198` by no Go file (`git diff --name-only 3d4fa198 983102b7`: workflows, lane scripts, pins, docs, deploy files). The campaign's harness is the integration commit it is started from: `983102b7` or a later one, recorded with the run; the product stays `3d4fa198` (`product=pinned`). Recorded independently of the product SHA |
| host driver | `briefs/host-track-c.sh`, **revision 2, sha256 `b06158ceb0e28499edefc98a047e5f4ea4a23e2050b703db192dfe975994e487`** (outside any repository; any edit changes this hash and is recorded with the run) |
| run SHA | per run: the checked-out commit plus image and binary hashes, recorded in that run's evidence. A `ci-lane-run/*` run may be an **audited inputs-only child** of the manifest commit (diff = `scripts/ci/run-inputs.json` only); **it must not silently become the product source**: the product is the pinned SHA above, whatever commit the run checks out |
| baseline | the retained 4 Nov results and the later CI preflights, under their original revisions (product `ecb67b1f`), cadence, loads and environment. They stay side by side with the new run and are not re-run |

## 2. Scope

**A-only.** Aggregator A = ristik/aggregator-go `integration/enshrined-evm`. The upstream-facing aggregator B and the UTB feeder (aggregator-go #16/#17, bft-core #967's variant) are **not accepted by this release**; `aggregator-go-upstream` in `deploy/testnet/pins.json` (12ab9074) is the image variant #967 added and is not exercised by any stage listed here. An A pass does not accept B. B needs a merged feeder pin, its own manifest revision and the affected live-source and bridge reruns.

Bridge across a PoS transition (#430 row 2): the §4.1 preflight **passed in CI** (bft-core#979 run 42546603859 at 4baaca59, GitHub-hosted runner, `--pos --utb`, aggregator A, epoch 1→2; dev4's summary `briefs/dev4-bridge-pos-preflight-2026-11-09.md`, with arch's review pending). A second CI run, **42555135158 at 6a88e290** (nbp d352e88a), redeemed a separate epoch-1 token on the per-SID path after activation, with both anchors sealed at root epoch 1 (receipt succeeded, vault credited exactly the lock); run 42546603859 stays separate evidence with its original pins. A fourth CI run, **42584403015 at f7963086** (the full #979 workflow: all 10 steps passed: restarts, aggregator restart, replays, SDK clients, custody, `utb-live`; dev4, #979 comment 6736397010). A third CI run, **42570597750 at e52080d9** (the pos-gap preflight, bft-core#979 comment 6733978274): 2->3, a lagging wallet repairs epochs 2 and 3 in one-entry pages, a fresh process reloads 1..3, EntryIDs matched, exact credit, custody balanced. That is CI evidence only: not a host run, and not the accepted bridge-on-PoS row. arch (dev4's brief): host execution/reservation not yet at the published pins; still to do before it: the freeze of the pins below, the host run itself, and the owner merges (every step of the bridge stage has a CI pass above, on unmerged nbp). Done since: nbp#67, #68, #69 and #70 merged into nbp main (§57, no owner merge needed) and #979 re-pinned to the merge commit of #70 (`a39d5928`, #979 head 654d0996). Still #979 merged through the queue as `3d4fa198` (rev3 approved; gates green at landing head `3f5a2840`). Arch's review of the preflight is not recorded in this file; if it is wanted before the run it is a confirmation item of the freeze request. If any of them slips, this release is the PoS-only manifest and #430's bridge row stays open for a later manifest revision.

## 3. Components

| Component | Commit | Source | Why this one |
|---|---|---|---|
| bft-core (product) | `3d4fa198639c1a47d12c09171a1d2ea53d660e45` | `pins.json: bft`; images and host tools are built from it | arch §10: the product is the newer frozen commit, not `ecb67b1f` (`ecb67b1f8542bae014c532d064c205306451b7c2` stays the **baseline** of the existing evidence and is not re-run). The complete `ecb67b1f..<product SHA>` product delta is listed here at the freeze, by file (`git diff ecb67b1f..<product SHA> --stat -- '*.go' ':!*_test.go'`) and by change, **not described as harness-only**. At the product SHA it is **37 non-test Go files (+1347/-427)**, 3 of them tools under `scripts/` (`dnb-tool`, `utb-evidence`): the verified-certificate cache and timeout replay skip (#982/#992, #984), the V1 certification response frame limit (#993), the configuredprogress journal fix (#994), shard pending-work diagnostics (#995), loop profile and env-gated shadow counters (#980/#985/#986, measurement), gettrustbase on bft-go-base's response, status, limits, decoder and bundle code (#1001: `gettrustbase/` 4 files, `bridgeprofile`, `cli/ubft/cmd/utb_bundle.go`), the corpus authority as a trust base v2 bundle (#1000, `ucfixture`), fixtures (`q3fixture`, `rsmtbatch`, `executortest`), and the dnb-tool/bridge changes of #979. The receiver stream deadline hook (#987) is test-only. The list is `git diff --name-only ecb67b1f..3d4fa1986 -- '*.go' ':!*_test.go'` |
| ureth | `10552af21b31b2118c51d6215cd23cfb80faf33c` | `pins.json`, `lane-pins.json` | retained; `unicity/main` 7b2bc1b6 differs by corpus files only |
| unicity-pos-contracts | `7b510f6b5a9cf3987ccc5d7dc77d39f33de12330` | `pins.json`, `bridge/pins.json`, `lane-pins.json` | retained; `main` 4a32df9d adds golden-reference files, `src/` unchanged since be6e86fb |
| aggregator-go A | `b3909de4c8c0dc4682fbb6c7ff9732e7c1771207` | `pins.json`, `lane-pins.json` | integration head; moved from `009974a7` by #1002 (landed as `a0193e2a`, ristik/aggregator-go#23) |
| native-bridge-plugins (corpus and joined checks) | `838b08ce4304428c9ebcb9b0fbd4b55b260a99d4` | `bridge/pins.json`, `lane-pins.json` | retained; `main` f1c4a6a8 changes joined-test pins only |
| native-bridge-plugins (**bridge consumer**) | `a39d5928e6d1a0c5c2c6a3af4f1557b720cee8dc` (nbp main; merge commit of nbp#70, parents `51f3664c` (nbp#69 merge) and `52b3ff43`; the pin of bft-core#979 at its head 654d0996, per dev4). nbp#70 changes the live driver negatives only (`tests/live/conflict.ts`, `tests/live/anyage.ts`, `tester/bridge-tester.ts`: the conflicting burn's verdict is read after later blocks). The consumer's trust-refresh and persistence work is #67 `d0723124` and #68 `a466adac` (both inside 51f3664c) | `bridge/pins.json` (bft-core#979) | the preflights ran on the unmerged heads 948d429a (#67), d352e88a (#68 on #67) and 8d7436ba, then on the merged 51f3664c; the pin is now a39d5928. nbp#71 (the staging-SDK port: JS c5840ef5 re-vendored, Rust de79e6c1) merged as `73bee544`, nbp main's head. **The consumer pin of the full run is `73bee544`, not a39d5928**: bft-core#979 is re-pinned to 73bee544 (head 1219ece9, a one-line `bridge/pins.json` change; dev4 checked the tree against f6ccc841). the bridge preflight on the landing head `3f5a2840` (nbp `73bee544`, the new SDK pair): workflow `testnet-bridge-pos` run **42689024892 succeeded** (the same head: testnet-package 42689024939, testnet-rehearsal 42689024768, ci-lane 42689025045, testnet-bridge 42689025095, xrepo 42689025118 succeeded; go-ci 42689024946 succeeded on rerun after a first-attempt failure of the network latency test, bft-core#1004, cause not established). #979 merged as squash `3d4fa198` (landing head `3f5a2840` is a merge-only update of the approved `98a2c4c8`). The earlier preflights ran on the old SDK pair and do not transfer |
| Foundry | 1.8.1, sha256 `37b45855232e57624d90113b049ca54f0c92055bb5c1997fcbdc3076c7b89c10` | `bridge/pins.json` | unchanged |

Reference updates ureth #95, contracts #79, nbp #64: **not taken**. If taken before freeze, their exact revisions replace the rows above and the affected corpus and joined checks are re-run; old evidence is not relabelled.

## 4. The three pin files (they differ on purpose)

| File | Role | Change in this PR |
|---|---|---|
| `deploy/testnet/pins.json` | node images | the freeze commit sets `bft` to the product SHA (§1); landed in bft-core#1005 (squash `5e07f210a3963ce20b430bf3a1c19d8cbe43a3eb`, parent `3d4fa198`). Against the baseline package pins (`20c27f428`, #968, the pins of the existing evidence) the file differs in exactly three keys (`git diff 20c27f428 5e07f210a -- deploy/testnet/pins.json`): `bft` `ecb67b1f` -> `3d4fa198` (#1005), `aggregator-go` `009974a7` -> `b3909de4` (#1002), and the new key `aggregator-go-upstream` `12ab9074` (#967: read by `generate.py` only for `--utb-aggregator upstream`, the upstream-facing aggregator variant; the A-only default does not use it); #979 does not touch the node images. The package workflow's pinned bft checkout (`testnet-package.yml` `ref:`) follows it (guarded by `test_package` B1Layout) |
| `deploy/testnet/bridge/pins.json` | bridge tools (built from their own pins; `dnb-tool` from the package's own bft-core checkout, recorded in `artifacts/bridge-images.json`) | in bft-core#979 (not in this PR): `native-bridge-plugins` 838b08ce → 51f3664c |
| `scripts/ci/lane-pins.json` | CI lanes | **adds the bft-core product pin** (arch §10: `lane-pins.json` has none today and the lane builds its own checkout): the product SHA is selected and enforced in the lane's build/check path, with a separate product checkout when the harness commit differs, so the CI campaign builds the same immutable product as the package. The nbp row stays `838b08ce` (corpus and joined checks; `main` only adds the bridge-consumer tester work and joined-test pins, none of which the lane runs); it does not follow the bridge consumer pin. **merged as bft-core#1005** (`5e07f210`): `components["bft-core"]` = `3d4fa198`, read only by a run with `product=pinned` (dispatch input, or `"product": "pinned"` in `run-inputs.json` of a `ci-lane-run/**` branch; pull requests and the nightly never read it). `build-tools.sh` builds `ubft` and the Go tools from a separate clean checkout at the pin (`check-pins.sh git bft-core`), `run-lane.sh` accepts a product other than the commit under test only when it equals the pin, and the evidence records product and harness separately (`bft-core head=<product> harness=<HEAD>`). Verified by a build-only pinned run, 42710230020 (harness `ec294ee9`): `product-commit.txt` = `3d4fa198`, `ubft`, `dnb-tool`, `utb-evidence` stamped `vcs.revision=3d4fa198`, `vcs.modified=false`. The lane's `state-transition-sdk-js` pin stays `75c5be7f` (`c5840ef5` has no `lib/util/TrustBaseUtils.js`, which the lane scripts need; owner-questions Q31) |

A changed package contract pin does not reach the bridge tools.

## 5. SDKs: two named consumers

| Consumer | Revision |
|---|---|
| public SDK fetch/cache acceptance clients | JS `c5840ef5f59201c52ea6cf7034ee02cb48d54007`; Rust `de79e6c1e393a1846b75bca0640b9ec9a55aa143`; Java `9fe6bf8ff16eaee162faea0c00404bc7d330b77b` (ristik staging heads `integration/enshrined-evm`; Java staging = main) | `deploy/testnet/sdk-clients/pins.json`, moved from JS `41cb7ddb` / Rust `4be1330d` by bft-core#1003 (squash `983102b73bcb7d3877f99818bf914d68bea9fb39`, landing head `f223fd54`; testnet-bridge-pos 42728411653, testnet-package 42728411685, testnet-rehearsal 42728411475, testnet-bridge 42728411319, go-ci 42728411421, ci-lane 42728411662, xrepo 42728411343 all succeeded there) | the staging heads carry the UTB v2 work the clients exercise. The Dockerfiles fetch exactly this commit and refuse a different HEAD. Earlier preflight evidence with the old client pins (4 Nov and the first #979 runs) does not transfer to these clients. Not used: the `upstream-pr/utb-v2` heads (JS f35b19c6, Java 0c24027f), which still move in review |
| the bridge's own SDK | `c5840ef5f59201c52ea6cf7034ee02cb48d54007` (ristik/state-transition-sdk-js `integration/enshrined-evm`, the §57 reconcile merge #28) via nbp's vendored tarball `vendor/unicitylabs-state-transition-sdk-4.0.0-utb.c5840ef.tgz`, sha256 `6b415c1cadf614099b7eed22262b4a015b486b2e436cb378d85f2e0e79fba282` (`vendor/state-transition-sdk.provenance.json` names the build); bridge-core tarball `unicitylabs-bridge-core-0.1.0-bridge.2.tgz` sha256 `61bb461800dc17368b4afd5e07207667951e540eef85165e8bdc361d7898e596` (unchanged); `package-lock.json` sha256 `42e66e81b291e320cb2fb4b858e6adda4911c5bc887d06e575952805afec2537`; Rust `unicity-token` at `de79e6c1e393a1846b75bca0640b9ec9a55aa143` (state-transition-sdk-rust `integration/enshrined-evm`, #29). All at the nbp main merge commit `73bee544de82f52c399c60587a39332bdf6fd686` (nbp#71, merged under §57 on rev2's approval at f6ccc841; merged tree equals that head's tree `dce3059f`). Replaces the 75c5be7f / 0517256d pair of the earlier preflights |

The bridge does not use JS `main` and has no `TrustBaseSession` cache here; that is a separate port, not assumed.

## 6. Parameters per generation

| Generation | UTB | Election cadence | Caps |
|---|---|---|---|
| core (G1), crash, owner, resources | off | 400 rounds / 300 s (rehearsal) | 16,1,6 |
| crash e1, crash e2, join | off | as above | as above |
| bridge generation (bft-core#979 recipe) | on (`--pos --utb`, aggregator A integration) | 1500 rounds / 1200 s (the declared dispatch inputs `cadence_rounds`/`cadence_seconds` of the preflight run 42584403015; `testnet-bridge-pos.yml` writes them to the run's `generation-recipe.json`; workflow defaults are 800 / 600) | as the generation's own caps, read from that run's `generation-recipe.json` at freeze |
| campaign (lane `x4-exit`) | per lane | per lane | per lane |

Test values, recorded, not testnet decisions. Each generation records its own setting in `generation.txt` (driver revision 2). Results from different cadences are not cross-read.

## 7. Builds

Every binary is built from the pinned source at the manifest, on Linux; a binary of an earlier build is **not** reused unless its sha256 is identical and recorded. Commands as the package runs them (`deploy/testnet/build-images.py` checks each source against `pins.json` and refuses a dirty tree):

| Component | Command (cwd = pinned source) | Toolchain |
|---|---|---|
| ubft (node images and host tools) | `make build` (host: in `tn1-builder:bookworm`, host tools `go build ./scripts/b1genesis ./scripts/h4-restore-pin ./cli/ubft` and `./deploy/testnet/keygen`) | Go 1.25.14 (`lane-pins.json` toolchains; the builder image's version is recorded in `build-ubft.log`) |
| ureth | `cargo build --locked --release -p unicity-reth` | Rust 1.97.1 per `lane-pins.json` toolchains (the ureth repo's own nightly pin applies to its fmt gate, not to this build): confirmed: the build-ureth job of ci-lane run 42710230020 installs Rust `1.97.1` and builds `unicity-reth v2.5.0` with `--release --locked` (12 m 33 s) |
| aggregator-go A | `CGO_ENABLED=1 go build -trimpath -o build/aggregator ./cmd/aggregator` (no rocksdb tag: memory SMT backend, state in MongoDB) | Go 1.25.14 |
| node image and the faucet/rpc images | `build-images.py --bft-source … --ureth-source … --aggregator-go-source …` (tags `tnops-*:verified`, or `trackc-<bft8>` on the host driver) | Docker; base images by digest in `pins.json` (`runtime`, `python`, `mongo`) |
| bridge tools | `deploy/testnet/bridge/build-bridge-image.py` from `bridge/pins.json` (contracts, nbp, node, go, Foundry 1.8.1) | recorded in `artifacts/bridge-images.json` |

Results recorded **from the run, not from this PR**: `artifacts/images.json` and `artifacts/bridge-images.json` of each build (binary sha256 of `ubft`, `unicity-reth`, `aggregator`, and the image ids), copied to the evidence directory as `images.json`. They exist only once the run's builds have run, so this row is filled from them at the run, never from a build before the freeze.

## 8. Features

**Measured behavior switches are explicit, never inherited:** the product's optional instrumentation (`UBFT_SHADOW_CERT=1` certificate-verification shadow counters, the per-message-type loop profile, the backoff shadow and cache-report counters) is OFF in every acceptance run unless a row says otherwise (the log-only loop profile and cache report excepted, see below); a run that turns one on records it with its inputs. Read from the product `3d4fa198`: `UBFT_SHADOW_CERT=1` (certificate-verification shadow counters, off unless `1`), `UBFT_SHADOW_BACKOFF=1` with `UBFT_SHADOW_BACKOFF_C` (cap factor, default 4; off unless `1`), and `UBFT_CERT_CACHE=0` (turns the verified-certificate cache OFF: the cache is **on by default**, it is product behaviour of #982/#992, not a switch of this run). The per-message-type loop profile and the cache report are **not** switches: they log counters every 30 s unconditionally (`loopProfileInterval`), change no behaviour, and are present in every run. The acceptance runs set none of the three variables.

Enabled: PoS profile (`--pos`), caps 16,1,6, unit weights. Disabled: `--utb` on every generation except the bridge preflight; B/feeder; unequal genesis weights (the `pos-join-heavy` stage is the refusal control only). `--utb` on the bridge generation. Bridge-client trust refresh (`withTrustRefresh` through the pinned SDK's `fetchTrustBaseEntries`, nbp#67, merged). This list is final for the frozen inputs (product `3d4fa198`, harness `983102b7`, nbp `73bee544`).

## 9. Runs this manifest covers (filled as they complete)

| Run | Evidence | Result |
|---|---|---|
| R1 campaign refresh (lane `x4-exit`, run-9 inputs) | PENDING | PENDING |
| host: core, crash e3, owner, resources, e1, e2, join | PENDING | PENDING |
| bridge across a PoS transition | PENDING | PENDING |

4 Nov results stay side by side with these; neither replaces the other, and neither closes #437/#59 alone.

## 10. Residual assumptions

- **Comparison with 4 Nov.** The new results are compared with the old artifacts under their original revisions, cadence, loads and environment. No controlled performance comparison is claimed across differing inputs. A regression is attributed by a focused old/new reproducer or a bisect, not by a second full host campaign (arch §10).
- **Later merges.** SDK and aggregator upstream merges under §58 get their own manifest revisions and the affected acceptance reruns; they do not automatically repeat the whole campaign, and this run does not accept changes that are not in the pinned set.
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

Cross-cutting: the product is identified by its pinned SHA **and** by the binaries and images actually run (`artifacts/images.json`, `artifacts/bridge-images.json`: sha256 of `ubft`, `unicity-reth`, `aggregator`, image ids), recorded apart from the harness, manifest and run SHAs; a run whose binaries do not carry the pinned product SHA is not evidence for this manifest. The run exercises the restart/recovery and UTB paths of the included fixes (the crash and restart stages a, b, d, e; `utb-live` h), not only a build of them. For every stop/kill stage the full transition, certification and receipt timestamps are kept; "awaiting round N block from leader" names a shard leader, and the root leader/collector come from the root logs; one measured network on the host; host lock entry `~/host-lock/dev3-<generation>`.

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
