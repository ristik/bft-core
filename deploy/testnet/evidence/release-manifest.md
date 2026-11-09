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

Bridge across a PoS transition (#430 row 2): **PENDING(bft-core#979 preflight result and ristik/native-bridge-plugins#67 merge)**. If either fails or slips, this release is the PoS-only manifest and #430's bridge row stays open for a later manifest revision.

## 3. Components

| Component | Commit | Source | Why this one |
|---|---|---|---|
| bft-core (product) | `ecb67b1f8542bae014c532d064c205306451b7c2` | `pins.json: bft`; images and host tools are built from it | retained; the `ecb67b1f..` delta has no production Go change (arch), and its script/workflow/helper changes are the harness, recorded above. PENDING(re-read the delta at freeze: `git diff ecb67b1f..<harness SHA> -- ':!*_test.go'` file list) |
| ureth | `10552af21b31b2118c51d6215cd23cfb80faf33c` | `pins.json`, `lane-pins.json` | retained; `unicity/main` 7b2bc1b6 differs by corpus files only |
| unicity-pos-contracts | `7b510f6b5a9cf3987ccc5d7dc77d39f33de12330` | `pins.json`, `bridge/pins.json`, `lane-pins.json` | retained; `main` 4a32df9d adds golden-reference files, `src/` unchanged since be6e86fb |
| aggregator-go A | `009974a72560c1f224fef99ada9fbf475f1488a7` | `pins.json`, `lane-pins.json` | integration head |
| native-bridge-plugins (corpus and joined checks) | `838b08ce4304428c9ebcb9b0fbd4b55b260a99d4` | `bridge/pins.json`, `lane-pins.json` | retained; `main` f1c4a6a8 changes joined-test pins only |
| native-bridge-plugins (**bridge consumer**) | PENDING(merge commit of nbp#67; head f3c8c337 today, SDK pin unchanged at 75c5be7) | `bridge/pins.json` | until it merges, 838b08ce is not that consumer's complete source |
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
| bridge preflight (bft-core#979) | on | 1500 rounds / 1200 s (declared there) | PENDING(from #979) |
| campaign (lane `x4-exit`) | per lane | per lane | per lane |

Test values, recorded, not testnet decisions. Each generation records its own setting in `generation.txt` (driver revision 2). Results from different cadences are not cross-read.

## 7. Builds

PENDING(exact command and toolchain per component: ubft in `tn1-builder:bookworm` via `make build`; ureth `cargo build --release --locked -p unicity-reth`, nightly pin as in `lane-pins.json`; aggregator-go; images by `build-images.py`; resulting image ids and binary sha256 from `artifacts/images.json`, filled from the run's evidence, not from this PR).

## 8. Features

Enabled: PoS profile (`--pos`), caps 16,1,6, unit weights. Disabled: `--utb` on every generation except the bridge preflight; B/feeder; unequal genesis weights (the `pos-join-heavy` stage is the refusal control only). PENDING(final list after #979).

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
- `utb-live` (bft-core #978) has not yet run on a live `--utb` generation; its first run is the evidence for it.
- Not covered by the campaign: a membership change on the accumulated chain, a non-offender exit there, a separate collector-restart fault.
