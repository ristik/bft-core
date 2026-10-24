# Bridge measured bounds

The measured prices, resources and limits behind the bridge release's numbers (`deploy/testnet/bridge`, `bridge-release.json` `limits`), in one place in the repository.
Every figure is from a GitHub-hosted runner, not from the testnet host; the host's envelope is measured separately (X1-MAIN #440). Protocol of
each measurement as stated.

## Native composition price (B7, protocol 5)

ureth `b7-bench.yml` run 39603730828 (2026-10-21; bft-core#741, oracle f8037d87, ureth dd1c5913), `ubuntu-24.04` standard runner (AMD EPYC
7763, 4 vCPU), 3 runs × 5 iterations, every case's coefficient of variation below 0.5%, status and gas equal to the oracle's in all 22 cases.
Baselines: ECRECOVER 214 µs (71.4 ns/gas), SHA256 of 1 KiB 1.7 ns/gas.

| case | leaves | anchors | input KB | exec gas | tx gas* | ms | ns/gas | × ECRECOVER |
|---|---|---|---|---|---|---|---|---|
| cons-s4-l24 | 24 | 4 | 17 | 0.60M | 0.84M | 8.3 | 13.8 | 0.19 |
| cons-s8-l256 | 256 | 8 | 160 | 5.06M | 7.19M | 87.1 | 17.2 | 0.24 |
| cons-s4-l1000 | 1000 | 4 | 686 | 20.1M | 29.5M | 340 | 16.9 | 0.24 |
| orig-s8-l1000 | 1000 | 1000 | 1454 | 29.9M | 48.0M | 389 | 13.0 | 0.18 |
| dense16-orig-s4-l256 | 256 | 256 | 821 | 31.8M | 43.7M | 255 | 8.0 | 0.11 |
| deep32-cons-s4-l256 | 256 | 4 | 369 | 7.18M | 13.9M | 88 | 12.3 | 0.17 |
| late-orig-s8-l1000 (status 62) | 1000 | 1000 | 1455 | 29.9M | 48.0M | 390 | 13.0 | 0.18 |

\* tx gas = max(21000 + standard calldata + exec, the EIP-7623 floor); the floor binds for large envelopes. Peak heap during a call is at most
2.0 MB. A late failure costs the same time as a success and is charged the same.

What they decided (bft-core#741): **D1** the direct envelope bound is 2 MiB (the largest measured, 1.45 MB, fits) and the pool's input bound
4 MiB; **D2** the trial gas schedule stands (worst 17.2 ns/gas against the 47.6 ns/gas limit, ECRECOVER/1.5: 2.8× margin); **D3** the ordinary
block capacity is 60M gas (the largest redemption, 48.0M tx gas, plus the vault wrapper), so a full block of the worst shape executes in about
0.73 s on the runner.

Protocol 6 (`BRIDGE_COMPOSE_V2`) adds `G_split` to the same schedule: `16·len(outer mint)` on every return (at every depth), and the split
lineage's terms only for a split part (spec section 6). It is not re-benchmarked; the per-gas time of the extra hashing is the same
SHA-256 work the table prices.

## Live redemptions on the package (protocol 6)

testnet-bridge run 40051018512 (2026-10-24, bft-core#817 at its final pins: bft 6ec52a81, ureth d41d5310, native-bridge-plugins 97f74161,
contracts 590eda63), one aggregator (K = 1), hosted runner:

| stage | history | envelope | redeem gas used | notes |
|---|---|---|---|---|
| `long-history` | 250 transfers, 252 leaves, history 72,117 B | 181,568 B | 8,029,336 (estimate 8,179,338) | bisected minimum 8,134,110 (calldata floor 6,075,640); at minimum − 1 status 0, 7,963,717 gas used, vault unchanged |
| `split` | the 60 of a depth-1 split | — | — | out of gas at 590,318 of the 885,477 estimate: status 0, vault unchanged |

The single aggregator consolidates at most 254 transfers (the SDK's 256 state IDs per endpoint batch), so the package runs 250. Where an
admitted history has no direct exit at all (the 2 MiB token bound against the block capacity) is measured in native-bridge-plugins
`docs/admitted-shapes.md`.

## Resources

**The package with the bridge services**, testnet-bridge run 40051018512, `docker stats` at the end of the run (after `custody`):

| service | memory | limit |
|---|---|---|
| ureth1..4 | 184 to 189 MiB each | 1.5 GiB |
| mongo | 351 MiB | 768 MiB |
| prometheus | 174 MiB | 256 MiB |
| aggregator | 98 MiB | 512 MiB |
| shard1..4 | 22 to 24 MiB each | 512 MiB |
| root1..4 | 18 MiB each | 384 MiB |
| faucet, relay, rpc, metrics1..4, authority1..4 | 10 to 17 MiB each | 64 to 256 MiB |
| lockproof | 8.4 MiB | 256 MiB |

The disk after the run: 56 GiB used of the runner's 146 GiB (`df.txt`), the bridge stages, their images and the restored generation included.

**The CI combined lane with two aggregator shards and a long history**, ci-lane run 40045012351 (2026-10-24, bft-core#818 at f9d548b9:
ureth d41d5310, contracts 31b2ec1a, native-bridge-plugins 97f74161), `resources-run-lane-combined`, sampled every 5 s over 1,842 s on a
4-vCPU, 16 GiB runner: memory used peak 5.70 GiB (lowest available 9.9 GiB), no swap, root file-system growth peak 5.70 GiB.

Not measured here: the host (X1-MAIN #440), arm64, and memory under sustained bridge load.
