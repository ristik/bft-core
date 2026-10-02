# T1 final genesis export (synthetic manifest, SealRegistry v2)

Record of the deterministic genesis export on the integration build, run twice from clean checkouts
with the T1 independent-builds procedure (`briefs/t1-independent-builds.md`, earlier run on `3057e052`). **Not a
production genesis:** the allocation manifest, chain ID `1337` and base shard configuration are the synthetic
examples. The production export repeats once the owner selects chain ID, supply, allocations, addresses and fee
parameters. It is not a T5 signoff.

## Inputs
- bft-core `626b6ebd73e151a9f635fcf26daf22f33cbbedbd` (`origin/integration/enshrined-evm` after #367).
- unicity-pos-contracts `e7eb3216549b772a9e1df2b1214976d7dd9e6e62`, OpenZeppelin `c64a1edb…`, forge-std `bf647bd6…`.
- Manifest `registrygenesis/testdata/allocation-build-v1.example.json`, SHA-256 `94dd351415fbb97ea3ab2fa755a51828bae9931019770370d19e8f53e5a43194`; base shard configuration SHA-256 `29929442f8b51257fa038ccd3eaf6123406b63f3d2597849019506a25e535f49` (`base-shard-conf.json`, the same file as the 2026-09-30 run).
- Toolchain: Go `go1.27.1`, Foundry `1.8.1`, `darwin/amd64`; `--registry-layout 2`.
- Each side: a separate detached worktree of both repositories, a new `HOME` and empty `GOCACHE`/`GOPATH`/`GOMODCACHE`. The three contract artifacts were rebuilt with `forge` in each side and matched the checked-in `t1-artifacts` byte for byte (no diff).

## Result: PASS, byte-identical
| Output | SHA-256 (runs A and B) |
|---|---|
| Finalized genesis JSON | `3a183dc4d5698ab3ecdd56a9fa212c79afa6cb73e5ef8cdb39b1c34c36ef9fd6` |
| Full shard configuration JSON | `a9902b87f769f2c85d15899aa0154aa59b6e727dc934b97162703416bd8f5979` |
| Exported manifest | `29eefe0234bdc201250a0d187b07a67b5be6d87cd64771bc92eb7d4f8a419bad` (unchanged since 2026-09-30) |
| `ubft` binary (`-trimpath`, `go build -a`) | `7b963e48a5f3558cb1b035699c5f77594fc3640564f8406b8b813632b7238237` (identical on both sides, same host) |
| FeeCollector / WUCT / VestingVault artifacts | `f07711f6…fe58a` / `d7d80b17…ca0db` / `18d059fa…b242`: as in the T5 dossier |

Printed identities (both runs): registry layout 2, code hash `0x7787f3166565c8e5ebd73801bf71cbacf0cf69f6bcfb8dea8bedbef8198caf38`; full shard conf hash `0x4c2d96e8aceb59a07ba788c289826497ce08cdd299726dad9b64211a485f5cc0` (initial assignment: shard epoch 0, the immutable genesis hash); state root `0x5f7bbd70f9364f80a40a52910a1a48f97067cc98d9363d796542d2da8dd8f6c6`; block hash `0x15c83d5755335361764f96ef287304edf8182375c1881a285d9a583b3dc32034`; execution config identity `0xf63207575830a59dece6e1b59ecbc46faa865492715252d5a846a6996bde98ba`; origin identity `0x2623ccb879acf7eab04eacdce5e9a21e845933d0da6bf70bf90ea61cbab52803`.

## Limits
- One host and one toolchain: the builds are independent environments, not independent machines or operators.
- These hashes are for the synthetic v2 genesis. The 2026-09-30 genesis used layout 1 (genesis `f0de30fe…`, state root `0xb14f8126…`) and is superseded for M3.
- One side needed a retry of `go mod download` after proxy read errors (cold cache each time), per the operator; the retained logs do not show it (side A's `modules.log` is empty, side B's earlier script version kept no module log). Modules are verified against `go.sum` (`-mod=readonly`), and the outputs of both sides are byte-identical.
- Any later change under `registrygenesis/`, the contracts pin, the artifacts or the genesis command invalidates this record; regenerate it on the final build.
- Logs, scripts and outputs: `briefs/t1-independent-builds-20261002/` (local, not in the repo): `run.sh`, `run-a/`, `run-b/` with `SHA256SUMS`, `toolchain.txt`, `genesis.log`.
