# Sixteen-seat PoS hook measurement

Use a private ureth worktree at the ureth pin of `deploy/testnet/pins.json` (`f3731651`, ureth#113; bft-core#1319: the record kind 9 import, the SealRegistry runtime `0x93dae8b0…` and the contracts' `85950b44` hook fixtures, whose registry genesis origin is `0xe2985dec…`; an older ureth revision does not elect under them). Apply `ureth-pos16.patch` there and copy `test/vr/fixtures/vr-hook-pos.json` from the matching unicity-pos-contracts revision to `crates/unicity/execution/testdata/vr-hook-pos.json`.

Run from the ureth worktree. Set `MODULE_CODE_HASH` to the compiled PoS adapter hash from the verified genesis deployment and use an absolute path for the fresh measurement.

```sh
VR_HOOK_BUILD=pos VR_HOOK_MODULE_CODE_HASH="$MODULE_CODE_HASH" \
  VR_HOOK_MEASUREMENT="$FRESH_MEASUREMENT" CARGO_BUILD_JOBS=4 \
  cargo test -p reth-unicity-execution --features test-utils --test vr_hook -- --ignored --exact vr_hook_measurement --nocapture
```

The hook fixture drives the real VR runtime with cap-bounded module paths. The matching contracts revision's `PosCompactSixteenTest` exercises the real adapter. For genesis and the live lane, use `vr-hook-pos16.json` as the recorded measurement and pass the independently generated file as `VR_FRESH_MEASUREMENT`. The run uses 15 genesis validators plus one joiner, `VR_POS16=1`, `VR_POS_RECOVERY=1`, `SIGNING=authority` and `VR_UTB=1`.

The Compose ceremony in package CI uses `vr-hook-pos16-independent.json`,
the independently recorded #1215 rerun from
`~/evidence/1215/vr-hook-measurement-pos16-fresh.json` on the dev host. The two
runs produced identical bytes. CI rechecks both against a newly generated
four-member genesis and the pinned contracts build.

bft-core#1303 re-measured both files twice: for the parking adapter (contracts#102, `0x307acec9…`) and then for contracts main `d86eb106` (the contracts#103 merge: the adapter emits `ParkSkipped` when a park fails), whose PosElectionAdapter is `0x64e35cd3…` (`script/vr-pos-genesis.sh` on the sample input). The ureth revision, the patch, the VR runtime (`0xbd919cb8…`) and `vr-hook-pos.json` (sha256 `0xe2273a50…`) are unchanged. Each time the two runs are byte-identical and every gas figure equals the #1286 measurement; only the module code hash moved.

bft-core#1319 re-measured both files for contracts `85950b44` (record kind 9 `PoPMissed`: the VR records facet, the core `0xe1a8cc6b…`, the PosElectionAdapter `0xeca12529…` and `vr-hook-pos.json` sha256 `0xa7b8d74e…` all move) on the ureth #1319 branch with the refreshed `ureth-pos16.patch` (its `record_requirement` is now 19,926,739). The two runs are byte-identical. The boundary rises from 19,926,696 to 19,926,739, the records requirement from 43,606,278 to 43,607,048 and the combined reservations by 770 each; the elect figures are unchanged.
