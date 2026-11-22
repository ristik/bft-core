# Sixteen-seat PoS hook measurement

Use a private ureth worktree at `b61d3beebf9e08e900e3bb88f5e3b2d275bc1dec`. Apply `ureth-pos16.patch` there and copy `test/vr/fixtures/vr-hook-pos.json` from the matching unicity-pos-contracts revision to `crates/unicity/execution/testdata/vr-hook-pos.json`.

Run from the ureth worktree. Set `MODULE_CODE_HASH` to the compiled PoS adapter hash from the verified genesis deployment and use an absolute path for the fresh measurement.

```sh
VR_HOOK_BUILD=pos VR_HOOK_MODULE_CODE_HASH="$MODULE_CODE_HASH" \
  VR_HOOK_MEASUREMENT="$FRESH_MEASUREMENT" CARGO_BUILD_JOBS=4 \
  cargo test -p reth-unicity-execution --features test-utils --test vr_hook -- --ignored --exact vr_hook_measurement --nocapture
```

The hook fixture drives the real VR runtime with cap-bounded module paths. The matching contracts revision's `PosCompactSixteenTest` exercises the real adapter. For genesis and the live lane, use `vr-hook-pos16.json` as the recorded measurement and pass the independently generated file as `VR_FRESH_MEASUREMENT`. The run uses 15 genesis validators plus one joiner, `VR_POS16=1`, `VR_POS_RECOVERY=1`, `SIGNING=authority` and `VR_UTB=1`.
