# Sixteen-seat PoS hook measurement

Use a private ureth worktree at `caaf5df681d1c021155a08a3f160ce8dbd92a7ac` (ristik/ureth#112: unicity/main with the #1286 contracts fixtures; the registry genesis origin of #1297 is in the fixtures, so an older ureth revision does not elect under them). Apply `ureth-pos16.patch` there and copy `test/vr/fixtures/vr-hook-pos.json` from the matching unicity-pos-contracts revision to `crates/unicity/execution/testdata/vr-hook-pos.json`.

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
