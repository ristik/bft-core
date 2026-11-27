# Sixteen-seat PoS hook measurement

Use a private ureth worktree at the ureth pin of `deploy/testnet/pins.json` (`c91535bf`, the ureth#113 merge, which also carries #114; bft-core#1319: the record kind 9 import, the SealRegistry runtime `0x93dae8b0…` and the contracts' `85950b44` hook fixtures, whose registry genesis origin is `0xe2985dec…`; an older ureth revision does not elect under them). Apply `ureth-pos16.patch` there and copy `test/vr/fixtures/vr-hook-pos.json` from the matching unicity-pos-contracts revision to `crates/unicity/execution/testdata/vr-hook-pos.json`.

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

## Four-validator PoA recovery

The Compose generator's `--vr-pos` flag selects the PoS adapter. For a PoA VR
generation, use the paired devnet with a private contracts checkout at the
`vr-contracts` pin in `deploy/testnet/pins.json`. The paired lane calls
`script/vr-genesis.sh` to install the PoA VR runtime and PoaElection. Its
recorded hook measurement is `deploy/testnet/vr-hook-measurement.json`.

Generate the independent measurement in a private ureth checkout at the
package's `ureth` pin. Use the PoA fixture `test/vr/fixtures/vr-hook.json` from
the pinned contracts as `crates/unicity/execution/testdata/vr-hook.json` in ureth.
Set `MODULE_CODE_HASH` to the PoaElection hash in the recorded measurement and
`FRESH_MEASUREMENT` to an absolute output path.

```sh
VR_HOOK_BUILD=poa VR_HOOK_MODULE_CODE_HASH="$MODULE_CODE_HASH" \
  VR_HOOK_MEASUREMENT="$FRESH_MEASUREMENT" CARGO_BUILD_JOBS=4 \
  cargo test -p reth-unicity-execution --features test-utils --test vr_hook -- --ignored --exact vr_hook_measurement --nocapture
```

From a private BFT checkout after acquiring a lane slot (see
[Lane slots](../../../docs/lane-slots.md)), run the following with
`PRIVATE_CONTRACTS`, `URETH_BINARY`, `EVIDENCE` and `LOG_DIR` set to absolute
paths. Set `URETH_COMMIT` to the package's ureth pin and point
`VR_FORGE_HOME` at a Forge home with the contracts' solc version if it differs
from the default home.

```sh
CARGO_BUILD_JOBS=4 VR_LANE=1 Q3_B1=1 M2_PROFILE2=1 \
  VR_POS=0 VR_JOINER=0 VR_ARCHIVE=0 VR_UTB=0 VR_AGG=0 SIGNING=local \
  VR_POA_RECOVERY=1 VR_STEPS=scripts/vr-boundary-steps.sh \
  VR_CONTRACTS="$PRIVATE_CONTRACTS" VR_FRESH_MEASUREMENT="$FRESH_MEASUREMENT" \
  POST_M2A_URETH_BIN="$URETH_BINARY" POST_M2A_URETH_COMMIT="$URETH_COMMIT" \
  VR_EVIDENCE="$EVIDENCE" M2_RUN_LOG_DIR="$LOG_DIR" \
  ./scripts/reth-paired-devnet.sh 4 10
```

The stage rotates identity 4's payee to create a successor, then stops two
shard nodes so the successor cannot acknowledge. It checks the committed
recovery into root epoch 3, restarts both shard nodes and verifies that all
four incumbent nodes serve and vote. It also compares the complete recovered
committee to genesis and polls the EVM's finalized block number after recovery.
