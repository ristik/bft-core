#!/usr/bin/env bash
# Sourced by drive.sh so its process and archive cleanup also covers this workload.
mkdir -p "$scratch/token-build/src"
cp "$here/QualificationToken.sol" "$scratch/token-build/src/"
forge build --root "$scratch/token-build" --use 0.8.37 --evm-version cancun -j 4
export NB2_ERC20_TOKEN_ARTIFACT="$scratch/token-build/out/QualificationToken.sol/QualificationToken.json"
cp "$here/QualificationToken.sol" "$NB2_OUT/descriptors/"
cp "$NB2_ERC20_PLUGIN/protocol/profile-erc20.json" "$NB2_OUT/descriptors/semantic-profile-erc20.json"
(
  cd "$NB2_ERC20_PLUGIN"
  find packages/native-bridge-plugin/lib wallet -type f -print0 |
    LC_ALL=C sort -z | xargs -0 sha256sum
) >"$NB2_OUT/erc20-wallet.sha256"
jq -n --arg contracts "$NB2_ERC20_CONTRACTS_REV" \
  --arg plugin "$NB2_ERC20_PLUGIN_REV" --arg oracle "$NB2_ERC20_ORACLE_REV" \
  --arg wallet "$(sha256sum "$NB2_OUT/erc20-wallet.sha256" | cut -d' ' -f1)" \
  --arg lock "$(sha256sum "$NB2_ERC20_PLUGIN/package-lock.json" | cut -d' ' -f1)" \
  --arg profile "$(sha256sum "$NB2_OUT/descriptors/semantic-profile-erc20.json" | cut -d' ' -f1)" \
  --arg token "$(sha256sum "$NB2_OUT/descriptors/QualificationToken.sol" | cut -d' ' -f1)" \
  '{contracts:$contracts,plugin:$plugin,oracle:$oracle,walletIndexSha256:$wallet,lockSha256:$lock,profileSha256:$profile,testTokenSourceSha256:$token}' \
  >"$NB2_OUT/descriptors/erc20-build-index.json"
rm -- "$scratch/sdk" "$scratch/wallet"
ln -s "$NB2_ERC20_PLUGIN/packages/native-bridge-plugin/lib" "$scratch/sdk"
ln -s "$NB2_ERC20_PLUGIN/wallet" "$scratch/wallet"
erc20_driver=("$NB2_ERC20_PLUGIN/node_modules/.bin/tsx" "$scratch/driver.ts" "$NB2_OUT" "$rpc" "$agg" "$chain"
  "$NB2_ERC20_ARTIFACTS" "$here/create.py" "$scratch")
NB2_ERC20_MODE=deploy run_driver "${erc20_driver[@]}"
cp "$scratch/send-key" "$scratch/operator-key"

for kind in plain fee; do
  export NB2_ERC20_MODE="$kind"
  export NB2_ARCHIVE_SEGMENTS=2 NB2_ARCHIVE_WINDOW=2 NB2_OFFLINE_PEAK=0
  if [[ "$kind" = fee ]]; then
    export NB2_ARCHIVE_SEGMENTS="${NB2_ERC20_FEE_SEGMENTS:-72}" NB2_ARCHIVE_WINDOW=6 NB2_OFFLINE_PEAK=1
  fi
  export NB2_LOAD_SKEW=1 NB2_PACKET_OPERATIONS=16
  openssl rand -hex 32 >"$scratch/relayer-key"
  openssl rand -hex 32 >"$scratch/load-key"
  openssl rand -hex 32 >"$scratch/holder-key"
  archive_url="$scratch/$kind-archive-url"
  python3 "$here/probe-qualification.py" archive "$rpc" "$chain" "$(cat "$NB2_OUT/execution.pin")" \
    "$archive_url" >"$NB2_OUT/$kind/preferred-archive.log" 2>&1 &
  archive_pid=$!
  for ((i = 0; i < 50; ++i)); do [[ -s "$archive_url" ]] && break; sleep .1; done
  export NB2_RECEIPT_PRIMARY_RPC="$(<"$archive_url")"
  export NB2_RECEIPT_ALT_RPC="http://127.0.0.1:$(("${rpc##*:}" + 1))"
  run_driver "${erc20_driver[@]}"
  rm -- "$scratch/holder-key"
  rm -rf -- "$scratch/app-wallet"
  if [[ "$kind" = fee && "${NB2_ERC20_CALIBRATE:-0}" = 1 ]]; then
    # Keep the same sealer running through Start, archive failover and Resume.
    NB2_RESUME_STAGE=load "${erc20_driver[@]}" &
    load_pid=$!
  fi
  NB2_RESUME_STAGE=checkpoint run_driver "${erc20_driver[@]}"
  stop_archive
  if [[ "$NB2_OFFLINE_PEAK" = 1 ]]; then
    if [[ -z "$load_pid" ]]; then
      NB2_RESUME_STAGE=load "${erc20_driver[@]}" &
      load_pid=$!
    fi
    NB2_RESUME_STAGE=settle run_driver "${erc20_driver[@]}"
    wait "$load_pid"
    load_pid=
  else
    NB2_RESUME_STAGE=load run_driver "${erc20_driver[@]}"
    NB2_RESUME_STAGE=settle run_driver "${erc20_driver[@]}"
  fi
done
