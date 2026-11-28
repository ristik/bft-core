#!/usr/bin/env bash
# Sourced by drive.sh so its process and archive cleanup also covers this workload.
: "${NB2_ERC20_CONTRACTS:?path to built contracts #107 merge checkout}"
: "${NB2_ERC20_PLUGIN:?path to built plug-ins #99 merge checkout}"
: "${NB2_ERC20_ORACLE_SOURCE:?path to the bft-core #1338 merge checkout}"
: "${NB2_ERC20_ORACLE_REV:?pinned bft-core #1338 merge commit}"
export NB2_ERC20_ARTIFACTS="$NB2_ERC20_CONTRACTS/out"
test "$(git -C "$NB2_ERC20_CONTRACTS" rev-parse HEAD)" = de62921f10be506f3cd7a559ae8541bcb644d0f4
test "$(git -C "$NB2_ERC20_PLUGIN" rev-parse HEAD)" = 43c4535deccee68f45a2400848ec9b28dbec9999
test "$NB2_ERC20_ORACLE_REV" = 5bf749649d1f61c8ac81c1fc9983019833462115
test "$(git -C "$NB2_ERC20_ORACLE_SOURCE" rev-parse HEAD)" = "$NB2_ERC20_ORACLE_REV"
test -f "$NB2_ERC20_ORACLE_SOURCE/nb2ref/erc20_vectors_test.go"
for checkout in "$NB2_ERC20_CONTRACTS" "$NB2_ERC20_PLUGIN" "$NB2_ERC20_ORACLE_SOURCE"; do
  test -z "$(git -C "$checkout" status --porcelain --untracked-files=no)"
done
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
jq -n --arg contracts "$(git -C "$NB2_ERC20_CONTRACTS" rev-parse HEAD)" \
  --arg plugin "$(git -C "$NB2_ERC20_PLUGIN" rev-parse HEAD)" --arg oracle "$NB2_ERC20_ORACLE_REV" \
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
  NB2_RESUME_STAGE=checkpoint run_driver "${erc20_driver[@]}"
  stop_archive
  if [[ "$NB2_OFFLINE_PEAK" = 1 ]]; then
    NB2_RESUME_STAGE=load "${erc20_driver[@]}" &
    load_pid=$!
    NB2_RESUME_STAGE=settle run_driver "${erc20_driver[@]}"
    wait "$load_pid"
    load_pid=
  else
    NB2_RESUME_STAGE=load run_driver "${erc20_driver[@]}"
    NB2_RESUME_STAGE=settle run_driver "${erc20_driver[@]}"
  fi
done
