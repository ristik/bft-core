#!/usr/bin/env bash
set -euo pipefail
rpc=$1 agg=$2 chain=$3 history=$4
export NB2_HISTORY_URL="$history"
here=$PWD/scripts/nb2-t7
scratch=$(mktemp -d "$NB2_OUT/.driver.XXXXXX")
driver_pid=
archive_pid=
load_pid=
cleanup() {
  trap '' TERM HUP INT
  if [[ -n "$driver_pid" ]]; then kill -TERM "$driver_pid" 2>/dev/null || true; wait "$driver_pid" || true; fi
  if [[ -n "$load_pid" ]]; then kill -TERM "$load_pid" 2>/dev/null || true; wait "$load_pid" || true; fi
  stop_archive
  rm -rf -- "$scratch"
}
stop_archive() {
  if [[ -n "$archive_pid" ]]; then
    kill -TERM "$archive_pid" 2>/dev/null || true
    wait "$archive_pid" || true
    archive_pid=
  fi
}
trap cleanup EXIT
trap 'exit 143' HUP INT TERM
run_driver() {
  "$@" &
  driver_pid=$!
  local rc=0
  wait "$driver_pid" || rc=$?
  driver_pid=
  return "$rc"
}
umask 077
# The paired lane funds this well-known development account in its disposable genesis.
printf '%s\n' 'test test test test test test test test test test test junk' >"$scratch/mnemonic"
openssl rand -hex 24 >"$scratch/password"
CAST_UNSAFE_PASSWORD=$(<"$scratch/password") cast wallet import sender --keystore-dir "$scratch" --mnemonic "$scratch/mnemonic" >/dev/null
printf '%s\n' '{"type":"module"}' >"$scratch/package.json"
cp "$here/driver.ts" "$here/receipt.ts" "$scratch/"
sed -n 's/^const testKeyHex = "\([0-9a-f]*\)"$/\1/p' scripts/evmtx/main.go >"$scratch/send-key"
test -s "$scratch/send-key"
ln -s "$NB2_PLUGIN/packages/native-bridge-plugin/lib" "$scratch/sdk"
ln -s "$NB2_PLUGIN/wallet" "$scratch/wallet"
cp test-nodes/utb-genesis.id "$NB2_OUT/trust.pin"
cp test-nodes/execution-genesis-hash "$NB2_OUT/execution.pin"
cp test-nodes/utb/utb-manifest.json "$NB2_OUT/utb-manifest.json"
"$UTB_VERIFIER" fetch --url "$history" --out "$NB2_OUT/trust.cbor"
"$UTB_VERIFIER" verify --bundle "$NB2_OUT/trust.cbor" --pin "$(cat "$NB2_OUT/trust.pin")"
python3 "$here/descriptors.py" "$PWD" "$NB2_URETH_SOURCE" "$NB2_PLUGIN" "$URETH_BIN" \
  "$NB2_OUT/descriptors" "$NB2_OUT/plugin-lib.sha256"
{
  git -C "$PWD" rev-parse HEAD
  sha256sum build/ubft "$UTB_VERIFIER" "$AGG_BIN" "$URETH_BIN" "$NB2_PLUGIN/package-lock.json" "$NB2_OUT/plugin-lib.sha256"
  go version -m "$AGG_BIN"
} >"$NB2_OUT/builds.txt"
driver=( "$NB2_PLUGIN/node_modules/.bin/tsx" "$scratch/driver.ts" "$NB2_OUT" "$rpc" "$agg" "$chain"
  "${NB2_ARTIFACTS:-$NB2_CONTRACTS/out}" "$here/create.py" "$scratch" )
if [[ "${NB2_QUALIFY_ERC20:-0}" = 1 ]]; then
  NB2_SCENARIO_DRIVER= NB2_QUALIFY_OFFLINE=0 NB2_QUALIFY_COSTS=0 NB2_QUALIFY_CUSTODY=0 \
    NB2_ROUTE=both NB2_SPLIT_DEPTH=1 run_driver "${driver[@]}"
elif [[ "${NB2_QUALIFY_OFFLINE:-0}" = 1 ]]; then
  openssl rand -hex 32 >"$scratch/relayer-key"
  openssl rand -hex 32 >"$scratch/load-key"
  python3 "$here/probe-qualification.py" archive "$rpc" "$chain" "$(cat "$NB2_OUT/execution.pin")" \
    "$scratch/archive-url" >"$NB2_OUT/preferred-archive.log" 2>&1 &
  archive_pid=$!
  for ((i = 0; i < 50; ++i)); do [[ -s "$scratch/archive-url" ]] && break; sleep .1; done
  export NB2_RECEIPT_PRIMARY_RPC="$(<"$scratch/archive-url")"
  export NB2_RECEIPT_ALT_RPC="http://127.0.0.1:$(("${rpc##*:}" + 1))"
  NB2_QUALIFY_COSTS=1 run_driver "${driver[@]}"
  [[ -s "$scratch/offline-burn.private.json" ]]
  NB2_RESUME_STAGE=checkpoint run_driver "${driver[@]}"
  stop_archive
  if [[ "${NB2_OFFLINE_EXTERNAL:-0}" = 1 ]]; then
    # The run directory is private. Keep this pointer out of the evidence index.
    printf '%s\n' "$scratch" >"$NB2_OUT/.offline-handoff"
    if [[ "${NB2_OFFLINE_PEAK:-0}" = 1 ]]; then
      NB2_RESUME_STAGE=load "${driver[@]}" &
      load_pid=$!
    else
      NB2_RESUME_STAGE=load run_driver "${driver[@]}"
    fi
    for ((i = 0; i < 900; ++i)); do
      [[ ! -e "$NB2_OUT/.offline-handoff" ]] && break
      if [[ -n "$load_pid" ]] && ! kill -0 "$load_pid" 2>/dev/null; then
        wait "$load_pid"
        load_pid=
      fi
      sleep 1
    done
    [[ ! -e "$NB2_OUT/.offline-handoff" ]]
    [[ -s "$NB2_OUT/$NB2_QUALIFY_CASE/offline-result.json" ]]
    if [[ -n "$load_pid" ]]; then wait "$load_pid"; load_pid=; fi
  elif [[ "${NB2_OFFLINE_PEAK:-0}" = 1 ]]; then
    NB2_RESUME_STAGE=load "${driver[@]}" &
    load_pid=$!
    NB2_RESUME_STAGE=settle run_driver "${driver[@]}"
    wait "$load_pid"
    load_pid=
  else
    NB2_RESUME_STAGE=load run_driver "${driver[@]}"
    NB2_RESUME_STAGE=settle run_driver "${driver[@]}"
  fi
else
  run_driver "${driver[@]}"
fi

if [[ -e "$NB2_OUT/FlatReceipts.receipt.json" ]]; then
  python3 "$here/probe-qualification.py" "$NB2_OUT" "$PWD" FlatReceipts.receipt.json
fi

if [[ "${NB2_QUALIFY_ERC20:-0}" = 1 ]]; then
  source "$here/erc20-drive.sh"
fi

if [[ -n "${NB2_SCENARIO_DRIVER:-}" ]]; then
  rm -rf -- "$scratch"
  run_driver "$NB2_SCENARIO_DRIVER" "$NB2_OUT" "$rpc" "$agg"
fi
