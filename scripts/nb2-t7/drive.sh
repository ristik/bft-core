#!/usr/bin/env bash
set -euo pipefail
rpc=$1 agg=$2 chain=$3 history=$4
here=$PWD/scripts/nb2-t7
scratch=$(mktemp -d "$NB2_OUT/.driver.XXXXXX")
driver_pid=
cleanup() {
  if [[ -n "$driver_pid" ]]; then kill -TERM "$driver_pid" 2>/dev/null || true; wait "$driver_pid" || true; fi
  rm -rf -- "$scratch"
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
cp "$here/driver.ts" "$scratch/"
sed -n 's/^const testKeyHex = "\([0-9a-f]*\)"$/\1/p' scripts/evmtx/main.go >"$scratch/send-key"
test -s "$scratch/send-key"
ln -s "$NB2_PLUGIN/packages/native-bridge-plugin/lib" "$scratch/sdk"
cp test-nodes/utb-genesis.id "$NB2_OUT/trust.pin"
cp test-nodes/execution-genesis-hash "$NB2_OUT/execution.pin"
cp test-nodes/utb/utb-manifest.json "$NB2_OUT/utb-manifest.json"
"$UTB_VERIFIER" fetch --url "$history" --out "$NB2_OUT/trust.cbor"
"$UTB_VERIFIER" verify --bundle "$NB2_OUT/trust.cbor" --pin "$(cat "$NB2_OUT/trust.pin")"
cp -R testvectors/nb2-continuation-v1.1-supplement/descriptors "$NB2_OUT/"
jq -n --arg commit "$(jq -r .ureth "$NB2_OUT/pins.json")" --arg digest "$(sha256sum "$URETH_BIN" | cut -d' ' -f1)" \
  '{ureth:$commit,binaries:{"unicity-reth":$digest}}' >"$NB2_OUT/descriptors/build-index.json"
{
  git rev-parse HEAD
  sha256sum build/ubft "$UTB_VERIFIER" "$AGG_BIN" "$URETH_BIN" "$NB2_PLUGIN/package-lock.json"
  go version -m "$AGG_BIN"
} >"$NB2_OUT/builds.txt"
run_driver "$NB2_PLUGIN/node_modules/.bin/tsx" "$scratch/driver.ts" "$NB2_OUT" "$rpc" "$agg" "$chain" \
  "${NB2_ARTIFACTS:-$NB2_CONTRACTS/out}" "$here/create.py" "$scratch"

if [[ -n "${NB2_SCENARIO_DRIVER:-}" ]]; then
  rm -rf -- "$scratch"
  run_driver "$NB2_SCENARIO_DRIVER" "$NB2_OUT" "$rpc" "$agg"
fi
