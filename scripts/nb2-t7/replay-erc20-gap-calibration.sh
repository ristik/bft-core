#!/usr/bin/env bash
set -euo pipefail
umask 077
old=${1:?#1038 workspace}
prior=${2:?pinned native settlement evidence}
out=${3:?new output directory}
sdk=${4:?absolute path to the built release SDK}
[[ "$old" = /* && "$prior" = /* && "$out" = /* && "$sdk" = /* ]]
mkdir "$out"
base=$(mktemp -d "$(dirname "$out")/gap-calibration.XXXXXX")
test_source=$(mktemp --suffix=.rs "$old/native-ureth/crates/unicity/execution/tests/nb2_erc20_1349_XXXXXX")
test_name=$(basename "$test_source" .rs)
trap 'rc=$?; rm -f -- "$test_source"; printf "%s\n" "$rc" >"$out.exit"; exit "$rc"' EXIT
export LC_ALL=C.UTF-8 PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.14.linux-amd64/bin:$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
export GOTOOLCHAIN=local GOFLAGS=-p=4 CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$old/native-target"
cp -a "$prior/"{descriptors,deployment.json,root-pin.bin,execution-genesis.bin,gamma.bin,generation-salt.bin} "$out/"
git -C "$base" clone --quiet --shared "$old/calibration" "$base/oracle"
git -C "$old/calibration" diff --binary | git -C "$base/oracle" apply -
cp "$old/calibration/nb2ref/erc20_vectors_test.go" "$base/oracle/nb2ref/"
python3 - "$base/oracle/nb2ref/flat_settlement_test.go" "$old/nb2_erc20_all_calls.rs" "$test_source" <<'PY'
from pathlib import Path
import sys

oracle, replay, test_source = map(Path, sys.argv[1:])
go_prefix, go = oracle.read_text().split('func TestFlatConcentratedSettlementQualification(', 1)
assert go.count('[]int{64, 1024}') == 1
go = go.replace('[]int{64, 1024}', '[]int{0, 1, 2, 3}', 1)
go = go.replace('a+1026, true)', 'a+5, true)', 1)
go = go.replace('StartHead: &history.heads[a], Proofs: history.proofs(a, count)}', '''Proofs: history.proofs(a, count)}
        if count != 0 {
            packet.StartHead = &history.heads[a]
        }''', 1)
go = go.replace('        advance, err := packet.Calldata(FlatAdvanceGaps, v.cfg.K)', '''
        if count == 0 {
            continue
        }
        advance, err := packet.Calldata(FlatAdvanceGaps, v.cfg.K)''', 1)
assert 'if count == 0 {\n            continue' in go and 'packet.StartHead = &history.heads[a]' in go
oracle.write_text(go_prefix + 'func TestFlatConcentratedSettlementQualification(' + go)

rust = replay.read_text()
assert rust.count('for count in [64, 1024]') == 1
rust = rust.replace('for count in [64, 1024]', 'for count in [0, 1, 2, 3]')
begin = rust.index('        let advance = raw(case.join("advance-calldata.bin"));')
end = rust.index('        let data = raw(case.join("calldata.bin"));', begin)
rust = rust[:begin] + '        if count > 0 {\n' + rust[begin:end] + '        }\n' + rust[end:]
rust = rust.replace('        let history = Bytes::from(raw(case.join("ordinary-history.bin")));', '''
        let history = if count == 0 { Bytes::new() } else { Bytes::from(raw(case.join("ordinary-history.bin"))) };''')
rust = rust.replace('        let ordinary_receipt = measure(', '''
        fs::write(case.join("ordinary-calldata.bin"), &ordinary).unwrap();
        let ordinary_receipt = measure(''')
test_source.write_text(rust)
PY
git -C "$base/oracle" diff -- nb2ref >"$out/oracle-overlay.patch"
cp "$test_source" "$out/replay.rs"
export NB2_CALIBRATION_ERC20=1 NB2_FLAT_VECTOR_OUT="$out" NB2_FLAT_QUALIFICATION_GRAPH="$out"
cd "$base/oracle"
go test -count=1 -v ./nb2ref -run '^TestFlatConcentratedSettlementQualification$' >"$out/oracle.log" 2>&1
export NB2_FLAT_FORGE_OUT="$old/contracts/out" NB2_FLAT_BFT="$old/calibration"
export NB2_FLAT_SUPPLEMENT="$out" NB2_TOKEN_OUT="$old/token-build/out"
cargo test --manifest-path "$old/native-ureth/Cargo.toml" --locked --release -p reth-unicity-execution \
  --test "$test_name" erc20_combined_resource_on_pinned_graph -- --nocapture >"$out/replay.log" 2>&1
node --input-type=module - "$out" "$sdk" <<'JS'
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , out, sdk] = process.argv;
const { signTx, LocalKeySigner } = await import(pathToFileURL(join(sdk, 'nb2/evm.js')));
const graph = JSON.parse(readFileSync(join(out, 'deployment.json'), 'utf8'));
const rows = [];
const key = new Uint8Array(32);
key[31] = 1;
const signer = new LocalKeySigner(key);
const log = readFileSync(join(out, 'replay.log'), 'utf8');
for (const [label, name, count, target, file] of [
  ...[1, 2, 3].map(count => ['advance-' + count, 'AdvanceGaps', count, graph.RecoveryAddress, 'advance-calldata']),
  ...[0, 1, 2].flatMap(count => [
    ['qualification-settle-seal-concentrated-' + count, 'recovered settlement', count, graph.VaultAddress, 'calldata'],
    ['ordinary-seal-concentrated-' + count, 'ordinary settlement', count, graph.VaultAddress, 'ordinary-calldata'],
  ]),
]) {
  const fields = log.match(new RegExp('^' + label + ' calldata=(\\d+) gas=(\\d+) .* min_bid=(\\d+) intrinsic=(\\d+) quote=(\\d+)$', 'm'));
  assert(fields, label);
  const [, calldataBytes, gasUsed, minimumBid, intrinsicGas, conservativeQuote] = fields.map(Number);
  const prefix = join(out, 'cold', 'qualification-settle-seal-concentrated-' + count, file);
  const data = readFileSync(prefix + '.bin');
  assert.equal(calldataBytes, data.length);
  const gas = 24_000_000;
  const tx = await signTx(signer, {
    chainId: 31337n, nonce: (1n << 64n) - 1n, gas: BigInt(gas), to: Buffer.from(target, 'hex'),
    value: 0n, maxFeePerGas: (1n << 256n) - 1n, maxPriorityFeePerGas: (1n << 256n) - 1n, data,
  });
  assert(calldataBytes <= 393_216 && tx.raw.length <= 524_288 && conservativeQuote <= gas, label);
  writeFileSync(prefix + '.signed', tx.raw);
  const predecessorBytes = name === 'ordinary settlement' ? undefined : data.readUInt32BE(111);
  rows.push({ name, gaps: count, predecessorBytes, calldataBytes, signedBytes: tx.raw.length, gasLimit: gas,
    gasUsed, minimumBid, intrinsicGas, conservativeQuote });
}
writeFileSync(join(out, 'measurement.json'), JSON.stringify({
  scope: 'Synthetic authority and seeded concentrated custody; signed envelopes were not broadcast', calls: rows,
}, null, 2) + '\n');
JS
