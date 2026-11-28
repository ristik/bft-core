#!/usr/bin/env bash
set -euo pipefail
umask 077
# Arguments identify the #1038 workspace, its native-width evidence, and a new output path.
old=${1:?#1038 workspace}
prior=${2:?original native-width evidence}
out=${3:?new output directory}
[[ "$old" = /* && "$prior" = /* && "$out" = /* ]]
base=$(mktemp -d "$(dirname "$out")/recut.XXXXXX")
trap 'rc=$?; printf "%s\n" "$rc" >"$out.exit"; exit "$rc"' EXIT
export LC_ALL=C.UTF-8 PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.14.linux-amd64/bin:$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
export GOTOOLCHAIN=local GOFLAGS=-p=4 CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$old/native-target"
mkdir "$out"
cp -a "$prior/"{descriptors,deployment.json,root-pin.bin,execution-genesis.bin,gamma.bin,generation-salt.bin} "$out/"
git -C "$base" clone --quiet --shared "$old/width" "$base/width"
git -C "$old/width" diff --binary | git -C "$base/width" apply -
cp "$old/width/nb2ref/erc20_vectors_test.go" "$base/width/nb2ref/"
python3 - "$base/width/nb2ref/flat_qualification_test.go" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
old = '{{"-sparse", 16, false}}'
assert old in s, 'the #1038 width overlay is required'
s = s.replace(old, '{{"-sparse", 16, false}, {"-sparse-split", 8, false}}')
s = s.replace('require.Greater(t, len(calldata), 385_000)', 'require.Equal(t, 393_188, len(calldata))')
p.write_text(s)
PY
cd "$base/width"
git -C "$base/width" diff -- nb2ref >"$out/oracle-overlay.patch"
NB2_CALIBRATION_ERC20=1 NB2_WIDTH_LAST=82 NB2_WIDTH_FILLER=96 NB2_FLAT_VECTOR_OUT="$out" NB2_FLAT_QUALIFICATION_GRAPH="$out" \
  go test -count=1 -v ./nb2ref -run '^TestFlatJointNativeQualification$' >"$out/oracle.log" 2>&1
for file in "$out"/packed-joint-native-qualification*/trace.bin.gz; do gzip -cd "$file" >"${file%.gz}"; done
before="$prior/packed-joint-native-qualification-sparse"
after="$out/packed-joint-native-qualification-sparse"
for file in evidence.bin trace.bin verdict.bin; do cmp "$before/$file" "$after/$file"; done
cmp "$after/verdict.bin" "$out/packed-joint-native-qualification-sparse-split/verdict.bin"
printf 'Exact unsplit evidence, trace and verdict match the prior artifact byte for byte. Split verdict matches.\n'
export NB2_FLAT_FORGE_OUT="$old/contracts/out" NB2_FLAT_BFT="$old/calibration"
export NB2_FLAT_SUPPLEMENT="$out" NB2_TOKEN_OUT="$old/token-build/out"
cargo test --manifest-path "$old/native-ureth/Cargo.toml" --locked --release -p reth-unicity-execution --test nb2_erc20_settle erc20_combined_resource_on_pinned_graph -- --nocapture >"$out/replay.log" 2>&1
node "$old/sign-candidates.mjs" "$out" "$old/plugin/packages/native-bridge-plugin/lib" "$out/signed-packets.json"
cmp "$before/packet-0.signed" "$after/packet-0.signed"
python3 - "$out" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
split = 'packed-joint-native-qualification-sparse-split'
quotes = re.findall(rf'{split} packet=(\d+) bytes=(\d+) .* quote=(\d+)', (root / 'replay.log').read_text())
assert len(quotes) == 2 and all(int(gas) <= 24_000_000 for _, _, gas in quotes), quotes
packets = json.loads((root / 'signed-packets.json').read_text())['packets']
signed = {row['index']: row for row in packets if row['name'] == split}
assert len(signed) == 2
for index, calldata, _ in quotes:
    item = signed[int(index)]
    assert item['calldataBytes'] == int(calldata) <= 393_216
    assert item['signedBytes'] <= 524_288
print('Both split quotes and signed envelopes fit the ERC20 admission limits.')
PY
