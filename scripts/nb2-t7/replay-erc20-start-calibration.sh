#!/usr/bin/env bash
set -euo pipefail
umask 077
old=${1:?#1038 workspace}
prior=${2:?pinned native width evidence}
out=${3:?new output directory}
[[ "$old" = /* && "$prior" = /* && "$out" = /* ]]
mkdir "$out"
base=$(mktemp -d "$(dirname "$out")/start-calibration.XXXXXX")
trap 'rc=$?; printf "%s\n" "$rc" >"$out.exit"; exit "$rc"' EXIT
export LC_ALL=C.UTF-8 PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.14.linux-amd64/bin:$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
export GOTOOLCHAIN=local GOFLAGS=-p=4 CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$old/native-target"
cp -a "$prior/"{descriptors,deployment.json,root-pin.bin,execution-genesis.bin,gamma.bin,generation-salt.bin} "$out/"
git -C "$base" clone --quiet --shared "$old/width" "$base/oracle"
git -C "$old/width" diff --binary | git -C "$base/oracle" apply -
cp "$old/width/nb2ref/erc20_vectors_test.go" "$base/oracle/nb2ref/"
python3 - "$base/oracle/nb2ref" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
run = source / 'flat_qualification_test.go'
s = run.read_text()
old = 'resumePages: 32, denseSparse: true'
assert s.count(old) == 1
s = s.replace(old, 'resumePages: 0, denseSparse: false')
old = 'for i := range 7 {\n\t\t\t\tflatFixtureExpandRSMT(t, w, &child.Proofs[i], 256)\n\t\t\t}'
assert s.count(old) == 1
s = s.replace(old, 'flatFixtureExpandRSMT(t, w, &child.Proofs[0], 128)')
run.write_text(s)
vectors = source / 'flat_native_vectors_test.go'
prefix, s = vectors.read_text().split('func flatLargeCombinedWitnesses(', 1)
old = 'records[:2], records[2:]'
assert s.count(old) == 1
s = s.replace(old, 'records[:16], records[16:]')
s = s.replace('p := scratch.packet(t, prior, receipt, cut)', '''p := scratch.packet(t, prior, receipt, cut)
        if prior == nil {
            require.Len(t, p.Operations, 16)
            t.Logf("Start at 16 operations uses %d pages", len(p.Pages))
            require.Len(t, p.Pages, 32)
        }''', 1)
vectors.write_text(prefix + 'func flatLargeCombinedWitnesses(' + s)
PY
git -C "$base/oracle" diff -- nb2ref >"$out/oracle-overlay.patch"
export NB2_CALIBRATION_ERC20=1 NB2_WIDTH_LAST=82 NB2_WIDTH_FILLER=96
export NB2_FLAT_VECTOR_OUT="$out" NB2_FLAT_QUALIFICATION_GRAPH="$out"
cd "$base/oracle"
go test -count=1 -v ./nb2ref -run '^TestFlatJointNativeQualification$' >"$out/oracle.log" 2>&1
for file in "$out"/packed-joint-native-qualification*/trace.bin.gz; do gzip -cd "$file" >"${file%.gz}"; done
node "$old/sign-candidates.mjs" "$out" "$old/plugin/packages/native-bridge-plugin/lib" "$out/signed-packets.json"
export NB2_FLAT_FORGE_OUT="$old/contracts/out" NB2_FLAT_BFT="$old/calibration"
export NB2_FLAT_SUPPLEMENT="$out" NB2_TOKEN_OUT="$old/token-build/out"
cargo test --manifest-path "$old/native-ureth/Cargo.toml" --locked --release -p reth-unicity-execution \
  --test nb2_erc20_settle erc20_combined_resource_on_pinned_graph -- --nocapture >"$out/replay.log" 2>&1
