#!/usr/bin/env bash
# Builds the Go side of the lane from the checkout under test and the aggregator from its pin, runs the lane's chain-free self-tests, and writes compact artifacts:
#   OUT/ubft                       build/ubft (VCS stamped for HEAD)
#   OUT/tools/<name>               dnb-tool, utb-evidence, evmtx, h3slots, h3-pdr, h4-restore-pin, m2slots, f7-mintproof-*, buildinfo
#   OUT/aggregator-<sha8>/         the aggregator and its provenance (commit.txt, gomod-pins.txt, sha256.txt, toolchain.txt)
#   OUT/selftest/                  the lane's and the pin checker's self-test logs, the first stamped with the commit they ran for
#   OUT/commit-under-test.txt, OUT/sha256.txt
# Run from the repository root. Needs Go (the pinned version), make, git, jq, python3, a C compiler.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/../.." && pwd); cd "$repo"
out=${1:?usage: build-tools.sh OUT_DIR}; mkdir -p "$out/tools" "$out/selftest"
head=$(git rev-parse HEAD); echo "$head" >"$out/commit-under-test.txt"
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "build-tools: the checkout is not clean" >&2; exit 1; }
want=$(jq -r .toolchains.go scripts/ci/lane-pins.json); have=$(go env GOVERSION)
[ "go$want" = "$have" ] || { echo "build-tools: go is $have, the manifest pins go$want" >&2; exit 1; }
{ go version; } >"$out/go-version.txt"

make build >/dev/null
cp build/ubft "$out/ubft"
for t in dnb-tool utb-evidence evmtx h3slots h3-pdr h4-restore-pin m2slots f7-mintproof-extract f7-mintproof-verify s4-equivocate; do go build -trimpath=false -o "$out/tools/$t" "./scripts/$t"; done
go build -o "$out/tools/buildinfo" ./scripts/ci/buildinfo
for b in "$out/ubft" "$out/tools/utb-evidence" "$out/tools/dnb-tool"; do
  "$out/tools/buildinfo" "$b" | grep -q "vcs.revision=$head" && ! "$out/tools/buildinfo" "$b" | grep -q 'vcs.modified=true' || { echo "build-tools: $b is not stamped for a clean $head" >&2; exit 1; }
done

# the aggregator from its pin (utb_agg_build: clean clone, VCS stamped, provenance directory; refuses a commit off integration/enshrined-evm)
export AGRE_ROOT=${AGRE_ROOT:-$(cd "$repo/.." && pwd)}
AGG_COMMIT=$(jq -er '.components["aggregator-go"].commit' scripts/ci/lane-pins.json); export AGG_COMMIT
scripts/utb-lane.sh --build-aggregator
cp -R "$AGRE_ROOT/builds/aggregator-${AGG_COMMIT:0:8}" "$out/"

# the self-tests that compile Go test binaries run here; the run job checks their recorded result
tb=$(mktemp -d); for i in 1 2 3; do build/ubft root-node init --home "$tb/root$i" -g >/dev/null; done
build/ubft trust-base generate --home "$tb" --epoch 1 --epoch-start 1 --network-id 3 --node-info "$tb/root1/node-info.json" --node-info "$tb/root2/node-info.json" --node-info "$tb/root3/node-info.json" >/dev/null
{ UBFT="$repo/build/ubft" UTB_ST_TRUSTBASE="$tb/trust-base.json" scripts/utb-lane.sh --selftest; printf 'commit %s\n' "$head"; } 2>&1 | tee "$out/selftest/utb-lane-selftest.log"
grep -q '^utb lane self-test: 0 failures' "$out/selftest/utb-lane-selftest.log" || { echo "build-tools: the lane self-test failed" >&2; exit 1; }
scripts/ci/check-pins.sh selftest 2>&1 | tee "$out/selftest/check-pins-selftest.log"
scripts/ci/check-pins.sh selftest >/dev/null 2>&1 || { echo "build-tools: the pin checker self-test failed" >&2; exit 1; }
# the evidence publisher with planted canaries (a secret file and a leaked secret value must not reach the upload set)
scripts/ci/publish-selftest.sh 2>&1 | tee "$out/selftest/publish-selftest.log"
grep -q '^publish-evidence self-test: .* 0 failures' "$out/selftest/publish-selftest.log" || { echo "build-tools: the publisher self-test failed" >&2; exit 1; }
( cd "$out" && find . -type f ! -name sha256.txt | LC_ALL=C sort | xargs sha256sum >sha256.txt )
