#!/usr/bin/env bash
# Clean checkouts of the pinned companion repositories (scripts/ci/lane-pins.json), built for the run job, as compact tar.zst artifacts:
#   contracts  checkout + submodules, forge build output (out/, cache/) and the solc binaries it used (svm/) so the run job compiles nothing it does not have to
#   nbp        checkout + `npm ci` (the vendored SDK tarball of its package.json), no dev tooling beyond what tests/live runs
#   sdkjs      checkout + `npm ci && npm run build`, then production dependencies only
# Each archive holds a git checkout at exactly the pinned commit (scripts/ci/check-pins.sh git verifies it in the run job).
#   scripts/ci/prepare-sources.sh OUT_DIR [WORK_DIR]       needs git, jq, forge (Foundry on PATH), node/npm, zstd
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); pins=$here/lane-pins.json
out=${1:?usage: prepare-sources.sh OUT_DIR [WORK_DIR]}; work=${2:-${RUNNER_TEMP:-/tmp}/sources}
mkdir -p "$out" "$work"

checkout() { # NAME DIR
  local name=$1 dir=$2 repo commit
  repo=$(jq -er --arg n "$name" '.components[$n].repository' "$pins"); commit=$(jq -er --arg n "$name" '.components[$n].commit' "$pins")
  rm -rf "$dir"; mkdir -p "$dir"
  git -C "$dir" init -q; git -C "$dir" fetch -q --depth 1 "$repo" "$commit"; git -C "$dir" checkout -q --detach FETCH_HEAD
  git -C "$dir" remote add origin "$repo"
  "$here/check-pins.sh" git "$name" "$dir"
}
pack() { # NAME DIR  -> OUT/NAME.tar.zst + .sha256
  ( cd "$(dirname "$2")" && tar -cf - "$(basename "$2")" | zstd -q -T0 -3 -o "$out/$1.tar.zst" )
  ( cd "$out" && sha256sum "$1.tar.zst" >"$1.tar.zst.sha256" )
  ls -l "$out/$1.tar.zst" | awk '{printf "%s %.1f MiB\n", $NF, $5/1048576}'
}

# contracts
c=$work/contracts
checkout contracts "$c"
git -C "$c" submodule update --init --depth 1 --recursive -q
( cd "$c" && forge build -q ) 
# solc binaries foundry fetched for the build (the run job's forge finds them here)
mkdir -p "$c/.ci-svm"; for d in "$HOME/.svm" "$HOME/.local/share/svm" ; do [ -d "$d" ] && cp -R "$d/." "$c/.ci-svm/" 2>/dev/null || true; done
pack contracts "$c"

# native-bridge-plugins
n=$work/native-bridge-plugins
checkout native-bridge-plugins "$n"
( cd "$n" && npm ci --no-audit --no-fund --silent )
pack native-bridge-plugins "$n"

# state-transition-sdk-js
s=$work/state-transition-sdk-js
checkout state-transition-sdk-js "$s"
( cd "$s" && npm ci --no-audit --no-fund --silent && npm run build --silent && npm prune --omit=dev --silent )
[ -f "$s/lib/util/TrustBaseUtils.js" ] || { echo "prepare-sources: the SDK build has no lib/util/TrustBaseUtils.js" >&2; exit 1; }
pack state-transition-sdk-js "$s"
