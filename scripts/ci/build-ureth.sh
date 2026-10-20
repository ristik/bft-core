#!/usr/bin/env bash
# Builds unicity-reth from the pin in scripts/ci/lane-pins.json (clean checkout of the exact commit, locked release build) and writes the provenance next to it.
#   scripts/ci/build-ureth.sh OUT_DIR [WORK_DIR]
# OUT_DIR gets: unicity-reth, commit.txt, sha256.txt, toolchain.txt, build-command.txt, cargo-lock.sha256, git-status.txt, build-times.txt, run-identity.txt.
# Linux x86_64 CI only builds: the digest of this binary is its own (the Mac attestation of the same commit is another artifact).
set -euo pipefail
out=${1:?usage: build-ureth.sh OUT_DIR [WORK_DIR]}; work=${2:-${RUNNER_TEMP:-/tmp}/ureth-build}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pins=$here/lane-pins.json
repo=$(jq -r .components.ureth.repository "$pins"); commit=$(jq -r .components.ureth.commit "$pins"); rust=$(jq -r .toolchains.rust "$pins")
mapfile -t cargoargs < <(jq -r '.components.ureth.cargoArgs[]' "$pins")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "build-ureth: the pinned commit is not 40 hex: $commit" >&2; exit 2; }
mkdir -p "$out" "$work"; rm -rf "$work/src"; mkdir -p "$work/src"
src=$work/src
git -C "$src" init -q
git -C "$src" fetch -q --depth 1 "$repo" "$commit"
git -C "$src" checkout -q --detach FETCH_HEAD
[ "$(git -C "$src" rev-parse HEAD)" = "$commit" ] || { echo "build-ureth: the checkout is not the pinned commit" >&2; exit 1; }
[ -z "$(git -C "$src" status --porcelain)" ] || { echo "build-ureth: the checkout is not clean" >&2; exit 1; }
rustup toolchain install "$rust" --profile minimal --no-self-update >/dev/null
t0=$(date -u +%FT%TZ); s0=$SECONDS
export CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
( cd "$src" && cargo "+$rust" "${cargoargs[@]}" --target-dir "$work/target" ) 2>&1 | tee "$work/cargo-build.log" | tail -n 5
bin=$work/target/release/unicity-reth
[ -x "$bin" ] || { echo "build-ureth: no $bin" >&2; exit 1; }
t1=$(date -u +%FT%TZ)
cp "$bin" "$out/unicity-reth"
( cd "$out" && sha256sum unicity-reth >sha256.txt )
printf '%s\n' "$commit" >"$out/commit.txt"
{ rustc "+$rust" -Vv; cargo "+$rust" -V; } >"$out/toolchain.txt"
printf 'cargo +%s %s --target-dir <work>/target\nCARGO_INCREMENTAL=0\nprofile.release from the workspace Cargo.toml at the pin (opt-level 3, thin LTO, strip symbols)\n' "$rust" "${cargoargs[*]}" >"$out/build-command.txt"
sha256sum "$src/Cargo.lock" | cut -d' ' -f1 >"$out/cargo-lock.sha256"
git -C "$src" status --short >"$out/git-status.txt"
printf 'start %s\nend %s\nelapsed_s %d\n' "$t0" "$t1" $((SECONDS - s0)) >"$out/build-times.txt"
printf 'repository %s\nrun_id %s\nrun_attempt %s\nworkflow_sha %s\nrunner_os %s\nrunner_arch %s\nimage %s\n' "${GITHUB_REPOSITORY:-local}" "${GITHUB_RUN_ID:-local}" "${GITHUB_RUN_ATTEMPT:-0}" "${GITHUB_SHA:-local}" "${RUNNER_OS:-$(uname -s)}" "${RUNNER_ARCH:-$(uname -m)}" "${ImageVersion:-unknown}" >"$out/run-identity.txt"
"$out/unicity-reth" --version >"$out/version.txt" 2>&1 || true
grep -q "$commit" "$out/version.txt" || { echo "build-ureth: the binary does not report the pinned commit" >&2; cat "$out/version.txt" >&2; exit 1; }
cat "$out/sha256.txt"
