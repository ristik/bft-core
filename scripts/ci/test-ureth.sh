#!/usr/bin/env bash
# The targeted ureth tests of the pin in scripts/ci/lane-pins.json: the Unicity crates' own tests (components.ureth.targetedPackages), NOT cargo test --workspace and no generic
# Ethereum suites. A clean checkout of the exact pinned commit, locked, then `cargo test -p <each package> --no-fail-fast`.
#   scripts/ci/test-ureth.sh OUT_DIR [WORK_DIR]
# OUT_DIR gets: cargo-test.log, summary.txt (passed / failed / ignored per test binary and in total), test-times.txt, toolchain.txt, commit.txt. Exit status: cargo's; also non-zero when no test ran
# (an empty selection is not a pass).
set -uo pipefail
out=${1:?usage: test-ureth.sh OUT_DIR [WORK_DIR]}; work=${2:-${RUNNER_TEMP:-/tmp}/ureth-test}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); pins=$here/lane-pins.json
repo=$(jq -r .components.ureth.repository "$pins"); commit=$(jq -r .components.ureth.commit "$pins"); rust=$(jq -r .toolchains.rust "$pins")
mapfile -t pkgs < <(jq -r '.components.ureth.targetedPackages[]' "$pins")
[ "${#pkgs[@]}" -gt 0 ] || { echo "test-ureth: no targeted packages in the manifest" >&2; exit 2; }
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "test-ureth: the pinned commit is not 40 hex: $commit" >&2; exit 2; }
mkdir -p "$out" "$work"; rm -rf "$work/src"; mkdir -p "$work/src"; src=$work/src
git -C "$src" init -q && git -C "$src" fetch -q --depth 1 "$repo" "$commit" && git -C "$src" checkout -q --detach FETCH_HEAD || { echo "test-ureth: cannot fetch the pin" >&2; exit 1; }
[ "$(git -C "$src" rev-parse HEAD)" = "$commit" ] || { echo "test-ureth: the checkout is not the pinned commit" >&2; exit 1; }
rustup toolchain install "$rust" --profile minimal --no-self-update >/dev/null || exit 1
printf '%s\n' "$commit" >"$out/commit.txt"; { rustc "+$rust" -Vv; cargo "+$rust" -V; } >"$out/toolchain.txt"
sel=(); for p in "${pkgs[@]}"; do sel+=(-p "$p"); done
export CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never RUST_BACKTRACE=1
t0=$(date -u +%FT%TZ); s0=$SECONDS
( cd "$src" && cargo "+$rust" test --locked "${sel[@]}" --no-fail-fast --target-dir "$work/target" ) >"$out/cargo-test.log" 2>&1; rc=$?
s1=$SECONDS
tail -n 25 "$out/cargo-test.log"
# per test binary: "Running <path>" then "test result: ok. N passed; M failed; K ignored"
awk '/^ +Running /{bin=$2} /^test result:/{print bin "\t" $0}' "$out/cargo-test.log" >"$out/results.tsv"
passed=$(awk -F'[ ;]+' '/test result:/{for(i=1;i<=NF;i++) if($i=="passed")s+=$(i-1)} END{print s+0}' "$out/cargo-test.log")
failed=$(awk -F'[ ;]+' '/test result:/{for(i=1;i<=NF;i++) if($i=="failed")s+=$(i-1)} END{print s+0}' "$out/cargo-test.log")
ignored=$(awk -F'[ ;]+' '/test result:/{for(i=1;i<=NF;i++) if($i=="ignored")s+=$(i-1)} END{print s+0}' "$out/cargo-test.log")
{ echo "packages: ${pkgs[*]}"; echo "commit: $commit"; echo "cargo exit: $rc"; echo "tests passed: $passed  failed: $failed  ignored: $ignored"; echo; cat "$out/results.tsv"; } >"$out/summary.txt"
printf 'start %s\nend %s\nelapsed_s %d (compile + run)\n' "$t0" "$(date -u +%FT%TZ)" $((s1 - s0)) >"$out/test-times.txt"
if [ "$rc" -eq 0 ] && [ "$passed" -eq 0 ]; then echo "test-ureth: cargo succeeded but no test ran: an empty selection is not a pass" >&2; rc=3; fi
cat "$out/summary.txt" | head -n 12
exit "$rc"
