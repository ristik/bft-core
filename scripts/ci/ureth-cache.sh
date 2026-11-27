#!/usr/bin/env bash
# Cache keys and fail-closed checks for the pinned ureth binary (build-ureth) and the targeted-test pass stamp (ureth-targeted).
#   scripts/ci/ureth-cache.sh keys                     -> bin_key=..., stamp_key=... (for $GITHUB_OUTPUT)
#   scripts/ci/ureth-cache.sh verify-bin OUT_DIR       a restored build-ureth.sh OUT_DIR: refused unless it is the pin's binary with intact provenance
#   scripts/ci/ureth-cache.sh write-stamp TEST_OUT FILE   after a passing test-ureth.sh run: the stamp of what passed
#   scripts/ci/ureth-cache.sh check-stamp FILE         a restored stamp: refused unless it records a pass of exactly this commit, selection, toolchain and script
#   scripts/ci/ureth-cache.sh selftest
# The keys are exact (no restore-keys): the ureth commit, the Rust toolchain, the build args or the test selectors, the script that builds or tests, and the runner
# image. Any change to one of them is a miss and a full build or test run. ci-lane.yml restores only on pull_request; the trusted events always build and test.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pins=${URETH_CACHE_PINS:-$("$here/lane-product.sh" manifest)}

commit() { jq -er .components.ureth.commit "$pins"; }
rust() { jq -er .toolchains.rust "$pins"; }
packages() { jq -ec '.components.ureth.targetedPackages' "$pins"; }
h() { sha256sum | cut -c1-16; }
image() { echo "${ImageOS:-unknown}-${RUNNER_ARCH:-$(uname -m)}"; }
build_recipe() { { jq -ec .components.ureth.cargoArgs "$pins"; cat "$here/build-ureth.sh"; } | h; }
test_recipe() { { packages; cat "$here/test-ureth.sh"; } | h; }
die() { echo "ureth-cache: $*" >&2; exit 1; }

keys() {
  local c r; c=$(commit); r=$(rust)
  [[ $c =~ ^[0-9a-f]{40}$ ]] || die "the pinned commit is not 40 hex: $c"
  echo "bin_key=ureth-bin-v1-$c-rust$r-$(build_recipe)-$(image)"
  echo "stamp_key=ureth-targeted-pass-v1-$c-rust$r-$(test_recipe)-$(image)"
}

verify_bin() {
  local d=${1:?OUT_DIR} c; c=$(commit)
  for f in unicity-reth sha256.txt commit.txt toolchain.txt build-command.txt version.txt; do [ -s "$d/$f" ] || die "restored build has no $f"; done
  [ "$(tr -d '[:space:]' <"$d/commit.txt")" = "$c" ] || die "restored build is of $(cat "$d/commit.txt"), the pin is $c"
  ( cd "$d" && sha256sum --quiet -c sha256.txt ) || die "restored unicity-reth does not match its recorded sha256"
  grep -q "^rustc $(rust) " "$d/toolchain.txt" || die "restored build is not of the pinned Rust $(rust)"
  grep -qF -- "$(jq -er '.components.ureth.cargoArgs | join(" ")' "$pins")" "$d/build-command.txt" || die "restored build used other cargo args"
  chmod +x "$d/unicity-reth"
  "$d/unicity-reth" --version 2>&1 | grep -q "$c" || die "restored unicity-reth does not report the pinned commit"
  echo "restored unicity-reth $(cut -d' ' -f1 "$d/sha256.txt") of $c verified"
}

write_stamp() {
  local out=${1:?TEST_OUT} file=${2:?FILE} passed failed
  passed=$(sed -n 's/^tests passed: \([0-9]*\) .*/\1/p' "$out/summary.txt"); failed=$(sed -n 's/.*failed: \([0-9]*\) .*/\1/p' "$out/summary.txt")
  grep -q '^cargo exit: 0$' "$out/summary.txt" || die "no stamp: cargo did not exit 0"
  [ "${passed:-0}" -gt 0 ] && [ "${failed:-1}" -eq 0 ] || die "no stamp: passed=${passed:-?} failed=${failed:-?}"
  [ "$(tr -d '[:space:]' <"$out/commit.txt")" = "$(commit)" ] || die "no stamp: the tests ran another commit"
  mkdir -p "$(dirname "$file")"
  jq -n --arg commit "$(commit)" --arg rust "$(rust)" --argjson packages "$(packages)" --arg recipe "$(test_recipe)" --arg image "$(image)" \
    --argjson passed "$passed" --argjson failed "$failed" --arg run "${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-local}/actions/runs/${GITHUB_RUN_ID:-0}/attempts/${GITHUB_RUN_ATTEMPT:-0}" \
    --arg event "${GITHUB_EVENT_NAME:-local}" --arg ref "${GITHUB_REF:-local}" --arg summary "$(cat "$out/summary.txt")" \
    '{commit:$commit, rust:$rust, packages:$packages, recipe:$recipe, image:$image, passed:$passed, failed:$failed, run:$run, event:$event, ref:$ref, summary:$summary}' >"$file"
  echo "stamp: $passed passed, 0 failed, of $(commit)"
}

check_stamp() {
  local file=${1:?FILE}
  [ -s "$file" ] || die "the restored stamp is empty"
  jq -e --arg commit "$(commit)" --arg rust "$(rust)" --argjson packages "$(packages)" --arg recipe "$(test_recipe)" --arg image "$(image)" \
    '.commit == $commit and .rust == $rust and .packages == $packages and .recipe == $recipe and .image == $image and .failed == 0 and .passed > 0' "$file" >/dev/null \
    || die "the restored stamp does not record a pass of this commit, selection, toolchain, script and image"
  echo "ureth-targeted already passed for $(commit) (rust $(rust), $(jq -r '.packages | join(",")' "$file")): $(jq -r .passed "$file") tests in $(jq -r .run "$file") ($(jq -r .event "$file") on $(jq -r .ref "$file"))"
}

selftest() {
  local t; t=$(mktemp -d)
  local fails=0 n=0
  ok() { n=$((n + 1)); if ( "$@" ) >/dev/null 2>&1; then echo "  ok    $*"; else echo "  FAIL  $*"; fails=$((fails + 1)); fi; }
  no() { n=$((n + 1)); if ( "$@" ) >/dev/null 2>&1; then echo "  FAIL  (accepted) $*"; fails=$((fails + 1)); else echo "  ok    refused: $*"; fi; }
  jq '.components.ureth.commit = "1111111111111111111111111111111111111111" | .toolchains.rust = "1.0.0"' "$pins" >"$t/pins.json"
  local real=$pins; pins=$t/pins.json
  local c=1111111111111111111111111111111111111111
  # a fake build OUT_DIR
  mkdir -p "$t/b"; printf '#!/bin/sh\necho "unicity-reth %s"\n' "$c" >"$t/b/unicity-reth"; chmod +x "$t/b/unicity-reth"
  ( cd "$t/b" && sha256sum unicity-reth >sha256.txt ); echo "$c" >"$t/b/commit.txt"; echo "rustc 1.0.0 (x)" >"$t/b/toolchain.txt"
  echo "cargo +1.0.0 $(jq -r '.components.ureth.cargoArgs | join(" ")' "$t/pins.json") --target-dir <work>/target" >"$t/b/build-command.txt"; echo v >"$t/b/version.txt"
  ok verify_bin "$t/b"
  cp -R "$t/b" "$t/b2"; echo x >>"$t/b2/unicity-reth"; no verify_bin "$t/b2"
  cp -R "$t/b" "$t/b3"; echo 2222222222222222222222222222222222222222 >"$t/b3/commit.txt"; no verify_bin "$t/b3"
  cp -R "$t/b" "$t/b4"; echo "rustc 1.0.1 (x)" >"$t/b4/toolchain.txt"; no verify_bin "$t/b4"
  # stamps
  mkdir -p "$t/o"; echo "$c" >"$t/o/commit.txt"
  printf 'packages: x\ncommit: %s\ncargo exit: 0\ntests passed: 12  failed: 0  ignored: 1\n' "$c" >"$t/o/summary.txt"
  ok write_stamp "$t/o" "$t/s.json"; ok check_stamp "$t/s.json"
  printf 'packages: x\ncommit: %s\ncargo exit: 101\ntests passed: 11  failed: 1  ignored: 1\n' "$c" >"$t/o/summary.txt"; no write_stamp "$t/o" "$t/f.json"
  printf 'packages: x\ncommit: %s\ncargo exit: 0\ntests passed: 0  failed: 0  ignored: 0\n' "$c" >"$t/o/summary.txt"; no write_stamp "$t/o" "$t/f.json"
  jq '.packages += ["another"]' "$t/s.json" >"$t/s2.json"; no check_stamp "$t/s2.json"
  jq '.failed = 1' "$t/s.json" >"$t/s3.json"; no check_stamp "$t/s3.json"
  jq '.components.ureth.commit = "3333333333333333333333333333333333333333"' "$t/pins.json" >"$t/pins2.json"
  pins=$t/pins2.json; no check_stamp "$t/s.json"; pins=$t/pins.json
  local k1 k2; k1=$(keys); jq '.components.ureth.targetedPackages += ["x"]' "$t/pins.json" >"$t/pins3.json"; k2=$(pins=$t/pins3.json; keys)
  n=$((n + 1)); if [ "$(sed -n 1p <<<"$k1")" = "$(sed -n 1p <<<"$k2")" ] && [ "$(sed -n 2p <<<"$k1")" != "$(sed -n 2p <<<"$k2")" ]; then echo "  ok    a selector change moves the stamp key only"; else echo "  FAIL  selector change keys"; fails=$((fails + 1)); fi
  pins=$real; rm -rf "$t"
  echo "ureth-cache self-test: $n cases, $fails failures"; [ "$fails" -eq 0 ]
}

case "${1:-}" in
  keys) keys ;;
  verify-bin) verify_bin "${2:-}" ;;
  write-stamp) write_stamp "${2:-}" "${3:-}" ;;
  check-stamp) check_stamp "${2:-}" ;;
  selftest) selftest ;;
  *) sed -n '2,10p' "$0" >&2; exit 2 ;;
esac
