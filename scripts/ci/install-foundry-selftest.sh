#!/usr/bin/env bash
# Self-test of install-foundry.sh against a local file:// "release" in a throwaway HOME: a good archive installs; a verified archive is reused from the cache with
# the url gone; a failing download is retried a bounded number of times and then fails; an archive with the wrong digest is refused (and never cached); a cached
# file with a bad digest is replaced. No network.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
sha256() { sha256sum "$1" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$1" | awk '{print $1}'; }
mkdir "$t/pk"; printf '#!/bin/sh\necho "cast Version: 1.8.1-selftest"\n' >"$t/pk/cast"; chmod +x "$t/pk/cast"; tar -czf "$t/a.tgz" -C "$t/pk" cast
sha=$(sha256 "$t/a.tgz"); zero=$(printf '0%.0s' $(seq 64))
pins() { printf '{"toolchains":{"foundry":{"url":"file://%s","sha256":"%s"}}}\n' "$1" "$2" >"$3"; }
pins "$t/a.tgz" "$sha" "$t/good.json"; pins "$t/gone.tgz" "$sha" "$t/gone.json"; pins "$t/a.tgz" "$zero" "$t/bad.json"
n=0; fails=0
run() { HOME=$1 FOUNDRY_PINS=$2 FOUNDRY_ATTEMPTS=${3:-3} FOUNDRY_PAUSE=0 "$here/install-foundry.sh" 2>"$t/err" >"$t/out"; }
chk() { n=$((n + 1)); if [ "$1" = ok ]; then echo "  ok    $2"; else echo "  FAIL  $2"; fails=$((fails + 1)); fi; }
mkdir -p "$t/h1"; if run "$t/h1" "$t/good.json" && grep -q selftest "$t/out" && [ -f "$t/h1/.cache/unicity-foundry/foundry-$sha.tar.gz" ]; then chk ok "a pinned archive installs and is cached by digest"; else chk no "a pinned archive installs and is cached by digest"; fi
if run "$t/h1" "$t/gone.json" && grep -q selftest "$t/out"; then chk ok "the cached archive is used with the url gone"; else chk no "the cached archive is used with the url gone"; fi
mkdir -p "$t/h2"; if run "$t/h2" "$t/gone.json" 3; then chk no "an unreachable url failed the install"; elif [ "$(grep -c 'attempt [0-9]*: downloading' "$t/err")" = 3 ]; then chk ok "an unreachable url is tried 3 times, then the install fails"; else chk no "an unreachable url is tried 3 times, then the install fails"; fi
mkdir -p "$t/h3"; if run "$t/h3" "$t/bad.json" 2; then chk no "a wrong digest was accepted"; elif [ "$(grep -c 'manifest pins' "$t/err")" = 2 ] && [ -z "$(ls "$t/h3/.cache/unicity-foundry" 2>/dev/null)" ]; then chk ok "a wrong digest is refused after 2 attempts and nothing is cached"; else chk no "a wrong digest is refused after 2 attempts and nothing is cached"; fi
echo junk >"$t/h1/.cache/unicity-foundry/foundry-$sha.tar.gz"; if run "$t/h1" "$t/good.json" && grep -q selftest "$t/out"; then chk ok "a cached file with a bad digest is replaced"; else chk no "a cached file with a bad digest is replaced"; fi
echo "install-foundry self-test: $n cases, $fails failures"; [ "$fails" -eq 0 ]
