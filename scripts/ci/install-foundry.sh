#!/usr/bin/env bash
# Installs the Foundry release pinned in scripts/ci/lane-pins.json (Linux x86_64) into ~/.foundry/bin. The archive is accepted only if its sha256 is the
# one pinned in that file: there is no attestation lookup, so nothing here depends on a second GitHub endpoint, and no mode skips the check.
#   scripts/ci/install-foundry.sh [CACHE_DIR]
# The verified archive is kept as CACHE_DIR/foundry-<sha256>.tar.gz (default ~/.cache/unicity-foundry; CI restores that directory with actions/cache). A cached
# file is used only if its digest verifies, otherwise it is deleted and downloaded again. A download that fails or has the wrong digest is retried with
# a growing pause (FOUNDRY_ATTEMPTS, default 6, pause 5 s doubling to 60 s); after the last attempt the script fails and says what it got.
# FOUNDRY_PINS overrides the pins file (tests only; a file:// url works).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); pins=${FOUNDRY_PINS:-$here/lane-pins.json}
cache=${1:-${FOUNDRY_CACHE_DIR:-$HOME/.cache/unicity-foundry}}; mkdir -p "$cache" "$HOME/.foundry/bin"
url=$(jq -er .toolchains.foundry.url "$pins"); want=$(jq -er .toolchains.foundry.sha256 "$pins")
attempts=${FOUNDRY_ATTEMPTS:-6}; pause=${FOUNDRY_PAUSE:-5}
file=$cache/foundry-$want.tar.gz
digest() { sha256sum "$1" | awk '{print $1}'; }

if [ -f "$file" ] && [ "$(digest "$file")" != "$want" ]; then echo "install-foundry: the cached $file does not have the pinned digest, deleting it" >&2; rm -f "$file"; fi
if [ ! -f "$file" ]; then
  n=0; got=
  while :; do
    n=$((n+1)); part=$file.part; rm -f "$part"
    if curl -fsSL --connect-timeout 20 --max-time 120 "$url" -o "$part"; then
      got=$(digest "$part")
      if [ "$got" = "$want" ]; then mv "$part" "$file"; break; fi
      echo "install-foundry: attempt $n: $url has sha256 $got, the manifest pins $want" >&2
    else
      echo "install-foundry: attempt $n: downloading $url failed" >&2
    fi
    rm -f "$part"
    [ "$n" -lt "$attempts" ] || { echo "install-foundry: giving up after $n attempts${got:+ (last sha256 $got, pinned $want)}" >&2; exit 1; }
    echo "install-foundry: retrying in ${pause}s" >&2; sleep "$pause"; pause=$((pause*2)); [ "$pause" -le 60 ] || pause=60
  done
fi
tar -xzf "$file" -C "$HOME/.foundry/bin"
"$HOME/.foundry/bin/cast" --version | head -1
