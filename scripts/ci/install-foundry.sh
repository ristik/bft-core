#!/usr/bin/env bash
# Installs the Foundry release pinned in scripts/ci/lane-pins.json (Linux x86_64) into ~/.foundry/bin after verifying the downloaded archive's sha256 against the manifest.
#   scripts/ci/install-foundry.sh [DOWNLOAD_DIR]
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); pins=$here/lane-pins.json
dl=${1:-${RUNNER_TEMP:-/tmp}/foundry-dl}; mkdir -p "$dl" "$HOME/.foundry/bin"
url=$(jq -er .toolchains.foundry.url "$pins"); want=$(jq -er .toolchains.foundry.sha256 "$pins")
curl -fsSL "$url" -o "$dl/foundry.tar.gz"
got=$(sha256sum "$dl/foundry.tar.gz" | awk '{print $1}')
[ "$got" = "$want" ] || { echo "install-foundry: $url has sha256 $got, the manifest pins $want" >&2; exit 1; }
tar -xzf "$dl/foundry.tar.gz" -C "$HOME/.foundry/bin"
"$HOME/.foundry/bin/cast" --version | head -1
