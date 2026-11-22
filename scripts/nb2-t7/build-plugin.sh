#!/usr/bin/env bash
# Build the SDK in a fresh tree containing only tracked files from the pin.
set -euo pipefail
source_checkout=$1 revision=$2 destination=$3
mkdir "$destination"
git -C "$source_checkout" archive "$revision" | tar -x -C "$destination"
cd "$destination"
npm ci --include=dev --no-audit --no-fund
npm run build
test -f packages/native-bridge-plugin/lib/nb2/index.js
