#!/usr/bin/env bash
# Copies the secrets of T6's isolated devnet (every jwt.hex and keys.json under its test-nodes, plus the treasury test key) into DEST in the --nodes layout of
# publish-evidence.sh (DEST/<dir>/jwt.hex, DEST/<dir>/keys.json), so the publisher can search the published pack for their VALUES after the isolated checkout is gone.
# DEST is outside the evidence and is never uploaded. Usage: t6-secrets.sh DEST TEST_NODES_DIR [TREASURY_KEY_HEX]
set -euo pipefail
dest=${1:?DEST}; src=${2:?TEST_NODES_DIR}; treasury=${3:-}
[ -d "$src" ] || exit 0   # nothing to save (the isolated checkout is already gone, or never existed)
mkdir -p "$dest"
( cd "$src" && find . -maxdepth 4 -type f \( -name jwt.hex -o -name keys.json \) -print ) | while IFS= read -r f; do
  d=$(dirname "${f#./}"); d=${d//\//-}; [ "$d" != . ] || d=top
  mkdir -p "$dest/$d"; cp "$src/$f" "$dest/$d/$(basename "$f")"
done
if [ -n "$treasury" ]; then mkdir -p "$dest/treasury"; printf '{"privateKey":"0x%s"}\n' "${treasury#0x}" >"$dest/treasury/keys.json"; fi
chmod -R go-rwx "$dest"
