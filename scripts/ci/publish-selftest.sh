#!/usr/bin/env bash
# Self-test of scripts/ci/publish-evidence.sh with planted canaries (no chain): a secret file is removed by name and listed, a secret VALUE that leaked into a log makes the
# archive unpublishable (quarantined, a REJECTED diagnostic naming the file but not the value is published instead), a failed run is marked incomplete with valid checksums,
# and a clean complete-looking run publishes with an outer digest.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
n=0; bad=0
ok() { n=$((n + 1)); echo "  ok    $1"; }
no() { n=$((n + 1)); bad=$((bad + 1)); echo "  FAIL  $1"; }
canary=CANARY-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
mkrun() { # DIR LEAKED(yes|no)
  mkdir -p "$1/nodes/root1" "$1/p85/run" "$1/state"
  echo "step lines" >"$1/lane.log"; echo "debug" >"$1/nodes/root1/debug.log"
  printf '{"privateKey":"%s"}\n' "$canary" >"$1/state/keys.json"; echo "$canary" >"$1/state/owner.key"; echo "jwt" >"$1/state/jwt.hex"
  [ "$2" = no ] || echo "leaked $canary here" >>"$1/nodes/root1/debug.log"
}
# the secrets the scan searches for by value are those under --nodes
mkdir -p "$t/test-nodes/root1"; printf '{"privateKey":"0x%s"}\n' "$canary" >"$t/test-nodes/root1/keys.json"

mkrun "$t/runA" no
"$here/publish-evidence.sh" --evidence "$t/runA" --out "$t/outA" --status 1 --nodes "$t/test-nodes" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 3 ] && ok "a failed run publishes (exit 3: incomplete)" || no "a failed run: exit $rc, wanted 3"
a=$(ls "$t/outA"/*.tar.gz 2>/dev/null | head -1)
if [ -n "$a" ]; then
  mkdir "$t/xA"; tar -xzf "$a" -C "$t/xA"; d=$t/xA/runA
  [ -f "$d/INCOMPLETE.txt" ] && ok "the pack is marked INCOMPLETE" || no "no INCOMPLETE.txt"
  ( cd "$d" && source "$here/../lib/portable.sh" && p_sha256 -c SHA256SUMS >/dev/null ) && ok "SHA256SUMS of the published directory verify" || no "checksums do not verify"
  [ ! -e "$d/state/keys.json" ] && [ ! -e "$d/state/owner.key" ] && [ ! -e "$d/state/jwt.hex" ] && ok "key, JWT and credential files are not in the pack" || no "a secret file is in the pack"
  grep -q 'owner.key' "$t/outA/removed.txt" && ok "the removed files are listed" || no "removed.txt does not list owner.key"
  ! grep -rqF "$canary" "$d" && ok "the canary is nowhere in the published tree" || no "the canary value is in the published tree"
  [ -s "$t/outA/$(basename "$a").sha256" ] && ok "the outer digest is written" || no "no outer digest"
else no "no archive published"; fi

mkrun "$t/runB" yes
"$here/publish-evidence.sh" --evidence "$t/runB" --out "$t/outB" --status 0 --nodes "$t/test-nodes" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && ok "a leaked secret value makes the archive unpublishable (exit 4)" || no "a leaked value: exit $rc, wanted 4"
ls "$t/outB"/*.tar.gz >/dev/null 2>&1 && no "the archive with the leaked value was published" || ok "that archive is not in the upload set"
ls "$t/outB"/*.REJECTED.txt >/dev/null 2>&1 && ok "a REJECTED diagnostic is published instead" || no "no REJECTED diagnostic"
! grep -rqF "$canary" "$t/outB" && ok "the diagnostic does not carry the value" || no "the upload set contains the canary value"
echo "publish-evidence self-test: $n cases, $bad failures"; [ "$bad" -eq 0 ]
