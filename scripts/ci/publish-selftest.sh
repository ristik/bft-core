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
  mkdir -p "$1.extra"; echo "run log" >"$1.extra/run-lane.log"
  mkdir -p "$1/nodes/root1" "$1/p85/run" "$1/state"
  echo "step lines" >"$1/lane.log"; echo "debug" >"$1/nodes/root1/debug.log"
  printf '{"privateKey":"%s"}\n' "$canary" >"$1/state/keys.json"; echo "$canary" >"$1/state/owner.key"; echo "jwt" >"$1/state/jwt.hex"
  mkdir -p "$1/p85/joiner"; printf '{"ownerKey":"0x%s","rootKey":"0x%s","expiry":1}\n' "$(printf '%064d' 7)" "$(printf '%064d' 8)" >"$1/p85/joiner/joiner.json"
  [ "$2" = no ] || echo "leaked $canary here" >>"$1/nodes/root1/debug.log"
}
# the secrets the scan searches for by value are those under --nodes
mkdir -p "$t/test-nodes/root1"; printf '{"privateKey":"0x%s"}\n' "$canary" >"$t/test-nodes/root1/keys.json"

mkrun "$t/runA" no
"$here/publish-evidence.sh" --evidence "$t/runA" --out "$t/outA" --status 1 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 3 ] && ok "a failed run publishes (exit 3: incomplete)" || no "a failed run: exit $rc, wanted 3"
a=$t/outA/runA.tar.gz; [ -f "$a" ] || a=
if [ -n "$a" ]; then
  mkdir "$t/xA"; tar -xzf "$a" -C "$t/xA"; d=$t/xA/runA
  [ -f "$d/INCOMPLETE.txt" ] && ok "the pack is marked INCOMPLETE" || no "no INCOMPLETE.txt"
  ( cd "$d" && source "$here/../lib/portable.sh" && p_sha256 -c SHA256SUMS >/dev/null ) && ok "SHA256SUMS of the published directory verify" || no "checksums do not verify"
  [ ! -e "$d/state/keys.json" ] && [ ! -e "$d/state/owner.key" ] && [ ! -e "$d/state/jwt.hex" ] && ok "key, JWT and credential files are not in the pack" || no "a secret file is in the pack"
  grep -q 'owner.key' "$t/outA/removed.txt" && ok "the removed files are listed" || no "removed.txt does not list owner.key"
  [ ! -e "$d/p85/joiner/joiner.json" ] && grep -q 'joiner.json' "$t/outA/removed.txt" && ok "a file with a private-key field is removed by content and listed" || no "joiner.json (private-key fields) is in the pack or unlisted"
  ! grep -rqF "$canary" "$d" && ok "the canary is nowhere in the published tree" || no "the canary value is in the published tree"
  [ -s "$t/outA/$(basename "$a").sha256" ] && ok "the outer digest is written" || no "no outer digest"
else no "no archive published"; fi

mkrun "$t/runB" yes
"$here/publish-evidence.sh" --evidence "$t/runB" --out "$t/outB" --status 0 --nodes "$t/test-nodes" --extra "$t/runB.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && ok "a leaked secret value makes the archive unpublishable (exit 4)" || no "a leaked value: exit $rc, wanted 4"
[ -f "$t/outB/runB.tar.gz" ] && no "the archive with the leaked value was published" || ok "that archive is not in the upload set"
[ -f "$t/outB/runB-ci.tar.gz" ] && ok "the CI logs archive is still published (scanned on its own)" || no "the CI logs archive was lost with the rejected one"
ls "$t/outB"/*.REJECTED.txt >/dev/null 2>&1 && ok "a REJECTED diagnostic is published instead" || no "no REJECTED diagnostic"
! grep -rqF "$canary" "$t/outB" && ok "the diagnostic does not carry the value" || no "the upload set contains the canary value"
# S1: a secret inside a compressed member is a secret in the archive (the value is one under --nodes)
mkrun "$t/runC" no; printf 'compressed leak %s\n' "$canary" | gzip -c >"$t/runC/nodes/root1/debug.log.gz"
"$here/publish-evidence.sh" --evidence "$t/runC" --out "$t/outC" --status 0 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && ok "a secret value inside a .gz member makes the archive unpublishable (exit 4)" || no "a value inside a .gz member: exit $rc, wanted 4"
[ -f "$t/outC/runC.tar.gz" ] && no "the archive with a secret inside a .gz member was published" || ok "that archive is not in the upload set"
# the same, nested in a .tar.gz
mkrun "$t/runC2" no; mkdir "$t/c2" && printf 'nested leak %s\n' "$canary" >"$t/c2/inner.log" && tar -C "$t/c2" -czf "$t/runC2/nodes/root1/bundle.tar.gz" inner.log
"$here/publish-evidence.sh" --evidence "$t/runC2" --out "$t/outC2" --status 0 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && [ ! -f "$t/outC2/runC2.tar.gz" ] && ok "a secret inside a .tar.gz member is refused too" || no "a value inside a .tar.gz: exit $rc or the archive was published"
# S2: the values of files REMOVED by name or content are searched for in what remains: the joiner's ownerKey is not under --nodes, but it appears in a log
joinerkey=$(printf '%064d' 424242)
mkrun "$t/runD" no; sed -i.bak "s/\"ownerKey\":\"0x[0-9]*\"/\"ownerKey\":\"0x$joinerkey\"/" "$t/runD/p85/joiner/joiner.json"; rm -f "$t/runD/p85/joiner/joiner.json.bak"
echo "leaked joiner key $joinerkey in a log" >>"$t/runD/nodes/root1/debug.log"
"$here/publish-evidence.sh" --evidence "$t/runD" --out "$t/outD" --status 0 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && [ ! -f "$t/outD/runD.tar.gz" ] && ok "a removed file's secret (joiner ownerKey) that leaked into a log refuses the archive" || no "removed-file value in a log: exit $rc or published"
! grep -rqF "$joinerkey" "$t/outD" && ok "the joiner key is not in the upload set" || no "the joiner key is in the upload set"
# #694: fail closed. A secret inside a member the view cannot expand, and a gzip that does not expand, make the archive unpublishable (never scanned as opaque bytes).
# The member-format cases need the tool that makes the format; a missing tool skips its case (CI has them all), the checks themselves are the same for every format.
refused() { # LABEL RUNDIR OUTDIR: the archive was refused with a REJECTED diagnostic that names the member and not the value
  local label=$1 r=$2 o=$3
  "$here/publish-evidence.sh" --evidence "$r" --out "$o" --status 0 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
  [ "$rc" -eq 4 ] && [ ! -f "$o/$(basename "$r").tar.gz" ] && ls "$o/$(basename "$r").tar.gz.REJECTED.txt" >/dev/null 2>&1 && ok "$label: refused (exit 4, REJECTED diagnostic)" || no "$label: exit $rc or the archive was published"
  ! grep -rqF "$canary" "$o" && ok "$label: the diagnostic does not carry the value" || no "$label: the upload set contains the value"
}
for fmt in zst xz bz2 zip; do
  r=$t/runF-$fmt; mkrun "$r" no; src=$t/f-$fmt.txt; printf 'leak %s\n' "$canary" >"$src"
  case $fmt in
    zst) command -v zstd >/dev/null && zstd -q -o "$r/nodes/root1/debug.log.zst" "$src" ;;
    xz)  command -v xz >/dev/null && xz -c "$src" >"$r/nodes/root1/debug.log.xz" ;;
    bz2) command -v bzip2 >/dev/null && bzip2 -c "$src" >"$r/nodes/root1/debug.log.bz2" ;;
    zip) command -v zip >/dev/null && ( cd "$t" && zip -q "$r/nodes/root1/debug.log.zip" "f-$fmt.txt" ) ;;
  esac
  if [ -n "$(ls "$r/nodes/root1" | grep "\.$fmt\$")" ]; then refused "a secret inside a .$fmt member" "$r" "$t/outF-$fmt"; else echo "  skip  .$fmt (no tool)"; fi
done
# the format is recognised by its magic bytes too, not only by its name
r=$t/runG; mkrun "$r" no; printf '\x28\xb5\x2f\xfd rest of a zstd frame' >"$r/nodes/root1/renamed.dat"; refused "a zstd member renamed to .dat" "$r" "$t/outG"
r=$t/runG2; mkrun "$r" no; printf 'leak %s\n' "$canary" | gzip -c >"$r/nodes/root1/renamed.dat"; refused "a gzip member with a non-gz name" "$r" "$t/outG2"
# a corrupt or truncated gzip is unscannable, not scanned as its compressed bytes
r=$t/runH; mkrun "$r" no; printf 'leak %s\n' "$canary" | gzip -c | head -c 20 >"$r/nodes/root1/debug.log.gz"; refused "a truncated .gz" "$r" "$t/outH"
r=$t/runH2; mkrun "$r" no; echo "this is not gzip" >"$r/nodes/root1/fake.log.gz"; refused "a .gz that is not gzip" "$r" "$t/outH2"
r=$t/runH3; mkrun "$r" no; mkdir "$t/h3"; echo x >"$t/h3/a"; tar -C "$t/h3" -czf "$r/nodes/root1/b.tar.gz" a; head -c 30 "$r/nodes/root1/b.tar.gz" >"$r/nodes/root1/c.tgz"; rm "$r/nodes/root1/b.tar.gz"; refused "a truncated .tgz" "$r" "$t/outH3"
# inside a tar.gz: a plain tar member that nobody expands
r=$t/runH4; mkrun "$r" no; mkdir "$t/h4"; printf 'leak %s\n' "$canary" >"$t/h4/in.log"; tar -C "$t/h4" -cf "$t/h4.tar" in.log; tar -C "$t" -czf "$r/nodes/root1/outer.tar.gz" h4.tar; refused "a plain .tar inside a .tar.gz" "$r" "$t/outH4"
# the plain case still publishes (expandable gz and a nested gz are fine)
r=$t/runH5; mkrun "$r" no; printf 'fine\n' | gzip -c >"$r/nodes/root1/ok.log.gz"
"$here/publish-evidence.sh" --evidence "$r" --out "$t/outH5" --status 0 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ -f "$t/outH5/runH5.tar.gz" ] && ok "a valid .gz member still publishes" || no "a valid .gz was refused (exit $rc)"
# T6 (#712): the secrets of the isolated devnet are saved in the --nodes layout, and a JWT leaked into a failed-node log refuses the archive
tn=$t/t6nodes; mkdir -p "$tn/evm1" "$tn/root1"; jwt=$(printf 'ab%.0s' {1..32}); echo "$jwt" >"$tn/evm1/jwt.hex"; printf '{"privateKey":"0x%s"}\n' "$(printf '%064d' 99)" >"$tn/root1/keys.json"
"$here/t6-secrets.sh" "$t/t6sec" "$tn" 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
[ -s "$t/t6sec/evm1/jwt.hex" ] && [ -s "$t/t6sec/root1/keys.json" ] && [ -s "$t/t6sec/treasury/keys.json" ] && ok "t6-secrets saves the jwt, the keys and the treasury key in the --nodes layout" || no "t6-secrets did not save them"
r=$t/runT6; mkrun "$r" no; mkdir -p "$r/failed-node-logs"; echo "engine auth with $jwt failed" >"$r/failed-node-logs/evm1-reth.log"
"$here/publish-evidence.sh" --evidence "$r" --out "$t/outT6" --kind t6 --status 1 --min-node-logs 0 --nodes "$t/t6sec" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && [ ! -f "$t/outT6/runT6.tar.gz" ] && ok "T6: a JWT of the isolated devnet in a failed-node log refuses the archive" || no "T6 jwt leak: exit $rc or published"
! grep -rqF "$jwt" "$t/outT6" && ok "T6: the JWT is not in the upload set" || no "T6: the JWT is in the upload set"
r=$t/runT6b; mkrun "$r" no; mkdir -p "$r/failed-node-logs"; echo "engine auth failed" >"$r/failed-node-logs/evm1-reth.log"
"$here/publish-evidence.sh" --evidence "$r" --out "$t/outT6b" --kind t6 --status 1 --min-node-logs 0 --nodes "$t/t6sec" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1
[ -f "$t/outT6b/runT6b.tar.gz" ] && ok "T6: the same pack without the leak publishes" || no "T6: a clean pack was refused"
mkrun "$t/runE" no
"$here/publish-evidence.sh" --evidence "$t/runE" --out "$t/outE" --status 0 --nodes "$t/test-nodes" --extra "$t/runA.extra/run-lane.log" >/dev/null 2>&1; rc=$?
[ -f "$t/outE/runE.tar.gz" ] && [ ! -e "$t/xE" ] && ok "the same run without a leak publishes (joiner.json removed)" || no "a clean run was not published (exit $rc)"
echo "publish-evidence self-test: $n cases, $bad failures"; [ "$bad" -eq 0 ]
