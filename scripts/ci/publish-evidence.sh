#!/usr/bin/env bash
# Selects the publishable copy of a lane evidence directory, scans it, and writes the upload set.
#   scripts/ci/publish-evidence.sh --evidence DIR --out OUT --status N [--nodes test-nodes] [--min-node-logs N] [--extra PATH]...
# OUT/<name>.tar.gz   the publishable run directory (keys, JWTs, credentials, execution-client data and raw node databases excluded by name), SHA256SUMS recomputed over the
#                     FINAL published directory and inside the archive, and INCOMPLETE.txt when the run did not complete (--status != 0 or a missing sentinel)
# OUT/<name>.tar.gz.sha256   the outer digest
# OUT/MANIFEST.txt, OUT/removed.txt   what was published, what was left out by name, and every scan verdict
# A secret found by value or field in what remains is NOT published: the archive is quarantined (OUT/../quarantine, never uploaded) and OUT/<name>.REJECTED.txt names what
# was found where, never the value (scripts/lib/reth-pin.sh select-upload, the pattern of reth-smoke.yml).
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/../.." && pwd)
source "$repo/scripts/lib/portable.sh"
ev= out= status=0 nodes= minlogs=0; extra=()
while [ $# -gt 0 ]; do case "$1" in
  --evidence) ev=$2; shift 2 ;; --out) out=$2; shift 2 ;; --status) status=$2; shift 2 ;; --nodes) nodes=$2; shift 2 ;;
  --min-node-logs) minlogs=$2; shift 2 ;; --extra) extra+=("$2"); shift 2 ;; *) echo "publish-evidence: unknown argument $1" >&2; exit 2 ;; esac; done
[ -d "$ev" ] && [ -n "$out" ] || { echo "usage: publish-evidence.sh --evidence DIR --out OUT --status N [--nodes DIR] [--min-node-logs N] [--extra PATH]..." >&2; exit 2; }
name=$(basename "$ev"); mkdir -p "$out"; quarantine="$(cd "$out" && pwd)/../quarantine"; mkdir -p "$quarantine"
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT
pub=$stage/$name; mkdir -p "$pub"

# 1. the publishable copy: everything except secrets and bulk by name (what is left out is listed, not silently dropped)
( cd "$ev" && find . \( -name keys.json -o -name 'jwt.hex' -o -name '*.key' -o -name '*.scan' -o -name '*.cred' -o -name '*.sock' -o -name '.scan-inputs' -o -name '.devnet-pid' -o -name '.runner-pids' \) -print ) | sort >"$out/removed.txt"
rsync -a --exclude keys.json --exclude jwt.hex --exclude '*.key' --exclude '*.scan' --exclude '*.cred' --exclude '*.sock' --exclude .scan-inputs \
  --exclude .devnet-pid --exclude .runner-pids --exclude 'reth*/' --exclude 'evm*/' --exclude 'auth*/' "$ev/" "$pub/"
# a file which carries a private key in a JSON field (the P85 joiner's joiner.json: ownerKey, rootKey) is left out by content as well as by name; listed, not silent
( cd "$pub" && grep -rIlE '"(ownerKey|rootKey|privateKey)"[[:space:]]*:[[:space:]]*"(0x)?[0-9a-fA-F]{64}"' . 2>/dev/null ) | sed 's#^\./#./#' | sort >"$stage/secret-fields.txt"
while read -r f; do [ -n "$f" ] || continue; rm -f "$pub/$f"; echo "$f (private-key field, removed by content)" >>"$out/removed.txt"; done <"$stage/secret-fields.txt"
# the CI harness's own logs (run log, lane stdout, Mongo, host records) are a second archive, scanned on its own: a secret in the evidence directory must not take the
# diagnostics with it, and a secret in a log must not ride along unscanned
ci=$stage/$name-ci; mkdir -p "$ci"
for p in ${extra[@]+"${extra[@]}"}; do [ -e "$p" ] && cp -R "$p" "$ci/"; done
# 2. completeness: the sentinels the lane prints at its end, the exit status, the evidence checker on the self-contained pack
complete=yes; why=()
[ "$status" -eq 0 ] || { complete=no; why+=("lane exit status $status"); }
grep -q 'P85 recovery lane complete' "$ev/lane.log" 2>/dev/null || grep -q 'UTB lane: all steps PASSED' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in lane.log"); }
if [ "$complete" = yes ]; then
  if [ -d "$pub/p85/run/utb" ]; then "$repo/scripts/utb-lane.sh" --check-evidence "$pub/p85/run/utb" >"$pub/ci-check-evidence.txt" 2>&1 || { complete=no; why+=("utb-lane.sh --check-evidence refused the published pack"); }
  else complete=no; why+=("no p85/run/utb pack"); fi
fi
if [ "$complete" = no ]; then
  { echo "INCOMPLETE: this is a failed or partial run's pack, kept for diagnosis. It is NOT acceptance evidence."; printf 'reason: %s\n' "${why[@]}"; } >"$pub/INCOMPLETE.txt"
fi
# 3. SHA256SUMS over the final published directory (INCOMPLETE.txt and the checker output included)
( cd "$pub" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs -I{} bash -c 'source "$0/scripts/lib/portable.sh"; p_sha256 "$1"' "$repo" {} >SHA256SUMS ) 
( cd "$pub" && p_sha256 -c SHA256SUMS >/dev/null ) || { echo "publish-evidence: the checksums of the published directory do not verify" >&2; exit 1; }
# 4. archives, then the secret scan and selection of each archive by the repository's existing pattern
( cd "$ci" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs -I{} bash -c 'source "$0/scripts/lib/portable.sh"; p_sha256 "$1"' "$repo" {} >SHA256SUMS )
tar -C "$stage" -czf "$stage/$name.tar.gz" "$name"
tar -C "$stage" -czf "$stage/$name-ci.tar.gz" "$name-ci"
mkdir -p "$out/sel"
sel=(--out "$out/sel" --quarantine "$quarantine" --require SHA256SUMS)
[ -z "$nodes" ] || sel+=(--nodes "$nodes")
"$repo/scripts/reth-pin.sh" select-upload "${sel[@]}" --min-node-logs "$minlogs" "$stage/$name.tar.gz"; scan_rc=$?
"$repo/scripts/reth-pin.sh" select-upload "${sel[@]}" --min-node-logs 0 "$stage/$name-ci.tar.gz"; scan_ci_rc=$?
cp "$out/sel/"* "$out/" 2>/dev/null; rm -rf "$out/sel"
for a in "$name.tar.gz" "$name-ci.tar.gz"; do [ -f "$out/$a" ] && ( cd "$out" && p_sha256 "$a" >"$a.sha256" ); done
{ echo "evidence $name  complete=$complete ${why[*]:-}"; echo "scan exit evidence=$scan_rc ci-logs=$scan_ci_rc"; ls -l "$out" | awk 'NR>1{print $NF, $5}'; } >"$out/PUBLISH-SUMMARY.txt"
cat "$out/PUBLISH-SUMMARY.txt"
[ "$scan_rc" -eq 0 ] && [ "$scan_ci_rc" -eq 0 ] && { [ "$complete" = yes ] || exit 3; exit 0; }
exit 4
