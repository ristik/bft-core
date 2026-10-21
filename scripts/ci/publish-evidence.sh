#!/usr/bin/env bash
# Selects the publishable copy of a lane evidence directory, scans it, and writes the upload set.
#   scripts/ci/publish-evidence.sh --evidence DIR --out OUT --status N [--nodes test-nodes] [--min-node-logs N] [--extra PATH]...
# OUT/<name>.tar.gz   the publishable run directory (keys, JWTs, credentials, execution-client data and raw node databases excluded by name), SHA256SUMS recomputed over the
#                     FINAL published directory and inside the archive, and INCOMPLETE.txt when the run did not complete (--status != 0 or a missing sentinel)
# OUT/<name>.tar.gz.sha256   the outer digest
# OUT/MANIFEST.txt, OUT/removed.txt   what was published, what was left out by name, and every scan verdict
# Secret values are searched for everywhere that is published, INCLUDING inside .gz / .tgz members (an expanded scan view), and the values of every file removed by name
# or content (keys, JWTs, credentials, the joiner's ownerKey/rootKey) are added to the search, so a removed secret that leaked into a log still refuses the archive.
# A secret found by value or field in what remains is NOT published: the archive is quarantined (OUT/../quarantine, never uploaded) and OUT/<name>.REJECTED.txt names what
# was found where, never the value (scripts/lib/reth-pin.sh select-upload, the pattern of stock-reth-control.yml).
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/../.." && pwd)
source "$repo/scripts/lib/portable.sh"
. "$repo/scripts/lib/reth-pin.sh"   # rethEvidenceValidate / rethEvidenceSecretValues (definitions only)
ev= out= status=0 nodes= minlogs=0 kind=combined; extra=()
while [ $# -gt 0 ]; do case "$1" in
  --evidence) ev=$2; shift 2 ;; --out) out=$2; shift 2 ;; --status) status=$2; shift 2 ;; --nodes) nodes=$2; shift 2 ;;
  --min-node-logs) minlogs=$2; shift 2 ;; --kind) kind=$2; shift 2 ;; --extra) extra+=("$2"); shift 2 ;; *) echo "publish-evidence: unknown argument $1" >&2; exit 2 ;; esac; done
[ -d "$ev" ] && [ -n "$out" ] || { echo "usage: publish-evidence.sh --evidence DIR --out OUT --status N [--nodes DIR] [--min-node-logs N] [--extra PATH]..." >&2; exit 2; }
name=$(basename "$ev"); mkdir -p "$out"; quarantine="$(cd "$out" && pwd)/../quarantine"; mkdir -p "$quarantine"
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT
pub=$stage/$name; mkdir -p "$pub"

# 1. the publishable copy: everything except secrets and bulk by name (what is left out is listed, not silently dropped)
( cd "$ev" && find . \( -name keys.json -o -name 'jwt.hex' -o -name '*.key' -o -name '*.scan' -o -name '*.cred' -o -name '*.sock' -o -name '.scan-inputs' -o -name '.devnet-pid' -o -name '.runner-pids' \) -print ) | sort >"$out/removed.txt"
( cd "$ev" && find . -type d \( -name 'reth*' -o -name 'evm*' -o -name 'auth*' \) -prune -print | sed 's#$# (directory excluded: execution-client data / authority credentials)#' ) | sort >>"$out/removed.txt"
rsync -a --exclude keys.json --exclude jwt.hex --exclude '*.key' --exclude '*.scan' --exclude '*.cred' --exclude '*.sock' --exclude .scan-inputs \
  --exclude .devnet-pid --exclude .runner-pids --exclude 'reth*/' --exclude 'evm*/' --exclude 'auth*/' "$ev/" "$pub/"
# the values of everything removed so far are searched for in what is published (S2): a key file, JWT or credential which was left out must not reappear in a log
vals=$stage/scan-values; : >"$vals"
collect_values() { # FILE: the secret values of a file which is left out. Whole-secret files (keys, JWTs, credentials, scan inputs): their content (0x stripped). Anything else: the values of its
  # private-key fields only (ownerKey, rootKey, privateKey, secret, seed), never its other tokens (addresses, node ids and public keys are not secrets and appear in public files)
  [ -f "$1" ] || return 0
  case "$1" in
    *.key|*/jwt.hex|*.cred|*.scan) tr -d '[:space:]' <"$1" 2>/dev/null | sed -E 's/^0x//' | awk 'length($0) >= 16' >>"$vals"; echo >>"$vals" ;;
    *) grep -aoE '"(ownerKey|rootKey|privateKey|secret|seed)"[[:space:]]*:[[:space:]]*"(0x)?[0-9a-fA-F]{32,}"' "$1" 2>/dev/null | sed -E 's/^.*:[[:space:]]*"(0x)?//; s/"$//' >>"$vals" ;;
  esac
}
while read -r f; do case "$f" in *"(directory excluded"*) ;; *) collect_values "$ev/$f" ;; esac; done <"$out/removed.txt"
# a file which carries a private key in a JSON field (the P85 joiner's joiner.json: ownerKey, rootKey) is left out by content as well as by name; listed, not silent
( cd "$pub" && grep -rIlE '"(ownerKey|rootKey|privateKey)"[[:space:]]*:[[:space:]]*"(0x)?[0-9a-fA-F]{64}"' . 2>/dev/null ) | sed 's#^\./#./#' | sort >"$stage/secret-fields.txt"
while read -r f; do [ -n "$f" ] || continue; collect_values "$pub/$f"; rm -f "$pub/$f"; echo "$f (private-key field, removed by content)" >>"$out/removed.txt"; done <"$stage/secret-fields.txt"
# the CI harness's own logs (run log, lane stdout, Mongo, host records) are a second archive, scanned on its own: a secret in the evidence directory must not take the
# diagnostics with it, and a secret in a log must not ride along unscanned
ci=$stage/$name-ci; mkdir -p "$ci"
for p in ${extra[@]+"${extra[@]}"}; do [ -e "$p" ] && cp -R "$p" "$ci/"; done
# 2. completeness: the sentinels the lane prints at its end, the exit status, the evidence checker on the self-contained pack
complete=yes; why=()
[ "$status" -eq 0 ] || { complete=no; why+=("lane exit status $status"); }
case "$kind" in
  combined)
    grep -q 'P85 recovery lane complete' "$ev/lane.log" 2>/dev/null || grep -q 'UTB lane: all steps PASSED' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in lane.log"); }
    if [ "$complete" = yes ]; then
      if [ -d "$pub/p85/run/utb" ]; then "$repo/scripts/utb-lane.sh" --check-evidence "$pub/p85/run/utb" >"$pub/ci-check-evidence.txt" 2>&1 || { complete=no; why+=("utb-lane.sh --check-evidence refused the published pack"); }
      else complete=no; why+=("no p85/run/utb pack"); fi
    fi ;;
  overbound)
    grep -q 'P85 recovery lane: all steps PASSED' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in lane.log"); }
    grep -q 'election_refused' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("the over-bound refusal step did not run"); } ;;
  x4shadow)
    grep -q 'X4 shadow lane: all steps PASSED' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in lane.log"); }
    adapter=$pub/p85/run/shadow/adapter
    [ "$(jq -r .status "$adapter/report.json" 2>/dev/null)" = PASS ] || { complete=no; why+=("the shadow adapter's report.json is missing or its status is not PASS"); }
    [ "$(jq -r '.manifest.campaign.intervalSeconds // 0' "$adapter/report.json" 2>/dev/null)" -ge 5400 ] 2>/dev/null || { complete=no; why+=("the report does not declare a 90-minute campaign interval"); }
    ( cd "$adapter" 2>/dev/null && p_sha256 -c SHA256SUMS >/dev/null ) || { complete=no; why+=("the adapter pack's SHA256SUMS do not verify"); } ;;
  abort)
    grep -q 'H6 Abort rehearsal: Abort before H committed' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no Abort-before-H completion line in lane.log"); }
    [ -s "$pub/q3/h6-before-h/abort.status" ] && [ -s "$pub/q3/h6-after-h/abort.status" ] || { complete=no; why+=("the Abort evidence files are missing"); } ;;
  t6)
    grep -q 'PASS: T6 placeholder harness run complete' "$ev/t6-rehearsal.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in t6-rehearsal.log"); }
    head -1 "$ev/run-summary.md" 2>/dev/null | grep -q '^T6 harness rehearsal: PASS' || { complete=no; why+=("run-summary.md does not say PASS"); }
    ! grep -q 'NOT EVIDENCE' "$ev/run-mode.txt" 2>/dev/null || { complete=no; why+=("run-mode.txt marks the run NOT EVIDENCE"); } ;;
  *) complete=no; why+=("unknown kind $kind") ;;
esac
if [ "$complete" = no ]; then
  { echo "INCOMPLETE: this is a failed or partial run's pack, kept for diagnosis. It is NOT acceptance evidence."; printf 'reason: %s\n' "${why[@]}"; } >"$pub/INCOMPLETE.txt"
fi
# 3. SHA256SUMS over the final published directory (INCOMPLETE.txt and the checker output included)
( cd "$pub" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs -I{} bash -c 'source "$0/scripts/lib/portable.sh"; p_sha256 "$1"' "$repo" {} >SHA256SUMS ) 
( cd "$pub" && p_sha256 -c SHA256SUMS >/dev/null ) || { echo "publish-evidence: the checksums of the published directory do not verify" >&2; exit 1; }
# 4. archives, then the secret scan and selection of each archive by the repository's existing pattern
( cd "$ci" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs -I{} bash -c 'source "$0/scripts/lib/portable.sh"; p_sha256 "$1"' "$repo" {} >SHA256SUMS )
( cd "$ci" && p_sha256 -c SHA256SUMS >/dev/null ) || { echo "publish-evidence: the checksums of the CI logs do not verify" >&2; exit 1; }
tar -C "$stage" -czf "$stage/$name.tar.gz" "$name"
tar -C "$stage" -czf "$stage/$name-ci.tar.gz" "$name-ci"
mkdir -p "$out/sel"
# the scan inputs: every secret under --nodes is read by the validator itself; the values of the removed files are sealed into one file
{ sort -u "$vals"; echo '#sealed'; } >"$stage/scan-inputs"
# scan view of an archive: the tree with every .gz / .tgz / .tar.gz member expanded beside it (a secret inside a compressed member is a secret in the archive)
scan_view() { # TREE NAME -> prints the view archive path
  local v=$stage/view-$2 f depth
  rm -rf "$v"; mkdir -p "$v"; rsync -a "$1/" "$v/$2/"
  for depth in 1 2 3; do
    while IFS= read -r f; do
      [ -e "$f.expanded" ] || [ -d "$f.expanded.d" ] && continue
      case "$f" in *.tar.gz|*.tgz) mkdir -p "$f.expanded.d"; tar -xzf "$f" -C "$f.expanded.d" 2>/dev/null || gunzip -c "$f" >"$f.expanded" 2>/dev/null || true ;; *) gunzip -c "$f" >"$f.expanded" 2>/dev/null || true ;; esac
    done < <(find "$v" -type f \( -name '*.gz' -o -name '*.tgz' \) ! -name '*.expanded' 2>/dev/null)
  done
  tar -C "$v" -czf "$stage/view-$2.tar.gz" "$2"; echo "$stage/view-$2.tar.gz"
}
publish_archive() { # NAME MINLOGS -> sets last_rc: 0 published, 1 published incomplete-by-validator, 2 refused
  local n=$1 minlogs_=$2 view rep
  view=$(scan_view "$stage/$n" "$n")
  rep=$(rethEvidenceValidate "$view" "${nodes:-}" "$stage/scan-inputs" 0 SHA256SUMS 2>&1); last_rc=$?
  if [ "$last_rc" -eq 2 ]; then
    mv "$stage/$n.tar.gz" "$quarantine/$n.tar.gz"
    { echo "REJECTED: $n.tar.gz was not published (a recorded secret value, or a secret file or field, is in it, including inside compressed members)."
      echo "It was moved to the quarantine on the machine that ran the lane and was not uploaded. Validation found (file names only, never the values):"
      echo "$rep" | sed "s#$stage/##g"; } >"$out/$n.tar.gz.REJECTED.txt"
    return 2
  fi
  "$repo/scripts/reth-pin.sh" select-upload "${sel[@]}" --min-node-logs "$minlogs_" "$stage/$n.tar.gz"; last_rc=$?
  return "$last_rc"
}
sel=(--out "$out/sel" --quarantine "$quarantine" --require SHA256SUMS)
[ -z "$nodes" ] || sel+=(--nodes "$nodes")
publish_archive "$name" "$minlogs"; scan_rc=$?
publish_archive "$name-ci" 0; scan_ci_rc=$?
cp "$out/sel/"* "$out/" 2>/dev/null; rm -rf "$out/sel"
for a in "$name.tar.gz" "$name-ci.tar.gz"; do [ -f "$out/$a" ] && ( cd "$out" && p_sha256 "$a" >"$a.sha256" ); done
{ echo "evidence $name  complete=$complete ${why[*]:-}"; echo "scan exit evidence=$scan_rc ci-logs=$scan_ci_rc"; ls -l "$out" | awk 'NR>1{print $NF, $5}'; } >"$out/PUBLISH-SUMMARY.txt"
cat "$out/PUBLISH-SUMMARY.txt"
[ "$scan_rc" -eq 0 ] && [ "$scan_ci_rc" -eq 0 ] && { [ "$complete" = yes ] || exit 3; exit 0; }
exit 4
