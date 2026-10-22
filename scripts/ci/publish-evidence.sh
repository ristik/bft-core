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
ev= out= status=0 nodes= minlogs=0 kind=combined s4=0 x4o=0; extra=()
while [ $# -gt 0 ]; do case "$1" in
  --evidence) ev=$2; shift 2 ;; --out) out=$2; shift 2 ;; --status) status=$2; shift 2 ;; --nodes) nodes=$2; shift 2 ;;
  --min-node-logs) minlogs=$2; shift 2 ;; --kind) kind=$2; shift 2 ;; --s4) s4=$2; shift 2 ;; --x4o) x4o=$2; shift 2 ;; --extra) extra+=("$2"); shift 2 ;; *) echo "publish-evidence: unknown argument $1" >&2; exit 2 ;; esac; done
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
  x4rewards)
    grep -q 'X4 rewards lane: all steps PASSED' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in lane.log"); }
    # the pool's whole life replayed against the chain: it ran dry (a zero-budget interval), was refilled, and a later interval was paid; the replay agreed with the chain
    xr=$pub/p85/run/x4pos/steps/xr/replay-after.txt
    line=$(sed -n 's/^REWARDS-REPLAY ok //p' "$xr" 2>/dev/null | tail -n 1)
    [ -n "$line" ] || { complete=no; why+=("no REWARDS-REPLAY ok line in the exhaust-refill step's final replay"); }
    [ "$(jq -r '.refilledAfterExhaustion' <<<"${line:-null}" 2>/dev/null)" = true ] && [ "$(jq -r '.zeroBudget // 0' <<<"${line:-null}" 2>/dev/null)" -ge 1 ] 2>/dev/null \
      && [ "$(jq -r '.paid // 0' <<<"${line:-null}" 2>/dev/null)" -ge 3 ] 2>/dev/null && [ "$(jq -r '.fundings // 0' <<<"${line:-null}" 2>/dev/null)" -ge 1 ] 2>/dev/null \
      || { complete=no; why+=("the replay does not show a dry pool refilled and then paid (zeroBudget >= 1, fundings >= 1, paid >= 3, refilledAfterExhaustion)"); } ;;
  x4exit)
    grep -q 'P85 recovery lane: all steps PASSED' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no completion sentinel in lane.log"); }
    # the exit lifecycle: requested and imported with the proposers' proof lines (latency, tuples), refused early for a lawful reason, matured, claimed with exact amounts
    xs=$pub/p85/run/x4pos/steps
    jq -e '.imported == true and .pRet > 0 and .tRet > 0' "$xs/exit-request/request.json" >/dev/null 2>&1 || { complete=no; why+=("exit-request/request.json does not show an imported Retirement (pRet, tRet)"); }
    grep -q 'retirement proof ready.*latencyMs=' "$xs/exit-request/roots.log" 2>/dev/null || { complete=no; why+=("no 'retirement proof ready' line with latencyMs in exit-request/roots.log"); }
    jq -e '.outcome == "refused" and .lawfulEarly == true and (.expected == "" or .expected == .reason)' "$xs/exit-claim/refusal.json" >/dev/null 2>&1 || { complete=no; why+=("exit-claim/refusal.json: the early mature was not refused for a lawful reason"); }
    if [ "$s4" = 1 ]; then   # the S4 (held offender) variant, keyed on the run's own S4 flag (run-lane passes S4_LANE), not on a directory name: the exit was refused for the evidence hold while the case was admitted and unsettled
      jq -e '.outcome == "refused" and .reason == "EvidenceHoldPending"' "$xs/exit-request/hold-probe.json" >/dev/null 2>&1 || { complete=no; why+=("exit-request/hold-probe.json: no EvidenceHoldPending refusal while the case was admitted"); }
    fi
    jq -e '.creditDelta > 0' "$xs/exit-claim/matured.json" >/dev/null 2>&1 || { complete=no; why+=("exit-claim/matured.json: no credit delta"); }
    jq -e '.received > 0' "$xs/exit-claim/claimed.json" >/dev/null 2>&1 || { complete=no; why+=("exit-claim/claimed.json: nothing claimed"); } ;;
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
if [ "$x4o" = 1 ]; then   # X4 B4: the second offence (a staying member, root4), settled after the recovery with no election result open, one claim for both bounties
  pre=$(find "$pub" -path '*/s4b/pre-submit.json' | head -n 1); post=$(find "$pub" -path '*/s4b/post-settle.json' | head -n 1)
  jq -e '.openResult == "0x0000000000000000000000000000000000000000000000000000000000000000" and .epoch >= 3' "${pre:-/nonexistent}" >/dev/null 2>&1 || { complete=no; why+=("s4b/pre-submit.json: offence 2 was not submitted in epoch 3 with no open election result"); }
  jq -e '.epoch == 3 and .roundAfter > .roundBefore' "${post:-/nonexistent}" >/dev/null 2>&1 || { complete=no; why+=("s4b/post-settle.json: the K assignment does not show epoch 3 advancing after the second admission"); }
  [ -n "$(find "$pub" -path '*/s4b/SHA256SUMS' | head -n 1)" ] || { complete=no; why+=("s4b/SHA256SUMS: the second offence's archive is missing"); }
  grep -q "PASS: x4o: the reporter's credit" "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no 'x4o: the reporter's credit = bounty 1 + bounty 2' line in lane.log"); }
  grep -q 'PASS: s4: the reporter claimed exactly the bounty' "$ev/lane.log" 2>/dev/null || { complete=no; why+=("no exact reporter claim line in lane.log"); }
fi
[ -z "${CI_INTERIM:-}" ] || { complete=no; why+=("INTERIM EXPERIMENT, not acceptance evidence: $CI_INTERIM"); }
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
# scan view of an archive: the tree with every .gz / .tgz / .tar.gz member expanded beside it (a secret inside a compressed member is a secret in the archive).
# FAIL CLOSED: a member the view cannot expand and that is not on the allowlist (any other compression or archive format, found by extension OR by magic bytes), a
# gzip/tgz whose expansion fails (corrupt or truncated), and a gzip still unexpanded after the nesting depth, make the archive unscannable. They are listed in
# $stage/unscannable-NAME (names only) and publish_archive refuses the archive. Formats allowed to stay opaque: none (the lane's artifacts are text, JSON, CBOR and .gz).
opaque_allow=''   # newline-separated archive-relative member paths
unscannable_reason() { # FILE -> prints a reason when FILE is a compression or archive format the view cannot expand, nothing otherwise
  local f=$1 magic
  case "$f" in
    *.zst|*.zstd|*.xz|*.lzma|*.bz2|*.zip|*.7z|*.rar|*.lz4|*.lz|*.Z|*.br|*.tar|*.tbz|*.tbz2|*.txz|*.tzst|*.jar|*.war|*.apk|*.cpio|*.ar|*.deb|*.rpm) echo "archive/compression format by extension"; return ;;
  esac
  magic=$(head -c 6 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  case "$magic" in
    28b52ffd*) echo "zstd by magic bytes" ;;   fd377a585a00) echo "xz by magic bytes" ;;   425a68*) echo "bzip2 by magic bytes" ;;
    504b0304*|504b0506*) echo "zip by magic bytes" ;;   377abcaf271c) echo "7z by magic bytes" ;;   526172211a07*) echo "rar by magic bytes" ;;   04224d18*) echo "lz4 by magic bytes" ;;
    5d0000*) echo "lzma by magic bytes" ;;   1f9d*) echo "compress(1) by magic bytes" ;;
    1f8b*) ;;   # gzip: expanded by scan_view (by magic, whatever the name)
    *) [ "$(head -c 262 "$f" 2>/dev/null | tail -c 5)" = ustar ] && echo "tar by magic bytes" ;;
  esac
}
is_gzip() { [ "$(head -c 2 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = 1f8b ]; }
scan_view() { # TREE NAME -> prints the view archive path; unscannable members are listed in $stage/unscannable-NAME
  local v=$stage/view-$2 f depth why u=$stage/unscannable-$2 rel
  rm -rf "$v"; mkdir -p "$v"; rsync -a "$1/" "$v/$2/"; : >"$u"
  # gzip is expanded by its magic bytes whatever the name, and the output of an expansion is looked at again (a gzip of a gzip, a zstd inside a gzip), up to the depth bound
  for depth in 1 2 3 4 5; do
    while IFS= read -r f; do
      { [ -e "$f.expanded" ] || [ -d "$f.expanded.d" ]; } && continue
      rel=${f#$v/}
      case "$f" in
        *.tar.gz|*.tgz) mkdir -p "$f.expanded.d"
          # a tar.gz is unpacked as an archive; a .tgz that is a plain gzip is expanded as bytes; if neither works the file is unscannable
          if ! tar -xzf "$f" -C "$f.expanded.d" 2>/dev/null; then
            rm -rf "$f.expanded.d"
            gunzip -c "$f" >"$f.expanded" 2>/dev/null || { rm -f "$f.expanded"; echo "$rel: gzip expansion failed (corrupt or truncated)" >>"$u"; }
          fi ;;
        *) gunzip -c "$f" >"$f.expanded" 2>/dev/null || { rm -f "$f.expanded"; echo "$rel: gzip expansion failed (corrupt or truncated)" >>"$u"; } ;;
      esac
    done < <(find "$v" -type f \( -name '*.gz' -o -name '*.tgz' -o -size +0 \) 2>/dev/null | while IFS= read -r g; do
               case "$g" in *.gz|*.tgz) echo "$g" ;; *) is_gzip "$g" && echo "$g" ;; esac; done)
  done
  # everything left in the view (originals and expanded contents alike) that the view cannot read, and a gzip nested deeper than the loop expands
  while IFS= read -r f; do
    rel=${f#$v/}
    why=$(unscannable_reason "$f"); [ -z "$why" ] || { printf '%s\n' "$opaque_allow" | grep -qxF "$rel" || echo "$rel: $why" >>"$u"; }
    if { case "$f" in *.gz|*.tgz) true ;; *) is_gzip "$f" ;; esac; } && [ ! -e "$f.expanded" ] && [ ! -d "$f.expanded.d" ] && ! grep -qF "$rel:" "$u"; then
      echo "$rel: gzip nested deeper than the scan expands" >>"$u"
    fi
  done < <(find "$v" -type f 2>/dev/null)
  sort -u "$u" -o "$u"
  tar -C "$v" -czf "$stage/view-$2.tar.gz" "$2"; echo "$stage/view-$2.tar.gz"
}
publish_archive() { # NAME MINLOGS -> sets last_rc: 0 published, 1 published incomplete-by-validator, 2 refused
  local n=$1 minlogs_=$2 view rep
  view=$(scan_view "$stage/$n" "$n")
  # a --nodes directory that yields no secret value means the save of the devnet's secrets failed: nothing could be searched for, so nothing is published
  if [ -n "${nodes:-}" ] && [ -z "$(rethEvidenceSecretValues "$nodes" 2>/dev/null | tr -d ' \n')" ]; then echo "--nodes $nodes yields no secret values to search for (the secrets were not saved?)" >>"$stage/unscannable-$n"; fi
  if [ -s "$stage/unscannable-$n" ]; then
    # fail closed: what cannot be scanned is not published
    mv "$stage/$n.tar.gz" "$quarantine/$n.tar.gz"
    { echo "REJECTED: $n.tar.gz was not published (it holds members the secret scan cannot read: a compression or archive format it cannot expand, or a corrupt or too deeply nested gzip)."
      echo "It was moved to the quarantine on the machine that ran the lane and was not uploaded. Unscannable members:"
      cat "$stage/unscannable-$n"; } >"$out/$n.tar.gz.REJECTED.txt"
    last_rc=2; return 2
  fi
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
