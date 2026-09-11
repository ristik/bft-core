#!/bin/bash
# reth-pin.sh - the pinned execution client and the evidence archive, shared by every lane that
# packages a real-reth run: scripts/reth-smoke.sh (the smoke lane, locally and in CI) and the
# real-reth-fault workflow (F1c, #90).
#
# DEFINITIONS ONLY. Sourcing this file sets variables and defines functions; it starts nothing,
# changes no directory and installs no trap, so scripts/reth-smoke-selftest.sh can exercise every
# refusal below without reth, a network or a devnet. The same discipline as reth-chaos-lib.sh, for
# the same reason: a self-test that sources executable initialisation tests the wrong thing.
#
# Why this exists as a library rather than inline workflow YAML. #90 asks for the wrong-pin,
# bad-binary, missing-binary, cache-hit and failure-collection paths to be exercised, not read. As
# inline workflow steps they can only run on a hosted runner; here the workflow and a local run
# execute the same functions, and the self-test executes their failure paths deliberately.

# --- the pin ------------------------------------------------------------------------------------
#
# The approved execution client: ristik/ureth branch unicity/main, byte-identical today to upstream
# paradigmxyz/reth tag v2.5.0 at this commit (docs/design/f1-baseline.md §2, §6.4). Every lane's own
# pinnedRethCommit must equal RETH_PIN_COMMIT; the self-test checks that they do.
RETH_PIN_COMMIT=189c0df32617afc488e0f091dbface1bd72cceb4
RETH_PIN_TAG=v2.5.0
RETH_PIN_RELEASE_BASE=https://github.com/paradigmxyz/reth/releases/download/$RETH_PIN_TAG

# rethPinAsset <platform> prints "<asset> <sha256>" for the upstream release artifact of the pinned
# tag, or fails for a platform upstream does not publish. The digests are GitHub's own reported
# asset digests for tag v2.5.0 (recorded in docs/design/f1-baseline.md §6.4), not values computed
# from a download and then trusted.
#
# Only valid while the fork has not diverged: the moment ureth carries its own commits these assets
# stop being the pinned client, and the lane must build from source or publish its own artifact with
# equivalent provenance.
rethPinAsset() {
  case "$1" in
    linux-x86_64)  echo "reth-v2.5.0-x86_64-unknown-linux-gnu.tar.gz 6719ec675744c279dadab1269a15b3afb6ed153839aa87ccad7c2d119d48f47f" ;;
    linux-aarch64) echo "reth-v2.5.0-aarch64-unknown-linux-gnu.tar.gz 47fcc3899095ca469efc986720240c7eadd08730f200fae1095f6c5da6625c3d" ;;
    darwin-arm64)  echo "reth-v2.5.0-aarch64-apple-darwin.tar.gz 0a43ae8566515d53e43e21cdfc8f88c28aea33aa4ad931f5a61b94d5067cf202" ;;
    *) return 1 ;;
  esac
}

# rethPinPlatform prints this host's platform key in rethPinAsset's vocabulary.
rethPinPlatform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) [ "$os" = darwin ] && arch=arm64 || arch=aarch64 ;;
  esac
  echo "$os-$arch"
}

rethPinSha256() { # rethPinSha256 <file>
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# rethPinErr prints a refusal to stderr. Every refusal starts "reth-pin: " so a caller, a log reader
# and the self-test can tell this library's verdicts from anything else on stderr.
rethPinErr() { echo "reth-pin: $*" >&2; }

# rethPinRunBounded <seconds> <cmd...> runs cmd with a hard budget, prints its combined output, and
# returns its status (124 if the budget was hit). `timeout` is not on every host this runs on (macOS
# has none), and a binary that hangs on --version must be a refusal, not a stalled lane.
#
# The budget bounds the whole command, not just its first process. cmd runs as the leader of its own
# process group (perl's setpgrp, then exec) and the budget kills that group, so a shell script whose
# child does the hanging dies with it. Its output goes to a file, never to the caller's pipe: an
# earlier revision let the command inherit the $(...) pipe, killed only the direct child, and the
# caller then waited for a surviving grandchild to close the pipe — a 1-second budget took 4.4s
# against `sleep 4`, and would have taken forever against a hang.
rethPinRunBounded() {
  local budget=$1 pid i out rc
  shift
  out=$(mktemp) || return 1
  perl -e 'setpgrp(0, 0); exec @ARGV or die "exec $ARGV[0]: $!\n"' -- "$@" >"$out" 2>&1 </dev/null &
  pid=$!
  rc=124
  for ((i = 0; i < budget * 10; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"; rc=$?
      break
    fi
    sleep 0.1
  done
  if [ "$rc" -eq 124 ]; then
    kill -KILL -- "-$pid" 2>/dev/null
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  fi
  cat "$out"
  rm -f "$out"
  return $rc
}

# rethPinVerifyBinary <path> [expected-commit] succeeds only if <path> is an executable that runs and
# reports exactly the expected commit (default RETH_PIN_COMMIT). This is the check that runs on
# EVERY path — fresh download, cache hit, operator-supplied binary — because it is the only one that
# asks the binary itself. A cache, a tag or a file name is never the authority.
rethPinVerifyBinary() {
  local bin=$1 want=${2:-$RETH_PIN_COMMIT} out status got
  if [ -z "$bin" ] || [ ! -e "$bin" ]; then
    rethPinErr "no reth binary at '${bin}' — this lane has no fake fallback"
    return 1
  fi
  if [ ! -f "$bin" ] || [ ! -x "$bin" ]; then
    rethPinErr "'$bin' is not an executable file"
    return 1
  fi
  out=$(rethPinRunBounded "${RETH_PIN_VERSION_BUDGET:-30}" "$bin" --version)
  status=$?
  if [ "$status" -ne 0 ]; then
    rethPinErr "'$bin --version' failed (exit $status): $(echo "$out" | head -1)"
    return 1
  fi
  got=$(echo "$out" | sed -n 's/^Commit SHA: //p' | head -1)
  if [ -z "$got" ]; then
    rethPinErr "'$bin --version' reports no 'Commit SHA:' line, so its revision cannot be verified"
    return 1
  fi
  if [ "$got" != "$want" ]; then
    rethPinErr "'$bin' reports commit $got, pinned is $want"
    return 1
  fi
  echo "reth-pin: verified $bin reports the pinned commit $got"
}

# rethPinObtain <cache-dir> <dest-dir> <asset> <sha256> <base-url> [expected-commit]
#
# Leaves a verified binary at <dest-dir>/reth, or fails having left nothing usable there.
# Sets RETH_PIN_CACHE_STATE to "hit" or "miss" and RETH_PIN_ARCHIVE to the cached archive's path.
#
# The cache holds the downloaded ARCHIVE, not the extracted binary, so its digest is re-checked on
# every hit — a hit is re-verified exactly as thoroughly as a download. A cached archive whose digest
# no longer matches is refused and left in place: silently re-downloading would hide whatever changed
# it, and the pin must fail visibly. Delete the file to refetch.
rethPinObtain() {
  local cacheDir=$1 destDir=$2 asset=$3 want=$4 base=$5 commit=${6:-$RETH_PIN_COMMIT}
  local archive=$cacheDir/$asset got tmp
  RETH_PIN_CACHE_STATE=
  RETH_PIN_ARCHIVE=$archive
  mkdir -p "$cacheDir" "$destDir" || { rethPinErr "cannot create $cacheDir or $destDir"; return 1; }
  rm -f "$destDir/reth"

  if [ -f "$archive" ]; then
    RETH_PIN_CACHE_STATE=hit
    got=$(rethPinSha256 "$archive")
    if [ "$got" != "$want" ]; then
      rethPinErr "cached $asset has sha256 $got, pinned is $want — refusing the cache hit (not refetching: whatever changed it should be seen). Delete $archive to refetch."
      return 1
    fi
    echo "reth-pin: cache hit, $asset digest re-verified ($got)"
  else
    RETH_PIN_CACHE_STATE=miss
    tmp=$archive.partial.$$
    echo "reth-pin: cache miss, fetching $base/$asset"
    if ! curl -fsSL --max-time 600 -o "$tmp" "$base/$asset"; then
      rm -f "$tmp"
      rethPinErr "download of $base/$asset failed"
      return 1
    fi
    got=$(rethPinSha256 "$tmp")
    if [ "$got" != "$want" ]; then
      rm -f "$tmp"
      rethPinErr "downloaded $asset has sha256 $got, pinned is $want — refused, nothing cached"
      return 1
    fi
    mv "$tmp" "$archive" || { rethPinErr "cannot move the verified archive into $cacheDir"; return 1; }
    echo "reth-pin: fetched and digest-verified $asset ($got)"
  fi

  if ! tar xzf "$archive" -C "$destDir" reth 2>/dev/null || [ ! -f "$destDir/reth" ]; then
    rm -f "$destDir/reth"
    rethPinErr "$asset contains no top-level 'reth' binary"
    return 1
  fi
  chmod +x "$destDir/reth"
  if ! rethPinVerifyBinary "$destDir/reth" "$commit"; then
    rm -f "$destDir/reth"
    return 1
  fi
}

# rethPinObtainPinned <cache-dir> <dest-dir> [platform] obtains the pinned release artifact for this
# (or the named) platform. Upstream publishes no x86_64 macOS asset for v2.5.0, so on such a host
# this refuses and names the alternative: a binary built from the pinned commit, verified by revision.
rethPinObtainPinned() {
  local platform=${3:-$(rethPinPlatform)} entry
  if ! entry=$(rethPinAsset "$platform"); then
    rethPinErr "no pinned release artifact for platform '$platform' (upstream $RETH_PIN_TAG publishes linux-x86_64, linux-aarch64 and darwin-arm64). Use --reth-bin with a binary built from $RETH_PIN_COMMIT; it is verified by the revision it reports."
    return 1
  fi
  RETH_PIN_ASSET=${entry%% *}
  RETH_PIN_SHA256=${entry##* }
  rethPinObtain "$1" "$2" "$RETH_PIN_ASSET" "$RETH_PIN_SHA256" "$RETH_PIN_RELEASE_BASE"
}

# --- evidence -----------------------------------------------------------------------------------

# rethEvidenceCollect <nodes-dir> <out-dir> copies what a failed run is diagnosed from: every node's
# logs and configuration, the shard conf, trust base and genesis files. Secrets are excluded BY
# CONSTRUCTION — keys.json and jwt.hex are never copied — and reth datadirs (directories) are not
# copied at all. rethEvidenceValidate then checks the result independently, rather than trusting
# this function to have been right.
#
# Every copy it attempts is required: a directory it cannot create or a file it cannot copy is
# named on stdout and makes it return nonzero, having still copied everything else it could. A
# collector that swallowed those failures once reported success for a collection that had silently
# dropped a node's log, and the archive then validated because ANOTHER node's log met the minimum
# log count. A log count is not a completeness check; this status is.
rethEvidenceCollect() {
  local nodes=$1 out=$2 d f name n=0 failed=0
  mkdir -p "$out" || { echo "reth-evidence: FAIL cannot create $out — nothing collected"; return 1; }
  [ -d "$nodes" ] || { echo "reth-evidence: no $nodes directory — the run produced no node state to collect"; return 0; }
  for d in "$nodes"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    if ! mkdir -p "$out/$name" 2>/dev/null || [ ! -d "$out/$name" ]; then
      echo "reth-evidence: FAIL cannot create $out/$name — every file of $name is missing from the collection"
      failed=$((failed + 1))
      continue
    fi
    for f in "$d"*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in keys.json | jwt.hex | pid | *.key) continue ;; esac
      if cp "$f" "$out/$name/" 2>/dev/null; then n=$((n + 1)); else echo "reth-evidence: FAIL could not copy $f"; failed=$((failed + 1)); fi
    done
  done
  for f in "$nodes"/*.json "$nodes"/*.log; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in keys.json) continue ;; esac
    if cp "$f" "$out/" 2>/dev/null; then n=$((n + 1)); else echo "reth-evidence: FAIL could not copy $f"; failed=$((failed + 1)); fi
  done
  if [ "$failed" -ne 0 ]; then
    echo "reth-evidence: FAIL collection incomplete — $n file(s) copied from $nodes, $failed required cop(ies) failed"
    return 1
  fi
  echo "reth-evidence: collected $n file(s) from $nodes"
}

# rethEvidenceValidate <archive> <nodes-dir|""> <min-node-logs> [required-name...]
#
# Checks an evidence archive is readable, carries every required file (by base name, anywhere in the
# archive — the smoke lane requires provenance.txt and run.log, the fault lane reth-chaos's
# manifest.txt), holds at least <min-node-logs> shard/root/reth logs, and contains no secret: by name
# (keys.json, jwt.hex, *.key), by content (any "privateKey" field), and by value — every jwt.hex and
# private key found under <nodes-dir> is searched for verbatim, so a secret that leaked into a log
# line is caught too. It is deliberately independent of the collector: it re-reads the archive rather
# than trusting what was meant to be copied.
#
# Exit status separates the two questions a caller asks of an archive:
#   0  validated: complete and secret-free
#   1  incomplete but secret-free: a required file or node log is missing, and it is still safe to
#      publish — a failed run's partial evidence is exactly what must reach whoever diagnoses it
#   2  NOT publishable: a secret was found, or the archive is missing, unreadable or does not
#      extract, so its contents cannot be vouched for
# rethEvidenceSelect publishes on 0 and 1 and quarantines on 2.
rethEvidenceValidate() {
  local archive=$1 nodes=${2:-} minLogs=${3:-0} tmp bad=0 unsafe=0 names v logs req
  shift 3 2>/dev/null || shift $#
  if [ ! -s "$archive" ]; then echo "reth-evidence: FAIL archive $archive is missing or empty"; return 2; fi
  if ! names=$(tar tzf "$archive" 2>/dev/null); then echo "reth-evidence: FAIL archive $archive is unreadable"; return 2; fi
  tmp=$(mktemp -d) || return 2
  if ! tar xzf "$archive" -C "$tmp" 2>/dev/null; then
    echo "reth-evidence: FAIL archive $archive does not extract"; rm -rf "$tmp"; return 2
  fi

  for req in "$@"; do
    echo "$names" | grep -qE "(^|/)${req//./\\.}\$" || { echo "reth-evidence: FAIL no $req in $archive"; bad=1; }
  done
  if echo "$names" | grep -qE '(^|/)(keys\.json|jwt\.hex|[^/]*\.key)$'; then
    echo "reth-evidence: FAIL secret file(s) in archive: $(echo "$names" | grep -E '(^|/)(keys\.json|jwt\.hex|[^/]*\.key)$' | tr '\n' ' ')"
    unsafe=1
  fi
  if grep -rlq '"privateKey"' "$tmp" 2>/dev/null; then
    echo "reth-evidence: FAIL a \"privateKey\" field appears in: $(grep -rl '"privateKey"' "$tmp" | sed "s|$tmp/||" | tr '\n' ' ')"
    unsafe=1
  fi
  if [ -n "$nodes" ] && [ -d "$nodes" ]; then
    while IFS= read -r v; do
      [ -n "$v" ] || continue
      if grep -rlqF -- "$v" "$tmp" 2>/dev/null; then
        echo "reth-evidence: FAIL a secret value from $nodes appears verbatim in: $(grep -rlF -- "$v" "$tmp" | sed "s|$tmp/||" | tr '\n' ' ')"
        unsafe=1
      fi
    done < <(rethEvidenceSecretValues "$nodes")
  fi
  logs=$(echo "$names" | grep -cE '(debug|reth)[^/]*\.log$')
  if [ "$logs" -lt "$minLogs" ]; then
    echo "reth-evidence: FAIL $archive holds $logs node log(s), at least $minLogs required — an archive without the logs is not useful evidence"
    bad=1
  fi
  rm -rf "$tmp"
  if [ "$unsafe" -ne 0 ]; then
    echo "reth-evidence: $archive is NOT publishable: it contains a secret"
    return 2
  fi
  [ "$bad" -eq 0 ] || return 1
  echo "reth-evidence: archive $archive validated: ${*:-no required files}, $logs node log(s), no secret by name, field or value"
}

# rethEvidenceSelect <out-dir> <quarantine-dir> <nodes-dir|""> <min-node-logs> <required-names> <archive...>
#
# Decides, per archive, what may be published, and puts exactly that into <out-dir> — the only
# directory a workflow uploads. <required-names> is one space-separated word list.
#
#   validated, or incomplete but secret-free  -> copied into <out-dir>, its validation report beside it
#   not publishable (secret, unreadable, ...) -> MOVED into <quarantine-dir>, never uploaded; a
#                                                <name>.REJECTED.txt diagnostic is published instead,
#                                                naming what was found where, never the value
#   missing                                   -> recorded as missing
#
# <out-dir>/MANIFEST.txt records every verdict with the archive's sha256. The published directory is
# then scanned once more for every secret value, so a diagnostic cannot carry what it reports. Returns
# nonzero if anything was rejected or missing (a secret in the evidence is itself a failure), zero if
# everything given was published.
#
# Why this exists: validation used to set a failure status and leave the archive where it was, and
# the workflow uploaded that path with always() — so a job would have published the very archive it
# had just found a JWT in.
rethEvidenceSelect() {
  local out=$1 quar=$2 nodes=$3 minLogs=$4 required=$5 a name report rc sha verdict v bad=0 n=0
  shift 5
  mkdir -p "$out" "$quar" || { echo "reth-evidence: FAIL cannot create $out or $quar"; return 1; }
  chmod 700 "$quar" 2>/dev/null
  : >>"$out/MANIFEST.txt"
  [ $# -gt 0 ] || { echo "(no archive was given)" >>"$out/MANIFEST.txt"; echo "reth-evidence: FAIL no archive to select"; return 1; }
  for a in "$@"; do
    name=$(basename "$a")
    if [ ! -e "$a" ]; then
      echo "$name MISSING — no archive at $a" >>"$out/MANIFEST.txt"
      echo "reth-evidence: FAIL no archive at $a — nothing to publish for it"
      bad=1
      continue
    fi
    # shellcheck disable=SC2086 # required is a word list by contract
    report=$(rethEvidenceValidate "$a" "$nodes" "$minLogs" $required 2>&1); rc=$?
    sha=$(rethPinSha256 "$a")
    if [ "$rc" -le 1 ]; then
      verdict=validated; [ "$rc" -eq 1 ] && verdict="incomplete, secret-free"
      if cp "$a" "$out/$name" && echo "$report" >"$out/$name.validation.txt"; then
        echo "$name sha256=$sha published ($verdict)" >>"$out/MANIFEST.txt"
        echo "reth-evidence: publishing $name ($verdict)"
        n=$((n + 1))
      else
        rm -f "$out/$name" "$out/$name.validation.txt"
        echo "$name sha256=$sha NOT published — could not be copied into $out" >>"$out/MANIFEST.txt"
        echo "reth-evidence: FAIL could not copy $name into $out"
        bad=1
      fi
    else
      if ! mv "$a" "$quar/$name"; then
        # It stays where it is — which is never the upload directory — but say so loudly.
        echo "reth-evidence: FAIL could not move rejected $a into $quar; it is NOT in $out, and must not be shared"
      fi
      {
        echo "REJECTED: $name (sha256 $sha) was not published."
        echo "It was moved to $quar/$name on the machine that ran the lane, and was not uploaded."
        echo "Validation found:"
        echo "$report"
      } >"$out/$name.REJECTED.txt"
      echo "$name sha256=$sha REJECTED — quarantined, not published; see $name.REJECTED.txt" >>"$out/MANIFEST.txt"
      echo "reth-evidence: FAIL $name is not publishable — quarantined in $quar, a diagnostic published instead"
      bad=1
    fi
  done
  if [ -n "$nodes" ] && [ -d "$nodes" ]; then
    while IFS= read -r v; do
      [ -n "$v" ] || continue
      if grep -rlqF -- "$v" "$out" 2>/dev/null; then
        echo "reth-evidence: FAIL a secret value appears in the upload directory itself: $(grep -rlF -- "$v" "$out" | tr '\n' ' ') — removed"
        grep -rlF -- "$v" "$out" | while IFS= read -r f; do rm -f "$f"; done
        bad=1
      fi
    done < <(rethEvidenceSecretValues "$nodes")
  fi
  echo "reth-evidence: $n archive(s) published to $out; see $out/MANIFEST.txt"
  return $bad
}

# rethEvidenceSecretValues <nodes-dir> prints, one per line, every JWT secret and private key found
# under <nodes-dir>, without 0x prefixes, for rethEvidenceValidate's verbatim search.
rethEvidenceSecretValues() {
  local f
  for f in "$1"/*/jwt.hex; do [ -f "$f" ] && tr -d ' \n' <"$f" && echo; done
  for f in "$1"/*/keys.json "$1"/keys.json; do
    [ -f "$f" ] || continue
    python3 -c 'import json,sys
def walk(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if k=="privateKey" and isinstance(v,str): print(v[2:] if v.startswith("0x") else v)
            else: walk(v)
walk(json.load(open(sys.argv[1])))' "$f" 2>/dev/null
  done
}
