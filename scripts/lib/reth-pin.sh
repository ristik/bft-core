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

# --- the fork pin: unicity-reth, built from a pinned commit -------------------------------------
#
# The stock pin above stays exactly as it is, and the two coexist rather than one replacing the
# other: scripts/reth-baseline.sh measures STOCK-client header economics and must keep getting
# upstream reth, while the paired lanes need the fork's seal-capable binary. They are different
# clients and a lane that needs the fork must ask for it by name.
#
# ureth diverged from upstream at ureth #4, so the v2.5.0 release assets the stock pin downloads are
# no longer the fork. The fork's seal-capable node is bin/unicity-reth, added by ureth #30; the pin
# is a COMMIT and is repinned only by an explicit edit to URETH_PIN_COMMIT here when that PR merges.
# Nothing follows a branch: a pin that moves on its own is not a pin.
URETH_PIN_REPO=https://github.com/ristik/ureth
URETH_PIN_COMMIT=0e0ce6dbd83f82340487e82c17393a405d547d73
URETH_PIN_BIN=unicity-reth

# The fee collector every Unicity lane passes. A test devnet needs a fixed, obviously-not-real
# address: the zero address is a real burn destination and any plausible address could be someone's,
# so this is the conventional ...dead placeholder, defined once so every lane agrees on it.
URETH_PIN_FEE_COLLECTOR=0x000000000000000000000000000000000000dead

# The sibling ureth checkout to prefer when it is usable at the pinned commit, instead of cloning a
# second copy. Overridable so the self-test can point at a stand-in; computed relative to this
# library rather than hardcoded, and in a subshell so sourcing this file changes no directory.
URETH_PIN_LOCAL=${URETH_PIN_LOCAL:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." 2>/dev/null && pwd)/ureth}

# urethPinErr prints a refusal to stderr. Every refusal starts "ureth-pin: " so a reader and the
# self-test can tell this library's verdicts from the stock pin's and from anything else on stderr,
# matching rethPinErr's rule.
urethPinErr() { echo "ureth-pin: $*" >&2; }

# urethPinVerifyBinary <path> [expected-commit] succeeds only if <path> is an executable that runs and
# reports exactly the expected commit (default URETH_PIN_COMMIT). It is rethPinVerifyBinary's check for
# the fork binary and for the same reason: the binary itself is the only authority on its revision.
# unicity-reth --version prints reth's long version, whose "Commit SHA:" line carries the full 40-hex
# commit, so this parses exactly the line the stock check parses.
urethPinVerifyBinary() {
  local bin=$1 want=${2:-$URETH_PIN_COMMIT} out status got
  if [ -z "$bin" ] || [ ! -e "$bin" ]; then
    urethPinErr "no $URETH_PIN_BIN binary at '${bin}'"
    return 1
  fi
  if [ ! -f "$bin" ] || [ ! -x "$bin" ]; then
    urethPinErr "'$bin' is not an executable file"
    return 1
  fi
  out=$(rethPinRunBounded "${RETH_PIN_VERSION_BUDGET:-30}" "$bin" --version)
  status=$?
  if [ "$status" -ne 0 ]; then
    urethPinErr "'$bin --version' failed (exit $status): $(echo "$out" | head -1)"
    return 1
  fi
  got=$(echo "$out" | sed -n 's/^Commit SHA: //p' | head -1)
  if [ -z "$got" ]; then
    urethPinErr "'$bin --version' reports no 'Commit SHA:' line, so its revision cannot be verified"
    return 1
  fi
  if [ "$got" != "$want" ]; then
    urethPinErr "'$bin' reports commit $got, pinned is $want"
    return 1
  fi
  echo "ureth-pin: verified $bin reports the pinned commit $got"
}

# urethPinCacheEntry <cache-dir> [commit] [platform] prints where the built binary is cached. The
# path carries BOTH the commit and the platform, so a binary built for another commit or another
# platform is a different path — a miss, never a hit.
urethPinCacheEntry() {
  local cacheDir=$1 commit=${2:-$URETH_PIN_COMMIT} platform=${3:-$(rethPinPlatform)}
  echo "$cacheDir/$URETH_PIN_BIN-$commit-$platform"
}

# urethPinUnicityFlags prints the --unicity.* flags a lane must pass. Only the required one is here:
# --unicity.fee-collector has no default (a zero address would silently burn fees), while the profile
# flags default to the kernel's pinned profile and must stay at those defaults so a lane measures the
# configured profile rather than a lane-local one.
urethPinUnicityFlags() {
  echo "--unicity.fee-collector $URETH_PIN_FEE_COLLECTOR"
}

# urethPinObtain <cache-dir> <dest-dir>
#
# Leaves a release unicity-reth built from URETH_PIN_COMMIT at <dest-dir>/unicity-reth, or fails
# having left nothing usable there. Sets URETH_PIN_CACHE_STATE to "hit" or "miss" and
# URETH_PIN_BINARY to the destination path.
#
# Release, not debug: these lanes have real T2 timing budgets and a debug client would change what
# they measure. The build is slow, which is exactly why the cache is keyed by commit and platform
# and why a sibling checkout already at the pinned commit is preferred to cloning a second copy.
#
# Every refusal starts "ureth-pin: ". The source is never taken on trust: whichever checkout
# produced the binary, the binary must report the pinned commit before it is accepted or cached.
urethPinObtain() {
  local cacheDir=$1 destDir=$2
  local platform commit cache dest src="" built worktree=""
  commit=$URETH_PIN_COMMIT
  platform=$(rethPinPlatform)
  cache=$(urethPinCacheEntry "$cacheDir" "$commit" "$platform")
  dest=$destDir/$URETH_PIN_BIN
  URETH_PIN_CACHE_STATE=
  URETH_PIN_BINARY=$dest

  mkdir -p "$cacheDir" "$destDir" || { urethPinErr "cannot create $cacheDir or $destDir"; return 1; }
  rm -f "$dest"

  if [ -f "$cache" ]; then
    URETH_PIN_CACHE_STATE=hit
    # Re-verify on every hit, exactly as rethPinObtain re-verifies a cached archive's digest. A cache
    # entry that does not report the pinned commit is refused loudly and left in place: silently
    # rebuilding would hide whatever changed it. Delete the entry to rebuild.
    if ! urethPinVerifyBinary "$cache" "$commit"; then
      urethPinErr "cached $cache is not the pinned $URETH_PIN_BIN — refusing the cache hit (not rebuilding: whatever changed it should be seen). Delete $cache to rebuild."
      return 1
    fi
    cp "$cache" "$dest" || { urethPinErr "cannot place the cached binary at $dest"; return 1; }
    chmod +x "$dest"
    echo "ureth-pin: cache hit, $URETH_PIN_BIN at $commit ($platform)"
    return 0
  fi

  URETH_PIN_CACHE_STATE=miss

  # Prefer the sibling checkout when it can produce the pinned commit — but never by checking it
  # out. That is somebody's working tree: detaching its HEAD to build a pinned commit would move a
  # developer off their branch as a side effect of running a lane, and leave them detached
  # afterwards. Add a throwaway worktree instead, which shares the object store (so this stays much
  # cheaper than a clone) while the real checkout keeps its branch, its index and its HEAD.
  #
  # If the checkout exists but cannot produce the commit, say so and fall back to fetching: building
  # whatever that checkout happens to be at and calling it pinned is the one failure this function
  # exists to prevent.
  if [ -n "$URETH_PIN_LOCAL" ] && [ -d "$URETH_PIN_LOCAL/.git" ]; then
    if git -C "$URETH_PIN_LOCAL" cat-file -e "$commit^{commit}" 2>/dev/null; then
      src=$cacheDir/$URETH_PIN_BIN-wt-$commit
      worktree=$src
      if [ ! -d "$src" ]; then
        echo "ureth-pin: adding a worktree for $commit from the local checkout $URETH_PIN_LOCAL"
        if ! git -C "$URETH_PIN_LOCAL" worktree add --detach "$src" "$commit" >/dev/null 2>&1; then
          urethPinErr "local checkout $URETH_PIN_LOCAL has $commit but a worktree for it could not be added; falling back to fetching $URETH_PIN_REPO"
          src=""
        fi
      fi
    else
      urethPinErr "local checkout $URETH_PIN_LOCAL does not contain the pinned commit $commit — falling back to fetching $URETH_PIN_REPO"
    fi
  else
    # Say so rather than quietly cloning. A mistyped or mis-derived path costs a network clone and a
    # cold build every time, and the only symptom is slowness — which is how a wrong path survived
    # this function's first review.
    echo "ureth-pin: no usable local checkout at $URETH_PIN_LOCAL, fetching $URETH_PIN_REPO instead"
  fi

  if [ -z "$src" ]; then
    src=$cacheDir/$URETH_PIN_BIN-src-$commit
    if [ -d "$src/.git" ]; then
      if ! git -C "$src" cat-file -e "$commit^{commit}" 2>/dev/null; then
        urethPinErr "cached checkout $src does not contain the pinned commit $commit — delete it to refetch"
        return 1
      fi
      if ! git -C "$src" checkout --detach "$commit" >/dev/null 2>&1; then
        urethPinErr "cached checkout $src could not be checked out at $commit"
        return 1
      fi
    else
      rm -rf "$src"
      echo "ureth-pin: fetching $URETH_PIN_REPO at $commit"
      if ! git clone --quiet "$URETH_PIN_REPO" "$src" 2>/dev/null; then
        rm -rf "$src"
        urethPinErr "cannot clone $URETH_PIN_REPO"
        return 1
      fi
      if ! git -C "$src" checkout --detach "$commit" >/dev/null 2>&1; then
        rm -rf "$src"
        urethPinErr "the checkout of $URETH_PIN_REPO has no commit $commit"
        return 1
      fi
    fi
  fi

  # Build into a cache-local target directory, never the source tree's own. Two reasons: a worktree
  # or clone under the cache must not have a developer's checkout write 2 GB of release artifacts
  # into it, and keying the target directory to the cache rather than the commit lets successive
  # pins share compilation work instead of rebuilding reth from scratch each time.
  echo "ureth-pin: building $URETH_PIN_BIN from $src (cargo build --release -p $URETH_PIN_BIN)"
  if ! ( cd "$src" && CARGO_TARGET_DIR=$cacheDir/target cargo build --release -p "$URETH_PIN_BIN" ); then
    urethPinErr "cargo build --release -p $URETH_PIN_BIN failed in $src"
    return 1
  fi
  built=$cacheDir/target/release/$URETH_PIN_BIN
  if [ ! -x "$built" ]; then
    urethPinErr "the build reported success but $built is not an executable"
    return 1
  fi
  if ! urethPinVerifyBinary "$built" "$commit"; then
    return 1
  fi
  cp "$built" "$cache" || { urethPinErr "cannot cache the built binary at $cache"; return 1; }
  cp "$built" "$dest" || { urethPinErr "cannot place the built binary at $dest"; return 1; }
  chmod +x "$dest"

  # Drop the throwaway worktree now the binary is cached. It is only needed once per pin, and
  # leaving it registered would litter the developer's checkout with entries that need
  # `git worktree prune` the moment the lane's cache directory is deleted. Failing to remove it is
  # not a failure of the obtain: the binary is already built, verified and cached.
  if [ -n "$worktree" ] && [ -d "$worktree" ]; then
    git -C "$URETH_PIN_LOCAL" worktree remove --force "$worktree" >/dev/null 2>&1 ||
      urethPinErr "note: could not remove the temporary worktree $worktree (run 'git -C $URETH_PIN_LOCAL worktree prune')"
  fi

  echo "ureth-pin: built and cached $URETH_PIN_BIN at $commit ($platform)"
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

# --- scan inputs: every secret an archive must be searched for ------------------------------------
#
# The by-value check can only search for secrets it knows. A lane that REPLACES its cluster destroys
# that cluster's JWTs and keys while its logs stay in the evidence: the fault lane rebuilds a cluster
# per scenario, and the smoke lane's stock control runs before the paired devnet wipes test-nodes/.
# Searching only the secrets left at the end once let a first cluster's leaked JWT through selection
# as "validated". So every lane RECORDS each secret before any process can use it, into a private
# scan-inputs file that lives outside every archive and every upload path:
#
#   <archive's directory>/.scan-inputs/<archive name without .tar.gz>.scan    (directory 700, file 600)
#
# One value per line, plus '#' lines. A capture that fails is written "#failed <what>"; the
# supervisor appends "#sealed" as the LAST line only if nothing failed. Validation with scan inputs
# requires exactly that: a missing, failed, unsealed or later-appended file never reads as secret-free.

# rethScanInputsPath <archive> prints the scan-inputs file that belongs to <archive>.
rethScanInputsPath() {
  local b; b=$(basename "$1")
  echo "$(dirname "$1")/.scan-inputs/${b%.tar.gz}.scan"
}

# rethScanInputsInit <scan-file> creates it empty and private (truncating a stale one).
rethScanInputsInit() {
  ( umask 077; mkdir -p "$(dirname "$1")" && chmod 700 "$(dirname "$1")" && : >"$1" ) 2>/dev/null ||
    { echo "reth-evidence: FAIL cannot create scan inputs $1"; return 1; }
}

# rethScanInputsRecord <scan-file> <value...> appends each value and confirms it is there. It creates
# the file (privately) if needed.
rethScanInputsRecord() {
  local f=$1 v; shift
  [ -f "$f" ] || rethScanInputsInit "$f" || return 1
  for v in "$@"; do
    [ -n "$v" ] || continue
    ( umask 077; printf '%s\n' "$v" >>"$f" ) 2>/dev/null || { echo "reth-evidence: FAIL cannot append to scan inputs $f"; return 1; }
    grep -qxF -- "$v" "$f" || { echo "reth-evidence: FAIL a value did not reach scan inputs $f"; return 1; }
  done
}

# rethScanInputsCapture <nodes-dir> <scan-file> records every secret now under <nodes-dir>. Fails if
# any of them cannot be read (a keys.json that does not parse is a secret that cannot be recorded).
rethScanInputsCapture() {
  local vals v n=0
  local -a all=()
  vals=$(rethEvidenceSecretValues "$1") || { echo "reth-evidence: FAIL cannot read every secret under $1"; return 1; }
  while IFS= read -r v; do [ -n "$v" ] && { all+=("$v"); n=$((n + 1)); }; done <<<"$vals"
  rethScanInputsRecord "$2" ${all[@]+"${all[@]}"} || return 1
  echo "reth-evidence: recorded $n secret value(s) from $1 as scan inputs"
}

rethScanInputsFail() { ( umask 077; printf '#failed %s\n' "$2" >>"$1" ) 2>/dev/null; return 0; }

# rethScanInputsSeal <scan-file> appends "#sealed", unless a capture failed.
rethScanInputsSeal() {
  local f=$1
  [ -f "$f" ] || { echo "reth-evidence: FAIL no scan inputs at $f to seal"; return 1; }
  if grep -q '^#failed' "$f"; then
    echo "reth-evidence: FAIL scan inputs $f record a failed capture ($(grep '^#failed' "$f" | tr '\n' ';')) — not sealed"
    return 1
  fi
  ( umask 077; echo '#sealed' >>"$f" ) 2>/dev/null || { echo "reth-evidence: FAIL cannot seal $f"; return 1; }
  echo "reth-evidence: scan inputs sealed: $(grep -vc '^#' "$f") value(s) in $f"
}

# rethScanInputsCheck <scan-file> succeeds only for a sealed file with no failed capture.
rethScanInputsCheck() {
  local f=$1
  [ -f "$f" ] || { echo "reth-evidence: FAIL scan inputs $f are missing — the secrets of any replaced cluster are unknown"; return 1; }
  grep -q '^#failed' "$f" && { echo "reth-evidence: FAIL scan inputs $f record a failed capture"; return 1; }
  [ "$(tail -n 1 "$f")" = "#sealed" ] || { echo "reth-evidence: FAIL scan inputs $f are not sealed (or were appended to after sealing)"; return 1; }
  return 0
}

# rethEvidenceValidate <archive> <nodes-dir|""> <scan-file|""> <min-node-logs> [required-name...]
#
# Checks an evidence archive is readable, carries every required file (by base name, anywhere in the
# archive — the smoke lane requires provenance.txt and run.log, the fault lane reth-chaos's
# manifest.txt), holds at least <min-node-logs> shard/root/reth logs, and contains no secret: by name
# (keys.json, jwt.hex, *.key, *.scan), by content (any "privateKey" field), and by value — every JWT
# and private key under <nodes-dir> AND every value in <scan-file> (see "scan inputs") is searched for
# verbatim in every file, aggregate logs included, so a secret that leaked into a log line is caught
# even after its cluster was replaced. It is deliberately independent of the collector: it re-reads
# the archive rather than trusting what was meant to be copied.
#
# Exit status separates the two questions a caller asks of an archive:
#   0  validated: complete and secret-free
#   1  incomplete but secret-free: a required file or node log is missing, and it is still safe to
#      publish — a failed run's partial evidence is exactly what must reach whoever diagnoses it
#   2  NOT publishable: a secret was found; or the archive is missing, unreadable or does not
#      extract; or the secrets it must be searched for cannot all be known (unreadable secrets, or
#      scan inputs missing, failed or unsealed) — in each case its contents cannot be vouched for
# rethEvidenceSelect publishes on 0 and 1 and quarantines on 2.
rethEvidenceValidate() {
  local archive=$1 nodes=${2:-} scan=${3:-} minLogs=${4:-0} tmp bad=0 unsafe=0 names v vals logs req
  shift 4 2>/dev/null || shift $#
  if [ ! -s "$archive" ]; then echo "reth-evidence: FAIL archive $archive is missing or empty"; return 2; fi
  if ! names=$(tar tzf "$archive" 2>/dev/null); then echo "reth-evidence: FAIL archive $archive is unreadable"; return 2; fi
  tmp=$(mktemp -d) || return 2
  if ! tar xzf "$archive" -C "$tmp" 2>/dev/null; then
    echo "reth-evidence: FAIL archive $archive does not extract"; rm -rf "$tmp"; return 2
  fi

  for req in "$@"; do
    echo "$names" | grep -qE "(^|/)${req//./\\.}\$" || { echo "reth-evidence: FAIL no $req in $archive"; bad=1; }
  done
  if echo "$names" | grep -qE '(^|/)(keys\.json|jwt\.hex|[^/]*\.key|[^/]*\.scan)$'; then
    echo "reth-evidence: FAIL secret file(s) in archive: $(echo "$names" | grep -E '(^|/)(keys\.json|jwt\.hex|[^/]*\.key|[^/]*\.scan)$' | tr '\n' ' ')"
    unsafe=1
  fi
  if grep -rlq '"privateKey"' "$tmp" 2>/dev/null; then
    echo "reth-evidence: FAIL a \"privateKey\" field appears in: $(grep -rl '"privateKey"' "$tmp" | sed "s|$tmp/||" | tr '\n' ' ')"
    unsafe=1
  fi
  vals=
  if [ -n "$nodes" ] && [ -d "$nodes" ]; then
    vals=$(rethEvidenceSecretValues "$nodes") || { echo "reth-evidence: FAIL cannot read every secret under $nodes, so they cannot all be searched for"; unsafe=1; }
  fi
  if [ -n "$scan" ]; then
    if rethScanInputsCheck "$scan"; then
      vals=$(printf '%s\n%s\n' "$vals" "$(grep -v '^#' "$scan")")
    else
      unsafe=1
    fi
  fi
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if grep -rlqF -- "$v" "$tmp" 2>/dev/null; then
      echo "reth-evidence: FAIL a recorded secret value appears verbatim in: $(grep -rlF -- "$v" "$tmp" | sed "s|$tmp/||" | tr '\n' ' ')"
      unsafe=1
    fi
  done < <(printf '%s\n' "$vals" | sort -u)
  logs=$(echo "$names" | grep -cE '(debug|reth)[^/]*\.log$')
  if [ "$logs" -lt "$minLogs" ]; then
    echo "reth-evidence: FAIL $archive holds $logs node log(s), at least $minLogs required — an archive without the logs is not useful evidence"
    bad=1
  fi
  rm -rf "$tmp"
  if [ "$unsafe" -ne 0 ]; then
    echo "reth-evidence: $archive is NOT publishable: it contains a secret, or its secrets cannot all be searched for"
    return 2
  fi
  [ "$bad" -eq 0 ] || return 1
  echo "reth-evidence: archive $archive validated: ${*:-no required files}, $logs node log(s), no secret by name, field or value${scan:+ (including every recorded scan input)}"
}

# rethEvidenceSelect <out-dir> <quarantine-dir> <nodes-dir|""> <require-scan-inputs: yes|no>
#                    <min-node-logs> <required-names> <archive...>
#
# Decides, per archive, what may be published, and puts exactly that into <out-dir> — the only
# directory a workflow uploads. <required-names> is one space-separated word list. With scan inputs
# required, each archive is searched for every value in its own scan-inputs file
# (rethScanInputsPath), and an archive without a sealed one is not publishable.
#
#   validated, or incomplete but secret-free  -> published into <out-dir>, its validation report beside it
#   not publishable (secret, unreadable, ...) -> MOVED into <quarantine-dir>, never uploaded; a
#                                                <name>.REJECTED.txt diagnostic is published instead,
#                                                naming what was found where, never the value
#   missing                                   -> recorded as missing
#
# The bytes validated are the bytes published: each archive is first copied into the (private)
# quarantine directory, that copy is validated, and it is that copy which is renamed into <out-dir>.
# <out-dir>/MANIFEST.txt records every verdict with its sha256, and the published directory is then
# scanned once more for every secret value. Returns nonzero if anything was rejected or missing (a
# secret in the evidence is itself a failure), zero if everything given was published.
#
# Why this exists: validation used to set a failure status and leave the archive where it was, and
# the workflow uploaded that path with always() — so a job would have published the very archive it
# had just found a JWT in.
rethEvidenceSelect() {
  local out=$1 quar=$2 nodes=$3 needScan=$4 minLogs=$5 required=$6 a name stage scan report rc sha verdict v vals bad=0 n=0
  local -a scans=()
  shift 6
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
    scan=
    if [ "$needScan" = yes ]; then scan=$(rethScanInputsPath "$a"); scans+=("$scan"); fi
    stage=$quar/.stage-$name
    if ! ( umask 077; cp "$a" "$stage" ); then
      echo "$name NOT published — could not be staged for validation" >>"$out/MANIFEST.txt"
      echo "reth-evidence: FAIL could not stage $a"; bad=1; continue
    fi
    # shellcheck disable=SC2086 # required is a word list by contract
    report=$(rethEvidenceValidate "$stage" "$nodes" "$scan" "$minLogs" $required 2>&1); rc=$?
    report=${report//$stage/$a}
    sha=$(rethPinSha256 "$stage")
    if [ "$rc" -le 1 ]; then
      verdict=validated; [ "$rc" -eq 1 ] && verdict="incomplete, secret-free"
      if mv "$stage" "$out/$name" && echo "$report" >"$out/$name.validation.txt"; then
        echo "$name sha256=$sha published ($verdict)" >>"$out/MANIFEST.txt"
        echo "reth-evidence: publishing $name ($verdict)"
        n=$((n + 1))
      else
        rm -f "$stage" "$out/$name" "$out/$name.validation.txt"
        echo "$name sha256=$sha NOT published — could not be moved into $out" >>"$out/MANIFEST.txt"
        echo "reth-evidence: FAIL could not publish $name into $out"
        bad=1
      fi
    else
      rm -f "$stage"
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
  vals=
  [ -n "$nodes" ] && [ -d "$nodes" ] && vals=$(rethEvidenceSecretValues "$nodes")
  for scan in ${scans[@]+"${scans[@]}"}; do
    [ -f "$scan" ] && vals=$(printf '%s\n%s\n' "$vals" "$(grep -v '^#' "$scan")")
  done
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if grep -rlqF -- "$v" "$out" 2>/dev/null; then
      echo "reth-evidence: FAIL a secret value appears in the upload directory itself: $(grep -rlF -- "$v" "$out" | tr '\n' ' ') — removed"
      grep -rlF -- "$v" "$out" | while IFS= read -r f; do rm -f "$f"; done
      bad=1
    fi
  done < <(printf '%s\n' "$vals" | sort -u)
  echo "reth-evidence: $n archive(s) published to $out; see $out/MANIFEST.txt"
  return $bad
}

# rethEvidenceSecretValues <nodes-dir> prints, one per line, every JWT secret and private key found
# under <nodes-dir>, without 0x prefixes. Fails if a keys.json cannot be read: a secret that cannot
# be read cannot be searched for, and must not be silently skipped.
rethEvidenceSecretValues() {
  local f status=0
  for f in "$1"/*/jwt.hex; do
    [ -f "$f" ] || continue
    if tr -d ' \n' <"$f"; then echo; else status=1; fi
  done
  for f in "$1"/*/keys.json "$1"/keys.json; do
    [ -f "$f" ] || continue
    python3 -c 'import json,sys
def walk(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if k=="privateKey" and isinstance(v,str): print(v[2:] if v.startswith("0x") else v)
            else: walk(v)
    elif isinstance(o,list):
        for v in o: walk(v)
walk(json.load(open(sys.argv[1])))' "$f" 2>/dev/null || status=1
  done
  return $status
}
