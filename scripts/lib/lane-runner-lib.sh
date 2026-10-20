# Sourced by the devnet lane wrappers (scripts/m2-lane.sh, h3-assignment-lane.sh, f8-mixed-lane-acceptance.sh): the parts every lane's runner shares.
# Definitions only: sourcing this file starts nothing and creates nothing. The caller sets REPO_ROOT, AGRE_ROOT and LANE (a short name for messages).
#
#   lane_preflight <ureth binary> <ureth commit> <dev run 0|1> [provenance dir]   before the lock, and again under it
#   lane_rugregator_preflight <dev run 0|1> [provenance dir]                        the F8 rugregator pin: the checkout AND the binary
#   lane_selftest_steps <steps file> <function that must NOT be defined> <VAR=1>... the steps file starts only with every flag set
#   lane_selftest_defines <library>... -- <function>...                             the libraries define only
#   lane_begin <evidence dir>            under the lock: run mode, heads, the sleep/wake record, the signal trap
#   lane_run_devnet <VAR=value>...       the paired devnet as a child stopped by its own pid; sets LANE_STATUS
#   lane_collect <evidence dir> <test-nodes subdir>...   copies kept for offline replay, the sleep/wake record, SHA256SUMS

# the attested Ureth of the single B1 layout (briefs/builds/ureth-6e59b68c); a lane's <LANE>_URETH_COMMIT overrides it
LANE_URETH_PIN=6e59b68cc29f196d54d3d6e28d6266a8c02d05a1

lane_pass() { printf 'PASS: %s\n' "$1"; }
lane_fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
lane_sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# lane_preflight: everything a run needs that can be known without a process, so a missing input costs no lock slot. An evidence run names its attested
# Ureth: the provenance directory (commit.txt, sha256.txt) records this very commit and this very binary, the checkout is clean and build/ubft is built
# from its HEAD. A development run (third argument 1) skips those and says so. Sets LANE_URETH_BIN, LANE_URETH_COMMIT (the full commit the binary
# reports), LANE_PROVENANCE and LANE_RUN_MODE.
lane_preflight() {
  local bin=$1 commit=$2 dev=${3:-0} provenance=${4:-} missing=() c reported got attested head
  for c in git go jq curl python3 awk tee lsof openssl make mktemp rsync; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  # the lock helper is needed only to TAKE the lock: a caller that already holds it, or a dedicated host (LANE_HOLDS_LOCK=1), needs none
  [ "${LANE_HOLDS_LOCK:-0}" = 1 ] || [ -x "$AGRE_ROOT/briefs/devnet-lock.sh" ] || missing+=("$AGRE_ROOT/briefs/devnet-lock.sh")
  [ -n "$bin" ] && [ -x "$bin" ] || missing+=("the Ureth binary (a build carrying the fresh-B1 profile)")
  [ -n "$commit" ] || missing+=("the Ureth source commit")
  [ -x "$REPO_ROOT/build/ubft" ] || missing+=("build/ubft (make build)")
  [ "${#missing[@]}" -eq 0 ] || lane_fail "$LANE preflight: missing ${missing[*]}"
  # the pin helpers compare commits for equality: resolve a full or abbreviated commit to the full one the binary reports
  reported=$("$bin" --version 2>&1 | sed -n 's/^Commit SHA: //p' | head -1)
  case "$reported" in *[!0-9a-f]*|"") lane_fail "$LANE preflight: $bin reports no commit" ;; esac
  [ "${#reported}" = 40 ] && [ "${reported#"$commit"}" != "$reported" ] || lane_fail "$LANE preflight: $bin does not report the commit $commit (it reports $reported)"
  LANE_URETH_BIN=$bin LANE_URETH_COMMIT=$reported LANE_PROVENANCE=
  head=$(git -C "$REPO_ROOT" rev-parse HEAD)
  if [ "$dev" = 1 ]; then
    LANE_RUN_MODE="DEVELOPMENT RUN, NOT EVIDENCE: the binary and the checkout are not verified against a provenance record"
    return 0
  fi
  LANE_PROVENANCE=${provenance:-$AGRE_ROOT/briefs/builds/ureth-${reported:0:8}}
  [ -s "$LANE_PROVENANCE/sha256.txt" ] && [ -s "$LANE_PROVENANCE/commit.txt" ] || lane_fail "$LANE preflight: no attested provenance at $LANE_PROVENANCE (commit.txt, sha256.txt)"
  [ "$(tr -d '[:space:]' <"$LANE_PROVENANCE/commit.txt")" = "$reported" ] || lane_fail "$LANE preflight: the provenance commit.txt is not $reported"
  attested=$(awk '{print $1; exit}' "$LANE_PROVENANCE/sha256.txt")
  got=$(lane_sha256 "$bin")
  [ "$got" = "$attested" ] || lane_fail "$LANE preflight: $bin sha256 $got is not the attested $attested (provenance $LANE_PROVENANCE)"
  [ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ] || lane_fail "$LANE preflight: the checkout has uncommitted changes (an evidence run needs a clean one)"
  go version -m "$REPO_ROOT/build/ubft" | grep -q "vcs.revision=$head" || lane_fail "$LANE preflight: build/ubft is not built from HEAD $head (make build)"
  ! go version -m "$REPO_ROOT/build/ubft" | grep -q 'vcs.modified=true' || lane_fail "$LANE preflight: build/ubft was built from a modified tree"
  LANE_RUN_MODE="RUN MODE: evidence run: attested prebuilt Ureth $bin sha256=$got commit=$reported (provenance $LANE_PROVENANCE); everything else from this checkout at $head"
}

# lane_rugregator_preflight <dev run 0|1> [provenance dir]: the rugregator checkout at the F8 pin (scripts/f8-rugregator-pin.sh, sourced by the caller)
# and, for an evidence run, the BINARY itself. The binary does not report its commit, so a checkout at the pin says nothing about a binary built at
# another time: the provenance directory (commit.txt, sha256.txt; default briefs/builds/rugregator-<pin>) must record the pin and this very binary.
# (Runs f8-b1-20261012-r1 and h3-b1-20261012-r1 were lost to a stale binary beside a correct checkout.) Sets LANE_RUGREGATOR_SHA256.
lane_rugregator_preflight() {
  local dev=${1:-0} provenance=${2:-} attested
  [ -n "${F8_RUGREGATOR_PIN:-}" ] || lane_fail "$LANE preflight: the rugregator pin is not loaded"
  [ -n "${RUGREGATOR_BIN:-}" ] && [ -x "$RUGREGATOR_BIN" ] || lane_fail "$LANE preflight: set RUGREGATOR_BIN to the binary built from $F8_RUGREGATOR_PIN"
  [ -n "${RUGREGATOR_SOURCE:-}" ] && [ -d "$RUGREGATOR_SOURCE" ] || lane_fail "$LANE preflight: set RUGREGATOR_SOURCE to the pinned rugregator checkout"
  [ "$(git -C "$RUGREGATOR_SOURCE" rev-parse HEAD)" = "$F8_RUGREGATOR_PIN" ] || lane_fail "$LANE preflight: RUGREGATOR_SOURCE is not at the pinned revision $F8_RUGREGATOR_PIN"
  LANE_RUGREGATOR_SHA256=$(lane_sha256 "$RUGREGATOR_BIN")
  [ "$dev" != 1 ] || return 0
  provenance=${provenance:-$AGRE_ROOT/briefs/builds/rugregator-${F8_RUGREGATOR_PIN:0:8}}
  [ -s "$provenance/sha256.txt" ] && [ -s "$provenance/commit.txt" ] || lane_fail "$LANE preflight: no rugregator provenance at $provenance (commit.txt, sha256.txt)"
  [ "$(tr -d '[:space:]' <"$provenance/commit.txt")" = "$F8_RUGREGATOR_PIN" ] || lane_fail "$LANE preflight: the rugregator provenance commit.txt is not $F8_RUGREGATOR_PIN"
  attested=$(awk '{print $1; exit}' "$provenance/sha256.txt")
  [ "$LANE_RUGREGATOR_SHA256" = "$attested" ] || lane_fail "$LANE preflight: RUGREGATOR_BIN sha256 $LANE_RUGREGATOR_SHA256 is not the recorded $attested (provenance $provenance)"
  LANE_RUGREGATOR_PROVENANCE=$provenance
}

# lane_selftest_defines <library>... -- <function>...: sourced in an empty directory the libraries define the named functions, leave no file and no process.
lane_selftest_defines() {
  local libs=() fns=() tmp ok=1 f
  while [ $# -gt 0 ] && [ "$1" != -- ]; do libs+=("$1"); shift; done
  shift || true
  fns=("$@")
  for f in "${libs[@]}"; do bash -n "$REPO_ROOT/$f" || lane_fail "$LANE selftest: $f does not parse"; done
  tmp=$(mktemp -d)
  ( cd "$tmp" && set -u && for f in "${libs[@]}"; do source "$REPO_ROOT/$f" || exit 1; done
    for f in "${fns[@]}"; do [ "$(type -t "$f")" = function ] || { echo "not defined: $f" >&2; exit 1; }; done
    [ -z "$(ls -A "$tmp")" ] && [ -z "$(jobs -p)" ] ) || ok=0
  rm -rf "$tmp"
  [ "$ok" = 1 ] || lane_fail "$LANE selftest: sourcing ${libs[*]} defined something missing, created a file or started a process"
  lane_pass "$LANE selftest: the libraries define only (${#fns[@]} step functions present; no file, no process at source time)"
}

# lane_selftest_steps <steps file> <probe function> <VAR=1>...: the steps file is what acts on a devnet, so it starts only when EVERY flag is set (the
# runner's lock flag among them). Sourced in an empty directory with each flag missing in turn, and with none, it runs nothing, creates nothing and does
# not define the probe function; with all of them it does start (and fails there on its first library, which is absent).
lane_selftest_steps() {
  local steps=$1 probe=$2 tmp i n combo; shift 2
  local flags=("$@")
  bash -n "$REPO_ROOT/$steps" || lane_fail "$LANE selftest: $steps does not parse"
  tmp=$(mktemp -d); n=${#flags[@]}
  for i in -1 $(seq 0 $((n - 1))); do
    combo=(); local j; for j in $(seq 0 $((n - 1))); do [ "$j" = "$i" ] || [ "$i" = -1 ] || combo+=("${flags[$j]}"); done
    ( cd "$tmp" && env -i PATH="$PATH" HOME="$HOME" ${combo[@]+"${combo[@]}"} bash -c 'source "$0"; rc=$?; [ "$rc" = 0 ] && [ -z "$(type -t "$1")" ] && [ -z "$(jobs -p)" ]' "$REPO_ROOT/$steps" "$probe" ) \
      || { rm -rf "$tmp"; lane_fail "$LANE selftest: $steps did something with only [${combo[*]-}] set"; }
  done
  [ -z "$(ls -A "$tmp")" ] || { rm -rf "$tmp"; lane_fail "$LANE selftest: sourcing $steps without every flag created a file"; }
  if ( cd "$tmp" && env -i PATH="$PATH" HOME="$HOME" "${flags[@]}" bash -c 'source "$0"' "$REPO_ROOT/$steps" ) >/dev/null 2>&1; then rm -rf "$tmp"; lane_fail "$LANE selftest: $steps did not start with every flag set"; fi
  rm -rf "$tmp"
  lane_pass "$LANE selftest: $steps starts only with ${flags[*]} ($((n + 1)) other combinations start nothing and define nothing)"
}

# lane_begin <evidence dir>: under the lock. A signal to the lane stops the scenario child by its own pid and waits for its teardown (an orphaned child
# keeps restarting nodes in this checkout); nothing is stopped by name.
LANE_DEVNET_PIDFILE=
lane_stop_devnet() {
  local pid i
  [ -n "$LANE_DEVNET_PIDFILE" ] && [ -s "$LANE_DEVNET_PIDFILE" ] || return 0
  pid=$(cat "$LANE_DEVNET_PIDFILE")
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -KILL "$pid" 2>/dev/null || true
}
lane_begin() {
  local dir=$1
  mkdir -p "$dir"
  lane_pass "devnet lock acquired by the queued runner; evidence directory $dir"
  echo "$LANE_RUN_MODE" | tee "$dir/run-mode.txt"
  [ -z "$LANE_PROVENANCE" ] || cp -R "$LANE_PROVENANCE" "$dir/ureth-provenance"
  [ -z "${LANE_RUGREGATOR_PROVENANCE:-}" ] || cp -R "$LANE_RUGREGATOR_PROVENANCE" "$dir/rugregator-provenance"
  # the machine's own sleep/wake record around the run: a run across a suspend is not evidence, and this shows it without reading the machine later
  { date -u +%FT%TZ; pmset -g log 2>/dev/null; } | gzip >"$dir/pmset-before.log.gz" || true
  echo "bft-core head=$(git -C "$REPO_ROOT" rev-parse HEAD) branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD) ureth=$LANE_URETH_COMMIT ubft sha256=$(lane_sha256 "$REPO_ROOT/build/ubft")${LANE_RUGREGATOR_SHA256:+ rugregator=$F8_RUGREGATOR_PIN rugregator sha256=$LANE_RUGREGATOR_SHA256}" | tee "$dir/heads.txt"
  LANE_EVIDENCE_DIR=$dir
  trap lane_stop_devnet EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# lane_run_devnet <VAR=value>...: the four-validator paired devnet with the given environment, output to lane.log. Sets LANE_STATUS.
lane_run_devnet() {
  set +e
  LANE_DEVNET_PIDFILE="$LANE_EVIDENCE_DIR/.devnet-pid"; rm -f "$LANE_DEVNET_PIDFILE"
  ( set -o pipefail
    cd "$REPO_ROOT" && env "$@" POST_M2A_URETH_BIN="$LANE_URETH_BIN" POST_M2A_URETH_COMMIT="$LANE_URETH_COMMIT" URETH_PIN_COMMIT="$LANE_URETH_COMMIT" \
      M2_RUN_LOG_DIR="$LANE_EVIDENCE_DIR/nodes" \
      bash -c 'echo $$ >"$0"; exec bash ./scripts/reth-paired-devnet.sh 4 10' "$LANE_DEVNET_PIDFILE" 2>&1 | tee "$LANE_EVIDENCE_DIR/lane.log" ) &
  wait "$!"
  LANE_STATUS=$?
  set -e
  rm -f "$LANE_DEVNET_PIDFILE"
}

# lane_collect <test-nodes subdir>...: the state stays in test-nodes (the nodes are stopped by the devnet's own teardown); the evidence gets a copy of the
# lane's flow directories and of what the lane's helpers read (roots' databases and public node info, trust bases), so a failure can be replayed offline.
# Not copied: the execution clients' data, the authorities' credentials, keys.
lane_collect() {
  local d n f
  for d in "$@"; do cp -R "$REPO_ROOT/test-nodes/$d" "$LANE_EVIDENCE_DIR/$d" 2>/dev/null || true; done
  rsync -a --exclude 'reth*/' --exclude 'evm*/' --exclude 'auth*/' --exclude '*.log' --exclude 'keys.json' --exclude '*.sock' --exclude '*.cred' \
    --exclude 'jwt.hex' --exclude '*-archives/' $(printf -- "--exclude %s/ " "$@") "$REPO_ROOT/test-nodes/" "$LANE_EVIDENCE_DIR/state/" 2>/dev/null || true
  for n in root1 root2 root3 root4 root5 root6 evm1 evm2 evm3 evm4 evm5 evm6; do
    [ -f "$REPO_ROOT/test-nodes/$n/debug.log" ] && cp "$REPO_ROOT/test-nodes/$n/debug.log" "$LANE_EVIDENCE_DIR/$n-debug.log"
  done
  { date -u +%FT%TZ; pmset -g log 2>/dev/null; } | gzip >"$LANE_EVIDENCE_DIR/pmset-after.log.gz" || true
  echo "state kept in $REPO_ROOT/test-nodes (nodes stopped by their own teardown); evidence copy in $LANE_EVIDENCE_DIR" >"$LANE_EVIDENCE_DIR/state.txt"
  (cd "$LANE_EVIDENCE_DIR" && find . -type f ! -name SHA256SUMS ! -name '.devnet-pid' | LC_ALL=C sort | xargs shasum -a 256 >SHA256SUMS) || true
}
