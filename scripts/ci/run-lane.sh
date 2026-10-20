#!/usr/bin/env bash
# The run job of the combined lane on a GitHub-hosted runner: installs only BINARIES and pinned sources from the build jobs' artifacts, verifies each against
# scripts/ci/lane-pins.json, starts the digest-pinned Mongo replica set, runs scripts/utb-lane.sh (--prep, then the run) under a deadline, and always finalizes.
#   scripts/ci/run-lane.sh ARTIFACT_DIR WORK_DIR OUT_DIR          (cwd: the checkout of the commit under test)
# ARTIFACT_DIR holds: ureth-linux/ (unicity-reth + provenance), tools/ (ubft, tools/, aggregator-<sha8>/, selftest/), sources/ (<name>.tar.zst + .sha256)
# Environment: CI_INJECT_FAILURE none|after-builds|in-lane, LANE_DEADLINE_MIN (default 75), GITHUB_* as set by Actions.
# OUT_DIR gets the upload set (scripts/ci/publish-evidence.sh) and run-lane's own logs. Exit status: the lane's, or 1 for a harness failure; the upload set is written either way.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/../.." && pwd); cd "$repo"
art=$(cd "${1:?ARTIFACT_DIR}" && pwd); work=${2:?WORK_DIR}; out=${3:?OUT_DIR}
mkdir -p "$work" "$out"; work=$(cd "$work" && pwd); out=$(cd "$out" && pwd)
source scripts/lib/portable.sh
log() { printf '%s run-lane: %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$out/run-lane.log"; }
die() { log "HARNESS FAILURE: $*"; rc=1; finalize; exit 1; }
pins=scripts/ci/lane-pins.json
inject=${CI_INJECT_FAILURE:-none}; deadline=${LANE_DEADLINE_MIN:-75}
head=$(git rev-parse HEAD)
export AGRE_ROOT=$work/agre DEVNET_LOCK_DIR=$work/agre/.devnet-lock
mkdir -p "$AGRE_ROOT/builds" "$AGRE_ROOT/briefs/devnet-runs"
rc=0; lane_rc=; finalized=0

finalize() {
  [ "$finalized" = 0 ] || return 0; finalized=1
  log "finalize: lane status ${lane_rc:-none}, harness status $rc"
  # PID-scoped teardown of this run's own processes (never a name sweep); the lane's own teardown runs on its exit paths
  [ -x scripts/p85-stop.sh ] && ( cd "$repo" && scripts/p85-stop.sh >"$out/p85-stop.log" 2>&1 ) || true
  scripts/ci/mongo-up.sh down "$out/mongo" >/dev/null 2>&1 || true
  host_evidence after "$out/host-after.log.gz"
  { dmesg 2>/dev/null || sudo -n dmesg 2>/dev/null; } | grep -i -E 'out of memory|oom-kill|killed process' >"$out/oom-lines.txt" 2>/dev/null || true
  [ -r /sys/fs/cgroup/memory.events ] && cp /sys/fs/cgroup/memory.events "$out/cgroup-memory.events" || true
  ev=$(ls -d "$AGRE_ROOT"/briefs/devnet-runs/utb-2* 2>/dev/null | sort | tail -1)
  if [ -n "$ev" ] && [ -d "$ev" ]; then
    cp -R "$ev" "$work/evidence-dir" 2>/dev/null || true; evdir=$work/evidence-dir
  else
    evdir=$work/evidence-none; mkdir -p "$evdir"; echo "the lane produced no evidence directory" >"$evdir/lane.log"
  fi
  st=${lane_rc:-1}; [ "$rc" -eq 0 ] || st=$rc
  scripts/ci/publish-evidence.sh --evidence "$evdir" --out "$out/upload" --status "$st" --nodes "$repo/test-nodes" --min-node-logs 1 \
    --extra "$out/run-lane.log" --extra "$out/lane-stdout.log" --extra "$out/lane-prep.log" --extra "$out/mongo" --extra "$out/p85-stop.log" --extra "$out/host-before.log.gz" --extra "$out/host-after.log.gz" --extra "$out/oom-lines.txt" >"$out/publish.log" 2>&1
  pub_rc=$?; log "publish-evidence exit $pub_rc"; cat "$out/publish.log" | tail -n 8
  return 0
}

host_evidence before "$out/host-before.log.gz"
log "commit under test $head; lane=$inject; deadline ${deadline} min; artifacts $art"

# ---- 1. verify and place the build artifacts (binaries and pinned sources only) ------------------------------------------------------------------------------
ur=$art/ureth-linux; [ -f "$ur/unicity-reth" ] || die "no unicity-reth in $ur"
ureth_commit=$(jq -er .components.ureth.commit "$pins")
prov=$AGRE_ROOT/builds/ureth-${ureth_commit:0:8}; mkdir -p "$prov"; cp "$ur"/* "$prov/"
chmod +x "$prov/unicity-reth"
[ "$(awk '{print $1; exit}' "$prov/sha256.txt")" = "$(p_sha256 "$prov/unicity-reth" | awk '{print $1}')" ] || die "unicity-reth does not match its recorded sha256"
scripts/ci/check-pins.sh component ureth "$(tr -d '[:space:]' <"$prov/commit.txt")" | tee -a "$out/run-lane.log" | grep -q '^ok' || die "the ureth provenance commit is not the pin"
export M2_URETH_BIN=$prov/unicity-reth M2_URETH_COMMIT=$ureth_commit M2_URETH_ATTESTED_PROVENANCE=$prov

mkdir -p build "$AGRE_ROOT/builds/tools"
cp "$art/tools/ubft" build/ubft; chmod +x build/ubft; cp -R "$art/tools/tools/." "$AGRE_ROOT/builds/tools/"; chmod +x "$AGRE_ROOT/builds/tools/"*
export LANE_TOOLS_DIR=$AGRE_ROOT/builds/tools DNB_TOOL=$AGRE_ROOT/builds/tools/dnb-tool UTB_EVIDENCE=$AGRE_ROOT/builds/tools/utb-evidence
agg_commit=$(jq -er '.components["aggregator-go"].commit' "$pins")
cp -R "$art/tools/aggregator-${agg_commit:0:8}" "$AGRE_ROOT/builds/"
export AGG_COMMIT=$agg_commit AGG_BIN=$AGRE_ROOT/builds/aggregator-${agg_commit:0:8}/aggregator; chmod +x "$AGG_BIN"
( cd "$art/tools" && p_sha256 -c sha256.txt >/dev/null ) || die "the tools artifact does not match its sha256.txt"
export LANE_SELFTEST_LOG=$art/tools/selftest/utb-lane-selftest.log

unpack() { # NAME DEST
  ( cd "$art/sources" && p_sha256 -c "$1.tar.zst.sha256" >/dev/null ) || die "$1.tar.zst does not match its sha256"
  mkdir -p "$2"; zstd -q -dc "$art/sources/$1.tar.zst" | tar -xf - -C "$2"
}
unpack contracts "$AGRE_ROOT"; unpack native-bridge-plugins "$AGRE_ROOT"; unpack state-transition-sdk-js "$AGRE_ROOT"
export P85_CONTRACTS=$AGRE_ROOT/contracts NBP_DIR=$AGRE_ROOT/native-bridge-plugins UTB_SDK_JS=$AGRE_ROOT/state-transition-sdk-js
[ ! -d "$P85_CONTRACTS/.ci-svm" ] || { mkdir -p "$HOME/.svm"; cp -R "$P85_CONTRACTS/.ci-svm/." "$HOME/.svm/" 2>/dev/null || true; }

# Foundry at the pinned release, verified by the digest of the downloaded archive
scripts/ci/install-foundry.sh "$work/dl" >>"$out/run-lane.log" 2>&1 || die "cannot install the pinned Foundry"
export PATH="$HOME/.foundry/bin:$repo/scripts/ci/shim:$PATH"
# T8: the lane includes the funded operator reward pool step (scripts/lib/rewards-lib.sh): the genesis payees hold keys, the pool is settled across the real
# acknowledged history, recomputed from scratch, claimed. Off by default on the Mac (REWARD_LANE unset); on in CI.
export REWARD_LANE=1
export LANE_PINNED=1 LANE_COMMIT_UNDER_TEST=$head UTB_MIN_FREE_GIB=${UTB_MIN_FREE_GIB:-$(jq -r '.runner.minFreeDiskGiB' "$pins")}
scripts/ci/check-pins.sh env 2>&1 | tee -a "$out/run-lane.log" | grep -q '^FAIL' && die "a component does not match the manifest"

# ---- 2. Mongo -------------------------------------------------------------------------------------------------------------------------------------------------
scripts/ci/mongo-up.sh up "$out/mongo" >>"$out/run-lane.log" 2>&1 || die "MongoDB replica set did not come up (see mongo/)"

[ "$inject" != after-builds ] || die "injected harness failure (inject_failure=after-builds): the builds are verified, the lane is not started"

# ---- 3. the lane ----------------------------------------------------------------------------------------------------------------------------------------------
[ "$inject" != in-lane ] || export CI_INJECT_FAIL_AFTER=utb_step_u1
log "scripts/utb-lane.sh --prep"
p_timeout "$((deadline * 60))" scripts/utb-lane.sh --prep >"$out/lane-prep.log" 2>&1; prep_rc=$?
log "prep exit $prep_rc"
if [ "$prep_rc" -ne 0 ]; then lane_rc=$prep_rc; tail -n 20 "$out/lane-prep.log"; finalize; exit "$lane_rc"; fi
log "scripts/utb-lane.sh (deadline ${deadline} min)"
p_timeout "$((deadline * 60))" scripts/utb-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
lane_rc=${PIPESTATUS[0]}
log "lane exit $lane_rc"
tail -n 6 "$out/lane-stdout.log" | cut -c1-200
finalize
[ "$lane_rc" -eq 0 ] && [ "${pub_rc:-1}" -eq 0 ]
