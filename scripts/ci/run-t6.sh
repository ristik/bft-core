#!/usr/bin/env bash
# The run job of the T6 rehearsal on a GitHub-hosted runner: places the attested Linux ureth (verified against scripts/ci/lane-pins.json), runs scripts/t6-rehearsal.sh under a
# deadline and always finalizes (the publishable evidence pack, its outer digest, the logs).
#   scripts/ci/run-t6.sh ARTIFACT_DIR WORK_DIR OUT_DIR          (cwd: the checkout of the commit under test, full history; Go on PATH)
# ARTIFACT_DIR holds ureth-linux/ (unicity-reth + provenance, from build-ureth). T6 rebuilds its own helper tools, the four allocation contracts (at its own pinned contracts
# commit) and its own Foundry (v1.8.3, Linux asset) in an isolated checkout, so this job needs Go, git and network, not the lane's tool or source artifacts.
# Environment: CI_INJECT_FAILURE none|after-builds|in-lane (in-lane = fail after the isolated build, before the network), T6_DEADLINE_MIN (default 105).
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/../.." && pwd); cd "$repo"
art=$(cd "${1:?ARTIFACT_DIR}" && pwd); work=${2:?WORK_DIR}; out=${3:?OUT_DIR}
mkdir -p "$work" "$out"; work=$(cd "$work" && pwd); out=$(cd "$out" && pwd)
source scripts/lib/portable.sh
log() { printf '%s run-t6: %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$out/run-lane.log"; }
die() { log "HARNESS FAILURE: $*"; rc=1; finalize; exit 1; }
pins=scripts/ci/lane-pins.json
inject=${CI_INJECT_FAILURE:-none}; deadline=${T6_DEADLINE_MIN:-105}
head=$(git rev-parse HEAD)
export AGRE_ROOT=$work/agre DEVNET_LOCK_DIR=$work/agre/.devnet-lock
# the devnet's secrets, saved for the value scan of the published pack (see finalize); outside the evidence, never uploaded
export T6_SECRETS_DIR=$work/t6-secrets; mkdir -p "$T6_SECRETS_DIR"
mkdir -p "$AGRE_ROOT/builds" "$AGRE_ROOT/briefs/devnet-runs"
rc=0; lane_rc=; finalized=0

finalize() {
  [ "$finalized" = 0 ] || return 0; finalized=1
  log "finalize: t6 status ${lane_rc:-none}, harness status $rc"
  host_evidence after "$out/host-after.log.gz"
  { dmesg 2>/dev/null || sudo -n dmesg 2>/dev/null; } | grep -i -E 'out of memory|oom-kill|killed process' >"$out/oom-lines.txt" 2>/dev/null || true
  [ -r /sys/fs/cgroup/memory.events ] && cp /sys/fs/cgroup/memory.events "$out/cgroup-memory.events" || true
  ev=$(ls -d "$AGRE_ROOT"/briefs/devnet-runs/t6-rehearsal-2* 2>/dev/null | sort | tail -1)
  if [ -n "$ev" ] && [ -d "$ev" ]; then cp -R "$ev" "$work/evidence-dir" 2>/dev/null || true; evdir=$work/evidence-dir
  else evdir=$work/evidence-none; mkdir -p "$evdir"; echo "T6 produced no evidence directory" >"$evdir/t6-rehearsal.log"; fi
  # a failing T6 keeps its isolated checkout: the nodes' logs (roots, EVM validators, execution clients, authorities; flattened, because the publisher leaves whole
  # evm*/reth*/auth* directories out by name) go into the evidence so a failure can be diagnosed from the artifact alone; the secret scan covers them like everything else
  iso=$(grep -a 'Isolated checkout:' "$out/lane-stdout.log" 2>/dev/null | tail -n 1 | sed 's/^.*Isolated checkout: //')
  if [ -n "$iso" ] && [ -d "$iso/bft-core/test-nodes" ]; then
    mkdir -p "$evdir/failed-node-logs"
    ( cd "$iso/bft-core/test-nodes" && find . -maxdepth 3 -type f \( -name '*.log' -o -name 'pid' \) ! -path '*/dd/*' -print | while read -r f; do cp "$f" "$evdir/failed-node-logs/$(echo "${f#./}" | tr '/' '-')" 2>/dev/null; done )
  fi
  # the values of this devnet's keys and JWTs are searched for in the published pack (--nodes). A passing run's checkout is already gone: t6-rehearsal.sh saved the
  # secrets into $T6_SECRETS_DIR before removing it; a failing run's checkout is still here. This directory is outside the evidence and never uploaded.
  # (no checkout and nothing saved earlier: the publisher refuses, it never publishes unscanned)
  [ -z "$iso" ] || [ ! -d "$iso/bft-core/test-nodes" ] || scripts/ci/t6-secrets.sh "$T6_SECRETS_DIR" "$iso/bft-core/test-nodes" "$(sed -n 's/^T6_TREASURY_TEST_KEY=//p' scripts/t6/lane-actions.sh | head -1)" || log "saving the devnet secrets failed"
  st=${lane_rc:-1}; [ "$rc" -eq 0 ] || st=$rc
  scripts/ci/publish-evidence.sh --evidence "$evdir" --out "$out/upload" --kind t6 --status "$st" --min-node-logs 0 --nodes "$T6_SECRETS_DIR" \
    --extra "$out/run-lane.log" --extra "$out/lane-stdout.log" --extra "$out/host-before.log.gz" --extra "$out/host-after.log.gz" --extra "$out/oom-lines.txt" >"$out/publish.log" 2>&1
  pub_rc=$?; log "publish-evidence exit $pub_rc"; tail -n 8 "$out/publish.log"
  return 0
}

host_evidence before "$out/host-before.log.gz"
log "commit under test $head; inject=$inject; deadline ${deadline} min; artifacts $art"

# ---- 1. the attested ureth (the same verification as run-lane.sh) -------------------------------------------------------------------------------------------
ur=$art/ureth-linux; [ -f "$ur/unicity-reth" ] || die "no unicity-reth in $ur"
ureth_commit=$(jq -er .components.ureth.commit "$pins")
prov=$AGRE_ROOT/builds/ureth-${ureth_commit:0:8}; mkdir -p "$prov"; cp "$ur"/* "$prov/"; chmod +x "$prov/unicity-reth"
want=$(awk '{print $1; exit}' "$prov/sha256.txt")
[ "$want" = "$(p_sha256 "$prov/unicity-reth" | awk '{print $1}')" ] || die "unicity-reth does not match its recorded sha256"
scripts/ci/check-pins.sh component ureth "$(tr -d '[:space:]' <"$prov/commit.txt")" | tee -a "$out/run-lane.log" | grep -q '^ok' || die "the ureth provenance commit is not the pin"
scripts/ci/check-pins.sh t6 | tee -a "$out/run-lane.log" | grep -q '^FAIL' && die "the T6 script's own pins do not match the manifest"
for c in lsof pgrep openssl make; do command -v "$c" >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq lsof procps openssl make >/dev/null 2>&1 || true; break; }; done
scripts/ci/prune-runner.sh >/dev/null 2>&1 || true

[ "$inject" != after-builds ] || die "injected harness failure (inject_failure=after-builds): the ureth is verified, T6 is not started"

# ---- 2. T6 ------------------------------------------------------------------------------------------------------------------------------------------------
# T6 clones the commit under test into its isolated checkout: from this checkout (no network, and a PR merge commit needs no branch ref)
export T6_BFT_REMOTE=$repo T6_BFT_REF=HEAD T6_BFT_COMMIT=$head
export T6_URETH_ATTESTED=$prov/unicity-reth T6_URETH_ATTESTED_SHA256=$want T6_URETH_ATTESTED_PROVENANCE=$prov T6_URETH_COMMIT=$ureth_commit
export T6_EVIDENCE_DIR=$AGRE_ROOT/briefs/devnet-runs/t6-rehearsal-$(date -u +%Y%m%dT%H%M%SZ)
[ "$inject" != in-lane ] || export T6_INJECT_FAIL_AFTER_BUILD=1
log "scripts/t6-rehearsal.sh (deadline ${deadline} min), evidence $T6_EVIDENCE_DIR"
p_timeout "$((deadline * 60))" scripts/t6-rehearsal.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
lane_rc=${PIPESTATUS[0]}
log "t6 exit $lane_rc"
tail -n 6 "$out/lane-stdout.log" | cut -c1-200
finalize
[ "$lane_rc" -eq 0 ] && [ "${pub_rc:-1}" -eq 0 ]
