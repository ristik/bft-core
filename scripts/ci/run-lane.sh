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
# CI_LANE_KIND: x4rewards (the shadow chain with a small reward allocation: the PoS campaign's reward steps, X4_REWARDS=1), x4shadow (P85_SHADOW=1 scripts/p85-lane.sh with the declared 90-minute campaign, scripts/shadow/campaign.json), combined (utb-lane.sh), overbound (P85_MODE=overbound scripts/p85-lane.sh) or abort (scripts/h6/abort-rehearsal-lane.sh); each from its own fresh genesis
kind=${CI_LANE_KIND:-combined}
case "$kind" in combined|overbound|abort|x4shadow|x4rewards|x4exit) ;; *) echo "run-lane: unknown CI_LANE_KIND $kind" >&2; exit 2 ;; esac
head=$(git rev-parse HEAD)
export AGRE_ROOT=$work/agre DEVNET_LOCK_DIR=$work/agre/.devnet-lock
mkdir -p "$AGRE_ROOT/builds" "$AGRE_ROOT/briefs/devnet-runs"
rc=0; lane_rc=; finalized=0

finalize() {
  [ "$finalized" = 0 ] || return 0; finalized=1
  log "finalize: lane status ${lane_rc:-none}, harness status $rc"
  # PID-scoped teardown of this run's own processes (never a name sweep); the lane's own teardown runs on its exit paths
  [ -x scripts/p85-stop.sh ] && ( cd "$repo" && scripts/p85-stop.sh >"$out/p85-stop.log" 2>&1 ) || true
  [ "$kind" != combined ] || scripts/ci/mongo-up.sh down "$out/mongo" >/dev/null 2>&1 || true
  host_evidence after "$out/host-after.log.gz"
  { dmesg 2>/dev/null || sudo -n dmesg 2>/dev/null; } | grep -i -E 'out of memory|oom-kill|killed process' >"$out/oom-lines.txt" 2>/dev/null || true
  [ -r /sys/fs/cgroup/memory.events ] && cp /sys/fs/cgroup/memory.events "$out/cgroup-memory.events" || true
  case "$kind" in combined) evglob=utb-2 ;; overbound) evglob=p85-overbound-2 ;; abort) evglob=h6-abort-2 ;; x4shadow|x4rewards) evglob=x4-shadow-lane-2 ;; x4exit) evglob=x4-exit-lane-2 ;; esac
  ev=$(ls -d "$AGRE_ROOT"/briefs/devnet-runs/${evglob}* 2>/dev/null | sort | tail -1)
  if [ -n "$ev" ] && [ -d "$ev" ]; then
    cp -R "$ev" "$work/evidence-dir" 2>/dev/null || true; evdir=$work/evidence-dir
  else
    evdir=$work/evidence-none; mkdir -p "$evdir"; echo "the lane produced no evidence directory" >"$evdir/lane.log"
  fi
  st=${lane_rc:-1}; [ "$rc" -eq 0 ] || st=$rc
  scripts/ci/publish-evidence.sh --evidence "$evdir" --out "$out/upload" --kind "$kind" --s4 "${S4_LANE:-0}" --x4o "${X4_OFFENCE_LANE:-0}" --x4a "${X4_ACCT_LANE:-0}" --x4r "${X4_REWARDS_POS:-0}" --x4g "${X4_GOV_LANE:-0}" --status "$st" --nodes "$repo/test-nodes" --min-node-logs 1 \
    --extra "$out/run-lane.log" --extra "$out/lane-stdout.log" --extra "$out/lane-prep.log" --extra "$out/mongo" --extra "$out/p85-stop.log" --extra "$out/host-before.log.gz" --extra "$out/host-after.log.gz" --extra "$out/oom-lines.txt" >"$out/publish.log" 2>&1
  pub_rc=$?; log "publish-evidence exit $pub_rc"; cat "$out/publish.log" | tail -n 8
  return 0
}

host_evidence before "$out/host-before.log.gz"
log "commit under test $head; kind=$kind inject=$inject; deadline ${deadline} min; artifacts $art"

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
if [ "$kind" = combined ]; then
  agg_commit=$(jq -er '.components["aggregator-go"].commit' "$pins")
  cp -R "$art/tools/aggregator-${agg_commit:0:8}" "$AGRE_ROOT/builds/"
  export AGG_COMMIT=$agg_commit AGG_BIN=$AGRE_ROOT/builds/aggregator-${agg_commit:0:8}/aggregator; chmod +x "$AGG_BIN"
fi
( cd "$art/tools" && p_sha256 -c sha256.txt >/dev/null ) || die "the tools artifact does not match its sha256.txt"
export LANE_SELFTEST_LOG=$art/tools/selftest/utb-lane-selftest.log

unpack() { # NAME DEST
  ( cd "$art/sources" && p_sha256 -c "$1.tar.zst.sha256" >/dev/null ) || die "$1.tar.zst does not match its sha256"
  mkdir -p "$2"; zstd -q -dc "$art/sources/$1.tar.zst" | tar -xf - -C "$2"
}
unpack contracts "$AGRE_ROOT"
[ "$kind" != combined ] || { unpack native-bridge-plugins "$AGRE_ROOT"; unpack state-transition-sdk-js "$AGRE_ROOT"; }
export P85_CONTRACTS=$AGRE_ROOT/contracts NBP_DIR=$AGRE_ROOT/native-bridge-plugins UTB_SDK_JS=$AGRE_ROOT/state-transition-sdk-js
[ ! -d "$P85_CONTRACTS/.ci-svm" ] || { mkdir -p "$HOME/.svm"; cp -R "$P85_CONTRACTS/.ci-svm/." "$HOME/.svm/" 2>/dev/null || true; }

# Foundry at the pinned release, verified by the digest of the downloaded archive
scripts/ci/install-foundry.sh "$work/dl" >>"$out/run-lane.log" 2>&1 || die "cannot install the pinned Foundry"
export PATH="$HOME/.foundry/bin:$repo/scripts/ci/shim:$PATH"
export DNB_AGG_SHARDS=$(jq -r '.lane.aggShards // 1' "$pins")
# the EVM shard's T2 (setup-evm-nodes.sh reads EVM_T2_MS; unset = 5000): scripts/ci/lane-pins.json lane.evmT2Ms, see its note and bft-core#728
if [ -n "$(jq -r '.lane.evmT2Ms // empty' "$pins")" ]; then export EVM_T2_MS=$(jq -r '.lane.evmT2Ms' "$pins"); log "EVM_T2_MS=$EVM_T2_MS (lane-pins)"; fi
# ureth with transaction-only gossip (ristik/ureth#34): the lane submits each transaction to ONE validator and proves that the others received it (scripts/lib/gossip-lib.sh)
if [ "$(jq -r '.lane.txGossip // false' "$pins")" = true ]; then export GOSSIP_LANE=1 LANE_TX_FANOUT=one; fi
# B7 PR 3: the long-history redemption step (scripts/lib/anyage-lib.sh anyage_step_long_history), when lane-pins says .lane.longHistory
if [ "$(jq -r '.lane.longHistory // false' "$pins")" = true ]; then export B7_LONG_HISTORY=1; fi
# T8: the lane includes the funded operator reward pool step (scripts/lib/rewards-lib.sh): the genesis payees hold keys, the pool is settled across the real
# acknowledged history, recomputed from scratch, claimed. Off by default on the Mac (REWARD_LANE unset); on in CI.
export REWARD_LANE=1
case "$kind" in x4shadow|x4rewards|x4exit) export REWARD_LANE=0 ;; esac   # the shadow chain has no authoritative election and no reward step
# S4 (#57, scripts/lib/s4-lib.sh, docs/root-evidence.md): the focused live slashing exercise is added to the combined lane when scripts/ci/run-inputs.json of the commit under
# test says "s4": true (a ci-lane-run/** push; off by default). It adds the roots' observer journals, a harness-signed equivocation by the joiner's root key and the
# submission through the real Evidence contract after the recovery.
if [ "$kind" = combined ] && [ "$(jq -r '.s4 // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ]; then export S4_LANE=1; log "S4_LANE=1 (run-inputs s4)"; fi
# run-inputs "offence2": true (with "s4": true, on the combined or x4exit kind) adds X4 B4's second offence by a staying member (scripts/x4pos/offence-lib.sh)
if [ "$(jq -r '.offence2 // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ]; then
  case "$kind" in combined|x4exit) [ "$(jq -r '.s4 // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ] || { log "offence2 needs s4: true"; exit 2; }; export X4_OFFENCE_LANE=1; log "X4_OFFENCE_LANE=1 (run-inputs offence2)" ;; esac
fi
# run-inputs "accounting": true (x4exit kind) adds X4 B6's accounting snapshots between the lane's phases and the checker at the end (scripts/x4pos/acct-lib.sh)
if [ "$(jq -r '.accounting // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ]; then
  case "$kind" in x4exit) export X4_ACCT_LANE=1; log "X4_ACCT_LANE=1 (run-inputs accounting)" ;; *) log "accounting is for the x4exit kind"; exit 2 ;; esac
fi
# run-inputs "rewards": true (with "accounting": true, x4exit kind) adds X4 B6c's reward steps on the recovery chain with a SMALL genesis pool, 0.5 UCT: the first closed interval takes it all and the second is at zero budget (it runs dry; the recovery chain closes only 2 intervals, see scripts/x4pos/rewards-pos-lib.sh, is refilled, then paid)
if [ "$(jq -r '.rewards // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ]; then
  [ "${X4_ACCT_LANE:-0}" = 1 ] || { log "rewards needs accounting: true on the x4exit kind"; exit 2; }
  export X4_REWARDS_POS=1 P85_REWARD_FUNDING=${P85_REWARD_FUNDING:-500000000000000000}; log "X4_REWARDS_POS=1 P85_REWARD_FUNDING=$P85_REWARD_FUNDING (run-inputs rewards)"
fi
# run-inputs "governance": true (with "accounting": true, x4exit kind) adds X4 B6e's governance experiment: the authority is a lane-held key, a proposal is queued after the baseline, executed after the delays
# and the lane records whether an election boundary activated it (scripts/x4pos/gov-lib.sh)
if [ "$(jq -r '.governance // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ]; then
  [ "${X4_ACCT_LANE:-0}" = 1 ] || { log "governance needs accounting: true on the x4exit kind"; exit 2; }
  export X4_GOV_LANE=1; log "X4_GOV_LANE=1 (run-inputs governance)"
fi
export LANE_PINNED=1 LANE_COMMIT_UNDER_TEST=$head UTB_MIN_FREE_GIB=${UTB_MIN_FREE_GIB:-$(jq -r '.runner.minFreeDiskGiB' "$pins")}
if [ "$kind" = combined ]; then pins_mode=env; else pins_mode=env-core; fi
scripts/ci/check-pins.sh "$pins_mode" 2>&1 | tee -a "$out/run-lane.log" | grep -q '^FAIL' && die "a component does not match the manifest"

# ---- 2. Mongo -------------------------------------------------------------------------------------------------------------------------------------------------
if [ "$kind" = combined ]; then scripts/ci/mongo-up.sh up "$out/mongo" >>"$out/run-lane.log" 2>&1 || die "MongoDB replica set did not come up (see mongo/)"; fi

[ "$inject" != after-builds ] || die "injected harness failure (inject_failure=after-builds): the builds are verified, the lane is not started"

# ---- 3. the lane ----------------------------------------------------------------------------------------------------------------------------------------------
case "$kind" in
  combined)
    [ "$inject" != in-lane ] || export CI_INJECT_FAIL_AFTER=utb_step_u1
    log "scripts/utb-lane.sh --prep"
    p_timeout "$((deadline * 60))" scripts/utb-lane.sh --prep >"$out/lane-prep.log" 2>&1; prep_rc=$?
    log "prep exit $prep_rc"
    if [ "$prep_rc" -ne 0 ]; then lane_rc=$prep_rc; tail -n 20 "$out/lane-prep.log"; finalize; exit "$lane_rc"; fi
    log "scripts/utb-lane.sh (deadline ${deadline} min)"
    p_timeout "$((deadline * 60))" scripts/utb-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
    lane_rc=${PIPESTATUS[0]} ;;
  overbound)
    # the election's refusal of an over-bound candidate: the P85 lane's own mode, a fresh genesis, the prerequisite steps preserved
    [ "$inject" != in-lane ] || export CI_INJECT_FAIL_AFTER=p85_joiner_nodes
    export P85_MODE=overbound P85_EVIDENCE_PREFIX=p85-overbound P85_LOCK_OWNER=p85-recovery
    log "P85_MODE=overbound scripts/p85-lane.sh (deadline ${deadline} min)"
    p_timeout "$((deadline * 60))" scripts/p85-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
    lane_rc=${PIPESTATUS[0]} ;;
  x4shadow)
    # the PoA-authoritative shadow observation (briefs/x4-shadow-campaign-design.md section 2): the records hook without an election; the adapter observes the checked-in
    # interval from the election's due moment and passes only on its own PASS (zero divergence, every scheduled sample, the required due counts)
    export P85_SHADOW=1 X4_CAMPAIGN=$repo/scripts/shadow/campaign.json P85_EVIDENCE_PREFIX=x4-shadow-lane P85_LOCK_OWNER=p85-recovery
    log "P85_SHADOW=1 scripts/p85-lane.sh, campaign $(jq -r .name "$X4_CAMPAIGN") (deadline ${deadline} min)"
    p_timeout "$((deadline * 60))" scripts/p85-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
    lane_rc=${PIPESTATUS[0]}
    if [ "$inject" = in-lane ]; then log "injected harness failure (inject_failure=in-lane) after the shadow lane (its own exit was $lane_rc)"; lane_rc=1; fi ;;
  x4rewards)
    # the reward steps of the PoS campaign (scripts/x4pos): the shadow chain (records hook, no election) funded small, so the pool runs dry; settle, replay the pool's
    # whole life against the chain, observe the zero-budget interval, refill, see a later interval paid
    export P85_SHADOW=1 X4_REWARDS=1 P85_EVIDENCE_PREFIX=x4-shadow-lane P85_LOCK_OWNER=p85-recovery
    log "X4_REWARDS=1 P85_SHADOW=1 scripts/p85-lane.sh (deadline ${deadline} min)"
    p_timeout "$((deadline * 60))" scripts/p85-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
    lane_rc=${PIPESTATUS[0]}
    if [ "$inject" = in-lane ]; then log "injected harness failure (inject_failure=in-lane) after the rewards lane (its own exit was $lane_rc)"; lane_rc=1; fi ;;
  x4exit)
    # the exit lifecycle of the PoS campaign (scripts/x4pos exit steps): the recovery lane's chain (election, roots with --pos-deployment and --pos-evm-rpc), then the joiner's
    # identity requests retirement; the roots build and order the Retirement, the lots mature after the gates and are claimed (X4_EXIT_LANE=1)
    # run-inputs "s4": true makes the joiner the slashed, held offender (scripts/lib/s4-lib.sh): its exit is refused on the evidence hold until the case is settled
    if [ "$(jq -r '.s4 // false' scripts/ci/run-inputs.json 2>/dev/null)" = true ]; then export S4_LANE=1; log "S4_LANE=1 (run-inputs s4)"; fi
    # INTERIM EXPERIMENT (not acceptance evidence): run-inputs "evmJournalCandidates": N raises the validators' journal bound (default 256), which #751 shows is what halts the 3-of-4
    # shard ~26 min after the recovery. The publisher marks such a pack INCOMPLETE with that reason, whatever it shows.
    jc=$(jq -r '.evmJournalCandidates // empty' scripts/ci/run-inputs.json 2>/dev/null)
    if [ -n "$jc" ]; then export EVM_JOURNAL_CANDIDATES=$jc CI_INTERIM="EVM_JOURNAL_CANDIDATES=$jc (interim experiment for #751)"; log "INTERIM EXPERIMENT: $CI_INTERIM"; fi
    export X4_EXIT_LANE=1 P85_EVIDENCE_PREFIX=x4-exit-lane P85_LOCK_OWNER=p85-recovery
    log "X4_EXIT_LANE=1 scripts/p85-lane.sh (deadline ${deadline} min)"
    p_timeout "$((deadline * 60))" scripts/p85-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
    lane_rc=${PIPESTATUS[0]}
    if [ "$inject" = in-lane ]; then log "injected harness failure (inject_failure=in-lane) after the exit lane (its own exit was $lane_rc)"; lane_rc=1; fi ;;
  abort)
    export H6_URETH_ATTESTED=$M2_URETH_BIN H6_URETH_ATTESTED_SHA256=$(awk '{print $1; exit}' "$M2_URETH_ATTESTED_PROVENANCE/sha256.txt") H6_URETH_ATTESTED_PROVENANCE=$M2_URETH_ATTESTED_PROVENANCE H6_URETH_COMMIT=$M2_URETH_COMMIT
    log "scripts/h6/abort-rehearsal-lane.sh (deadline ${deadline} min)"
    p_timeout "$((deadline * 60))" scripts/h6/abort-rehearsal-lane.sh 2>&1 | tee "$out/lane-stdout.log" >/dev/null
    lane_rc=${PIPESTATUS[0]}
    # the Abort lane has no step hook: inject_failure=in-lane adds a failing harness step after it ran (the lane's own result is kept in the log; the verdict is the injected failure)
    if [ "$inject" = in-lane ]; then log "injected harness failure (inject_failure=in-lane) after the Abort lane (its own exit was $lane_rc)"; lane_rc=1; fi ;;
esac
log "lane exit $lane_rc"
tail -n 6 "$out/lane-stdout.log" | cut -c1-200
finalize
[ "$lane_rc" -eq 0 ] && [ "${pub_rc:-1}" -eq 0 ]
