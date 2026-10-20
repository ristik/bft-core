#!/usr/bin/env bash
# The combined UTB acceptance lane (briefs/utb-signed-entries-design.md §11.4): the any-age/P85 lane (one aggregation partition, the EVM shard, ordinary
# handoff K->J with acknowledgement, stalled successor L and exact-K recovery) with the signed trust-base entry profile on from the first voting epoch,
# the aggregator of ristik/aggregator-go integration/enshrined-evm at a pinned commit (§11.3), an independent reference client and the JS SDK client.
#
#   scripts/utb-lane.sh --preflight    checks every pin, binary, checkout, manifest and tool and prints the step plan; starts NOTHING, takes no lock
#   scripts/utb-lane.sh --plan         prints the step plan only
#   scripts/utb-lane.sh --selftest     chain-free tests of the lane's own logic (genesis/manifest generation, flags, the evidence-pack checker)
#   scripts/utb-lane.sh --build-aggregator   AGG_COMMIT=<40 hex>: clone, build and record the aggregator (builds/aggregator-<sha8>/); pushes nothing
#   scripts/utb-lane.sh --prep         dry run of the genesis side (ANYAGE_PREP_ONLY with UTB_LANE=1): P85 genesis, the UTB genesis entry, pin and manifest,
#                                      aggregator shard configurations and the bridge deployment; starts no reth, root, validator or aggregator
#   scripts/utb-lane.sh --check-evidence DIR   checks an evidence directory against the required list (design §11.4)
#   scripts/utb-lane.sh                the run: refuses unless the preflight is entirely ok
#
# Entries of the run: epoch 2 is the K->J handoff (the P85 J never acknowledges), epoch 3 the derived recovery. The design's acknowledged-J / stalled-L / recovery sequence
# (three entries) is not what the P85 flow does; the plan below says what is exercised instead.
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
cd "$REPO_ROOT" || exit 1
source "$SCRIPT_DIR/lib/utb-lib.sh"
ok=0 bad=0
yes() { printf '  ok    %s\n' "$1"; ok=$((ok + 1)); }
no() { printf '  FAIL  %s\n' "$1"; bad=$((bad + 1)); }
note() { printf '  note  %s\n' "$1"; }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then yes "$what"; else no "$what"; fi; }

plan() {
  cat <<'PLAN'
UTB lane steps (one fresh genesis, the any-age/P85 machinery + UTB_LANE=1; evidence under briefs/devnet-runs/utb-<utc>/p85/utb, required list: --check-evidence).
Entries: epoch 2 is the K->J handoff (activated; the P85 J is never acknowledged), epoch 3 the derived recovery to K (the acknowledgement block installs both, span 2).
  0  preflight (this script), the devnet lock, the manifest: pins, builds, the aggregator commit, the genesis entry and its pin
  1  genesis: PoS genesis + bridge + aggregator shard + the UTB genesis entry (canonical V2, null signatures), generated once from the epoch-1 trust base
  2  U1  after the baseline and L1a: the aggregator serves the genesis only; the original token (its exact bytes and digest) is saved and verifies under the genesis committee;
         the reference client (its own durable store) starts from the genesis
  3  U2  after the K->J activation: the aggregator receives the epoch-2 entry attached to a version 3 certification response (log: received + appended, no catch-up), the root's
         message is captured and decodes to exactly that entry; the aggregator serves epoch 2
  4  U3a the aggregator restarts from its retained store (unchanged records); then it is stopped and its history store removed (the controlled fault)
  5  P85 stalled J and the derived recovery to K (epoch 3), liability closures
  6  U3b the aggregator restarts holding the genesis only, root HTTP unavailable to it: it repairs epochs 2..3 from a genesis-committee root over GetTrustBase (log: catch-up
         started / OK page from a root / finished); it serves epoch 3
  7  L2  the acknowledgement block installs both entries; U4 a token certified after the recovery; the stale client meets the unknown epoch 3, fetches [2 3] in one request
         and verifies; the aggregator restarts again, unchanged bytes, healthy;  U4b the JS SDK (the fork, UTB_SDK_JS) holds the genesis only, meets epoch 3 on the same
         certificate, fetches epochs 2..3 from the aggregator's GetTrustBase endpoint with its fetch-and-retry loop and verifies; its entries equal the history's bytes
  8  L1c the same saved bytes verify against the historical epoch; the one vault release;  U5 the original token verifies unchanged under its historical committee (utb-evidence),
         the bridge receipt, the complete history exported and reloaded by a fresh client store: identical records and tip
  9  restarts (P85); the root logs counted (V3 freeze rules are not enabled = 0, successor trust-base entry cannot be derived = 0, recoveries completed reported); the evidence pack assembled and checked by the tools (self-contained), teardown through scripts/p85-stop.sh only
PLAN
}

preflight() {
  echo "== UTB lane preflight (no devnet is started) =="
  echo "-- tools"
  export PATH="$HOME/.foundry/bin:$PATH"
  for t in cast forge jq python3 go curl git gh node npm shasum; do check "$t on PATH" command -v "$t"; done
  echo "-- merged prerequisites (read-only gh queries on ristik/*)"
  for pr in "ristik/bft-core 632" "ristik/bft-core 633" "ristik/bft-core 634" "ristik/bft-core 635" "ristik/bft-core 650" "ristik/aggregator-go 2" "ristik/bft-go-base 1" "ristik/ureth 70" "ristik/unicity-pos-contracts 39" "ristik/native-bridge-plugins 19"; do
    set -- $pr; st=$(gh pr view "$2" -R "$1" --json state --jq .state 2>/dev/null || echo unknown)
    if [ "$st" = MERGED ]; then yes "$1#$2 merged"; else no "$1#$2 is $st (must be MERGED before the run)"; fi
  done
  echo "-- bft-core checkout and build"
  check "clean checkout" bash -c "[ -z \"\$(git -C '$REPO_ROOT' status --porcelain --untracked-files=no)\" ]"
  head=$(git -C "$REPO_ROOT" rev-parse HEAD)
  check "HEAD contains origin/integration/enshrined-evm" git -C "$REPO_ROOT" merge-base --is-ancestor origin/integration/enshrined-evm HEAD
  if [ -x "$UBFT" ] && go version -m "$UBFT" 2>/dev/null | grep -q "vcs.revision=$head" && ! go version -m "$UBFT" | grep -q 'vcs.modified=true'; then yes "$UBFT is built from HEAD ${head:0:10}"; else no "$UBFT is missing or not built from HEAD ${head:0:10} (make build)"; fi
  # the participant binaries must know the profile: a binary that predates it would start a node that silently runs the plain protocol
  for sub in "root-node run" "shard-node run"; do
    check "$sub accepts --utb-genesis/--utb-genesis-id" bash -c "$UBFT $sub --help 2>&1 | grep -q -- '--utb-genesis-id'"
  done
  check "trust-base utb-manifest and utb-genesis exist" bash -c "$UBFT trust-base --help 2>&1 | grep -q utb-manifest && $UBFT trust-base --help 2>&1 | grep -q utb-genesis"
  check "trust-base utb-verify/utb-export exist (PR6: the independent verifier)" bash -c "$UBFT trust-base --help 2>&1 | grep -q utb-verify && $UBFT trust-base --help 2>&1 | grep -q utb-export"
  note "deploy/testnet/pins.json pins bft $(python3 -c "import json;print(json.load(open('$REPO_ROOT/deploy/testnet/pins.json'))['bft'][:10])" 2>/dev/null): the testnet package is NOT what this lane runs (devnet scripts + build/ubft)"
  echo "-- the independent verifier"
  check "utb-evidence builds (scripts/utb-evidence) into $UTB_EVIDENCE" bash -c "cd '$REPO_ROOT' && go build -o '$UTB_EVIDENCE' ./scripts/utb-evidence"
  echo "-- machine"
  free=$(df -k "$AGRE_ROOT" | awk 'NR==2{print int($4/1048576)}')
  # the lane itself writes about 1 GiB (the 25 GiB default also covers building ureth/contracts); a run with prebuilt, attested builds on a shared disk may
  # lower it (the preflight prints the value it checked against; it is not part of the evidence directory)
  min=${UTB_MIN_FREE_GIB:-25}
  if [ "${free:-0}" -ge "$min" ]; then yes "free disk ${free} GiB (>= $min)"; else no "free disk ${free:-?} GiB (< $min)"; fi
  [ -x "$AGRE_ROOT/briefs/devnet-lock.sh" ] && yes "devnet lock helper present" || no "devnet lock helper missing"
  if [ -d "$AGRE_ROOT/.devnet-lock" ]; then note "the devnet lock is HELD by: $(cat "$AGRE_ROOT/.devnet-lock/owner" 2>/dev/null) (the run would queue)"; else yes "devnet lock is free"; fi
  echo "-- ureth (attested build) and contracts: as the any-age lane (scripts/anyage-lane.sh --preflight checks them; this lane runs the same builds)"
  if [ -n "${M2_URETH_BIN:-}" ] && [ -x "$M2_URETH_BIN" ] && [ -n "${M2_URETH_COMMIT:-}" ]; then yes "M2_URETH_BIN $M2_URETH_BIN @ ${M2_URETH_COMMIT:0:10}"; else no "set M2_URETH_BIN and M2_URETH_COMMIT to the attested ureth build"; fi
  if [ -n "${P85_CONTRACTS:-}" ] && [ -d "$P85_CONTRACTS" ]; then yes "P85_CONTRACTS $P85_CONTRACTS"; else no "set P85_CONTRACTS to the contracts checkout"; fi
  check "the contracts genesis takes the root network and genesis identity (contracts#46: P85_ROOT_NETWORK, P85_ROOT_GENESIS; the lane sets both from the trust base)" bash -c "grep -q P85_ROOT_GENESIS '${P85_CONTRACTS:-/nonexistent}/script/P85Genesis.s.sol' && grep -q P85_ROOT_NETWORK '${P85_CONTRACTS:-/nonexistent}/script/P85Genesis.s.sol'"
  note "contracts#46 changes the manifest hash and the publication fixture: the copies under evmassign/testdata and rootchain/evmstate/testdata and the xrepo/fixtures.json pin are re-copied at the #46 merge commit (checked: the new fixture passes evmassign, evmstate, xrepo, posrelayer, signingauthority)"
  if [ -n "${NBP_DIR:-}" ] && [ -d "$NBP_DIR/tests/live" ]; then yes "NBP_DIR $NBP_DIR"; else no "set NBP_DIR to the native-bridge-plugins checkout"; fi
  check "NBP_DIR's live driver reads the trust-base release bundle (native-bridge-plugins#27, a lane prerequisite: the lane writes trust-base.bundle.cbor since bft-core#658 and no sdk-trust-base.json)" bash -c "grep -q 'trust-base.bundle.cbor' '${NBP_DIR:-/nonexistent}/tests/live/anyage.ts'"
  [ -n "${DNB_TOOL:-}" ] && [ -x "$DNB_TOOL" ] && yes "DNB_TOOL $DNB_TOOL" || no "set DNB_TOOL to a dnb-tool built from this checkout"
  if (exec 3<>/dev/tcp/127.0.0.1/27117) 2>/dev/null; then yes "MongoDB replica set port 27117 answers"; else no "no MongoDB on 127.0.0.1:27117"; fi
  echo "-- the aggregator (ristik/aggregator-go integration/enshrined-evm at AGG_COMMIT, built by --build-aggregator; provenance builds/aggregator-<sha8>/)"
  if [ -n "${AGG_BIN:-}" ] && [ -x "$AGG_BIN" ]; then
    yes "AGG_BIN $AGG_BIN"
    if prov=$(utb_agg_provenance "$AGG_BIN" "$AGRE_ROOT/builds" 2>/dev/null); then yes "provenance $prov records this binary and its commit (the binary reports the same revision)"; else no "$(utb_agg_provenance "$AGG_BIN" "$AGRE_ROOT/builds" 2>&1 | tail -1)"; fi
    if [ -n "${AGG_COMMIT:-}" ] && [ -n "${prov:-}" ]; then
      [ "$(tr -d '[:space:]' <"$prov/commit.txt")" = "$AGG_COMMIT" ] && yes "the binary is the pinned AGG_COMMIT ${AGG_COMMIT:0:10}" || no "the binary's commit is not AGG_COMMIT ${AGG_COMMIT:0:10}"
    else no "set AGG_COMMIT to the pinned aggregator-go commit (40 hex)"; fi
    if [ -n "${prov:-}" ]; then
      if pinned=$(utb_agg_pins_ok "$prov" "$REPO_ROOT" 2>&1); then yes "the aggregator's bft-core ($pinned) is in this checkout's history"; else no "$pinned"; fi
    fi
    check "the binary is a UTB build (its UTB variables are in the binary)" bash -c "strings '$AGG_BIN' | grep -q UTB_GENESIS_ID"
    check "the binary logs an attachment which adds nothing (aggregator-go#4: 'trust-base update already held'; U2 needs it when the catch-up wins)" bash -c "strings '$AGG_BIN' | grep -q 'trust-base update already held'"
    check "the binary speaks the combined response (CertificationResponseV3 is in the binary)" bash -c "strings '$AGG_BIN' | grep -q 'received CertificationResponseV3'"
  else
    no "set AGG_BIN to the aggregator built by: AGG_COMMIT=<40 hex> $0 --build-aggregator"
  fi
  echo "-- the JS SDK client (ristik/state-transition-sdk-js integration/enshrined-evm, built)"
  if [ -n "${UTB_SDK_JS:-}" ] && [ -f "$UTB_SDK_JS/lib/util/TrustBaseUtils.js" ]; then
    yes "UTB_SDK_JS $UTB_SDK_JS"
    check "UTB_SDK_JS is a clean git checkout" bash -c "[ -z \"\$(git -C '$UTB_SDK_JS' status --porcelain --untracked-files=no)\" ]"
    check "UTB_SDK_JS contains origin/integration/enshrined-evm (the trust-base history and fetch-and-retry are on it)" git -C "$UTB_SDK_JS" merge-base --is-ancestor origin/integration/enshrined-evm HEAD
    check "node runs the client check (syntax)" node --check "$REPO_ROOT/scripts/utb-sdk-client/check.mjs"
  else
    no "set UTB_SDK_JS to a built checkout of the SDK fork (npm ci && npm run build)"
  fi
  note "the aggregator history range is served at $(utb_agg_history_url 1) (GET /api/v1/trustbases)"
  echo "-- substrate and the generated genesis"
  check "reth-paired-devnet.sh supports UTB_LANE" grep -q 'UTB_LANE' "$REPO_ROOT/scripts/reth-paired-devnet.sh"
  check "helper.sh hands the profile to roots and validators" bash -c "grep -c 'UTB_LANE' '$REPO_ROOT/helper.sh' | grep -qx 2"
  check "m2_start_root keeps the profile on a restarted root" grep -q 'UTB_ROOT_FLAGS_FN' "$REPO_ROOT/scripts/lib/m2-handoff-lib.sh"
  if [ -s test-nodes/utb/utb-manifest.json ]; then
    check "the generated manifest checks out against its trust base" "$UBFT" trust-base utb-manifest --check test-nodes/utb/utb-manifest.json
    rev=$(python3 -c "import json;print(json.load(open('test-nodes/utb/utb-manifest.json'))['build']['bftCoreRevision'])" 2>/dev/null)
    [ "$rev" = "$head" ] && yes "the manifest was generated by a ubft built from HEAD" || no "the manifest's bft-core revision '${rev:0:10}' is not HEAD ${head:0:10} (regenerate: --prep)"
  else
    note "no generated manifest yet (test-nodes/utb/utb-manifest.json): --prep creates it"
  fi
  check "the genesis dry run was done on this HEAD (scripts/utb-lane.sh --prep): record at briefs/devnet-runs/utb-prep-<head>.ok" test -e "$AGRE_ROOT/briefs/devnet-runs/utb-prep-${head:0:12}.ok"
  check "the lane's own self-test passes" bash -c "UBFT='$UBFT' UTB_ST_TRUSTBASE='${UTB_ST_TRUSTBASE:-}' bash -c 'source $SCRIPT_DIR/lib/utb-lib.sh; utb_selftest'"
  echo
  echo "preflight: $ok ok, $bad not ready"
  [ "$bad" -eq 0 ]
}

# outside build/ (make build clears it) and absolute (the lane steps run in other directories)
UTB_EVIDENCE=${UTB_EVIDENCE:-$(cd "$REPO_ROOT/.." && pwd)/builds/utb-evidence-pr7}
lane_env() { export UTB_EVIDENCE ANYAGE_LANE=1 UTB_LANE=1 P85_LOCK_OWNER=utb P85_EVIDENCE_PREFIX=utb CONTRACTS=${P85_CONTRACTS:-} UTB_COMPONENTS="$(utb_lane_components)"; }

case "${1:-}" in
  --plan) plan ;;
  --selftest)
    : "${UTB_ST_TRUSTBASE:?set UTB_ST_TRUSTBASE to an epoch-1 trust base file (for example test-nodes/trust-base.json of any devnet genesis)}"
    utb_selftest ;;
  --build-aggregator)
    : "${AGG_COMMIT:?set AGG_COMMIT to the 40-hex aggregator-go commit on integration/enshrined-evm}"
    bin=$(utb_agg_build "$AGG_COMMIT" "$AGRE_ROOT/builds") || exit 1
    prov=$(utb_agg_provenance "$bin" "$AGRE_ROOT/builds") || exit 1
    echo "built $bin"; echo "provenance $prov"; utb_agg_pins_ok "$prov" "$REPO_ROOT" || echo "WARNING: re-pin the aggregator to a bft-core in this checkout's history before the real run" >&2 ;;
  --check-evidence) utb_check_evidence "${2:?usage: $0 --check-evidence DIR}" && echo "evidence complete" ;;
  --preflight) plan; echo; preflight ;;
  --prep)
    lane_env
    [ -n "${P85_CONTRACTS:-}" ] && [ -n "${DNB_TOOL:-}" ] || { echo "--prep needs P85_CONTRACTS, M2_URETH_BIN, M2_URETH_COMMIT, DNB_TOOL (and P85_DEV_RUN=1 unless the provenance is attested)" >&2; exit 2; }
    export ANYAGE_PREP_ONLY=1
    "$AGRE_ROOT/briefs/devnet-lock.sh" utb-prep env P85_LANE_LOCKED=1 "$SCRIPT_DIR/p85-lane.sh"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf '%s\n%s\n' "prep-only dry run on bft-core $(git -C "$REPO_ROOT" rev-parse HEAD) at $(date -u +%FT%TZ)" "${P85_DEV_RUN:+DEVELOPMENT RUN (P85_DEV_RUN=1): binary and checkout not attested}" >"$AGRE_ROOT/briefs/devnet-runs/utb-prep-$(git -C "$REPO_ROOT" rev-parse HEAD | cut -c1-12).ok"
    fi
    exit "$rc" ;;
  "")
    plan; echo
    preflight || { echo "REFUSED: the preflight is not entirely ok; nothing was started." >&2; exit 3; }
    lane_env
    exec "$SCRIPT_DIR/p85-lane.sh" ;;
  *) echo "usage: $0 [--plan|--preflight|--selftest|--build-aggregator|--prep|--check-evidence DIR]" >&2; exit 2 ;;
esac
