#!/usr/bin/env bash
# The any-age final lane (briefs/anyage-final-lane-plan.md, briefs/b1-any-age-acceptance-matrix.md "Minimal final lane"): one fresh-genesis run with
#   L1  retained old proofs verified after a handoff past the retired 30-round window, reused in the historical epoch after L2, one vault release;
#   L2  the first post-freeze acknowledgement block of the P85 primary -> stalled successor -> exact recovery installs both entries (span 2).
#
#   scripts/anyage-lane.sh --preflight     checks every pin, binary, checkout and tool and prints the step plan; starts NOTHING, takes no lock
#   scripts/anyage-lane.sh --plan          prints the step plan only
#   scripts/anyage-lane.sh --prep          dry run of the genesis side (ANYAGE_PREP_ONLY): P85 genesis, profile, identities, aggregator shard configurations and the
#                                          bridge deployment derived from them; starts no reth, root, validator or aggregator; needs the same env as the run
#   scripts/anyage-lane.sh                 the run: refuses unless the preflight is entirely ok; then the P85 runner under the devnet lock (owner "anyage")
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
source "$SCRIPT_DIR/lib/anyage-lib.sh"
ok=0 bad=0
yes() { printf '  ok    %s\n' "$1"; ok=$((ok + 1)); }
no() { printf '  FAIL  %s\n' "$1"; bad=$((bad + 1)); }
note() { printf '  note  %s\n' "$1"; }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then yes "$what"; else no "$what"; fi; }

plan() {
  cat <<'PLAN'
anyage lane steps (one fresh genesis; every step prints PASS/FAIL; evidence under briefs/devnet-runs/anyage-<utc>/):
  0  preflight (this script) and the devnet lock; run-mode, pins, pmset, SHA256SUMS as the P85 lane records them
  1  genesis: PoS genesis (custody, election, four bonded entities) + bridge (aggregator shard(s), verifier, vault) on the permanent-layout registry   [gap G1]
  2  baseline: registry dump (format 2, I=U=g..), the P85 baseline steps
  3  L1a  burn/lock a supported token; SAVE its exact original UC/proof bytes and hashes; dump the registry (epoch/start/end/O)
  4  P85: joiner nodes, onboarding, election reserved, proofs, handoff (primary J), install/activation
  5  L1b  once O - r exceeds the old 30-round window, eth_call-verify the SAVED proofs in the current epoch; vault release prepared (NOT sent)
  6  P85: J stalls (2 of 5 EVM validators), derived recovery back to K  ->  L2: locate the acknowledgement block, dump its parent and itself, offline check:
        I jumps by 2 in ONE block built directly on the frozen parent, both entries consecutive, old tip closed once, I=U=E, hooks once
  7  L1c  after L2, eth_call-verify the SAME saved proofs against the historical epoch; send the ONE vault release; claim; balance delta, nullifier
  8  restarts (P85), final dumps, teardown through scripts/p85-stop.sh only; evidence checksums
PLAN
}

preflight() {
  echo "== any-age final lane preflight (no devnet is started) =="
  echo "-- tools"
  export PATH="$HOME/.foundry/bin:$PATH"
  for t in cast forge jq python3 go curl git gh node npm; do check "$t on PATH" command -v "$t"; done
  check "cast is Foundry 1.8.x" bash -c 'cast --version | grep -q "1\.8\."'
  check "node >= 22" bash -c '[ "$(node -p "process.versions.node.split(\".\")[0]")" -ge 22 ]'
  check "anyage tooling self-test (slot derivations equal the Go ones; registry_check selftest)" bash -c "source '$SCRIPT_DIR/lib/anyage-lib.sh'; ANYAGE_CHECK='$SCRIPT_DIR/anyage/registry_check.py' anyage_selftest"
  echo "-- machine"
  free=$(df -k "$AGRE_ROOT" | awk 'NR==2{print int($4/1048576)}')
  if [ "${free:-0}" -ge 25 ]; then yes "free disk ${free} GiB (>= 25)"; else no "free disk ${free:-?} GiB (< 25)"; fi
  [ -x "$AGRE_ROOT/briefs/devnet-lock.sh" ] && yes "devnet lock helper present" || no "devnet lock helper missing"
  if [ -d "$AGRE_ROOT/.devnet-lock" ]; then note "the devnet lock is HELD by: $(cat "$AGRE_ROOT/.devnet-lock/owner" 2>/dev/null) (the run would queue)"; else yes "devnet lock is free"; fi
  echo "-- merged prerequisites (read-only gh queries on ristik/*)"
  for pr in "ristik/ureth 70" "ristik/unicity-pos-contracts 39" "ristik/native-bridge-plugins 17" "ristik/bft-core 611"; do
    set -- $pr; st=$(gh pr view "$2" -R "$1" --json state --jq .state 2>/dev/null || echo unknown)
    if [ "$st" = MERGED ]; then yes "$1#$2 merged"; else no "$1#$2 is $st (must be MERGED before the run)"; fi
  done
  echo "-- bft-core checkout"
  check "clean checkout" bash -c "[ -z \"\$(git -C '$REPO_ROOT' status --porcelain --untracked-files=no)\" ]"
  head=$(git -C "$REPO_ROOT" rev-parse HEAD)
  check "HEAD contains origin/integration/enshrined-evm (incl. #611)" git -C "$REPO_ROOT" merge-base --is-ancestor origin/integration/enshrined-evm HEAD
  if [ -x "$REPO_ROOT/build/ubft" ] && go version -m "$REPO_ROOT/build/ubft" 2>/dev/null | grep -q "vcs.revision=$head" && ! go version -m "$REPO_ROOT/build/ubft" | grep -q 'vcs.modified=true'; then yes "build/ubft is built from HEAD ${head:0:10}"; else no "build/ubft is missing or not built from HEAD ${head:0:10} (make build)"; fi
  echo "-- ureth (attested build)"
  if [ -n "${M2_URETH_BIN:-}" ] && [ -x "$M2_URETH_BIN" ] && [ -n "${M2_URETH_COMMIT:-}" ]; then
    rep=$("$M2_URETH_BIN" --version 2>&1 | sed -n 's/^Commit SHA: //p' | head -1)
    case "$rep" in "$M2_URETH_COMMIT"*) yes "binary reports commit ${rep:0:10}";; *) no "binary reports '$rep', expected $M2_URETH_COMMIT";; esac
    prov=${M2_URETH_ATTESTED_PROVENANCE:-$AGRE_ROOT/briefs/builds/ureth-${rep:0:8}}
    if [ -s "$prov/sha256.txt" ] && [ "$(awk '{print $1; exit}' "$prov/sha256.txt")" = "$(shasum -a 256 "$M2_URETH_BIN" | cut -d' ' -f1)" ] && [ "$(tr -d '[:space:]' <"$prov/commit.txt")" = "$rep" ]; then yes "provenance $prov records this binary and commit"; else no "no provenance record at $prov for this binary"; fi
    # the permanent layout and the batch precompile must be in the build: the binary must accept the new profile flag
    if "$M2_URETH_BIN" node --help 2>&1 | grep -q 'max-epochs-per-update'; then yes "ureth accepts --unicity.max-epochs-per-update"; else no "ureth does not know --unicity.max-epochs-per-update (build predates ureth#70?)"; fi
  else
    no "set M2_URETH_BIN and M2_URETH_COMMIT to the attested build that contains ureth#70"
  fi
  echo "-- contracts"
  if [ -n "${P85_CONTRACTS:-}" ] && [ -x "$P85_CONTRACTS/script/p85-genesis.sh" ]; then
    check "contracts checkout clean" bash -c "[ -z \"\$(git -C '$P85_CONTRACTS' status --porcelain --untracked-files=no)\" ]"
    art=$(python3 -c "import json;print(json.load(open('$P85_CONTRACTS/artifacts/seal-registry.json'))['codeHash'])" 2>/dev/null)
    want=$(sed -n 's/^const CodeHashHex = "\(0x[0-9a-f]*\)"/\1/p' "$REPO_ROOT/b1registry/artifact.go")
    if [ -n "$art" ] && [ "$art" = "$want" ]; then yes "contracts registry artifact code hash equals bft-core's pin ($want)"; else no "contracts registry code hash '$art' != bft-core pin '$want'"; fi
    check "xrepo shared fixtures identical to the contracts checkout" python3 "$REPO_ROOT/xrepo/check.py" --bft-core "$REPO_ROOT" --contracts "$P85_CONTRACTS"
    check "BridgeDeploy script present" test -e "$P85_CONTRACTS/script/BridgeDeploy.s.sol"
  else
    no "set P85_CONTRACTS to a unicity-pos-contracts checkout containing contracts#39"
  fi
  echo "-- plug-ins and aggregator"
  if [ -n "${NBP_DIR:-}" ] && [ -d "$NBP_DIR/tests/live" ]; then
    check "nbp checkout clean" bash -c "[ -z \"\$(git -C '$NBP_DIR' status --porcelain --untracked-files=no)\" ]"
    check "nbp dependencies installed (node_modules)" test -d "$NBP_DIR/node_modules"
    check "nbp live driver has the any-age entry points (anyage.ts)" test -e "$NBP_DIR/tests/live/anyage.ts"
  else
    no "set NBP_DIR to a native-bridge-plugins checkout containing nbp#17 (tests/live)"
  fi
  [ -n "${AGG_BIN:-}" ] && [ -x "$AGG_BIN" ] && yes "AGG_BIN $AGG_BIN" || no "set AGG_BIN to the pinned aggregator-go binary"
  [ -n "${DNB_TOOL:-}" ] && [ -x "$DNB_TOOL" ] && yes "DNB_TOOL $DNB_TOOL" || no "set DNB_TOOL to a dnb-tool built from this checkout (go build -o ... ./scripts/dnb-tool)"
  if (exec 3<>/dev/tcp/127.0.0.1/27117) 2>/dev/null; then yes "MongoDB replica set port 27117 answers"; else no "no MongoDB on 127.0.0.1:27117 (colima + the mongo:7 replset container; aggregator-go needs it)"; fi
  echo "-- substrate"
  if grep -q 'ANYAGE_LANE' "$REPO_ROOT/scripts/reth-paired-devnet.sh" 2>/dev/null; then yes "reth-paired-devnet.sh supports ANYAGE_LANE (aggregator + bridge on the P85 genesis)"; else no "reth-paired-devnet.sh has no ANYAGE_LANE (PoS genesis + aggregator shard + bridge deploy in one genesis)"; fi
  check "the combined genesis dry run was done on this HEAD (scripts/anyage-lane.sh --prep): record at briefs/devnet-runs/anyage-prep-<head>.ok" test -e "$AGRE_ROOT/briefs/devnet-runs/anyage-prep-${head:0:12}.ok"
  echo
  echo "preflight: $ok ok, $bad not ready"
  [ "$bad" -eq 0 ]
}

# The environment the P85 runner and the combined devnet read (CONTRACTS is the bridge deploy's name for the contracts checkout)
lane_env() { export ANYAGE_LANE=1 P85_LOCK_OWNER=anyage P85_EVIDENCE_PREFIX=anyage CONTRACTS=${P85_CONTRACTS:-}; }

case "${1:-}" in
  --plan) plan ;;
  --preflight) plan; echo; preflight ;;
  --prep)
    # A dry run of the genesis side. It takes the devnet lock (it writes test-nodes/ and ports are not touched, but the checkout is the lane's) and stops
    # before any reth, root, validator or aggregator is started.
    lane_env
    [ -n "${P85_CONTRACTS:-}" ] && [ -n "${DNB_TOOL:-}" ] || { echo "--prep needs P85_CONTRACTS, M2_URETH_BIN, M2_URETH_COMMIT, DNB_TOOL (and P85_DEV_RUN=1 unless the provenance is attested)" >&2; exit 2; }
    export ANYAGE_PREP_ONLY=1
    exec "$AGRE_ROOT/briefs/devnet-lock.sh" anyage-prep env P85_LANE_LOCKED=1 "$SCRIPT_DIR/p85-lane.sh" ;;
  "")
    plan; echo
    preflight || { echo "REFUSED: the preflight is not entirely ok; nothing was started." >&2; exit 3; }
    lane_env
    exec "$SCRIPT_DIR/p85-lane.sh" ;;
  *) echo "usage: $0 [--plan|--preflight|--prep]" >&2; exit 2 ;;
esac
