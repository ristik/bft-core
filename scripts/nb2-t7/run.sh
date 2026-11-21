#!/usr/bin/env bash
# Run from a fresh, dedicated bft-core checkout on the dev server.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${NB2_OUT:?absolute path to a new evidence directory}"
: "${NB2_CONTRACTS:?pinned contracts checkout with full build}"
: "${NB2_PLUGIN:?pinned plug-in checkout with npm ci and npm run build}"
: "${AGG_BIN:?pinned aggregator executable}"
: "${URETH_BIN:?pinned ureth executable}"
[[ "$NB2_OUT" = /* && ! -e "$NB2_OUT" && ! -e test-nodes ]] ||
  { echo "T7 requires a new absolute evidence path and a fresh checkout" >&2; exit 2; }
if [[ -n "${NB2_SCENARIO_DRIVER:-}" ]]; then
  [[ "$NB2_SCENARIO_DRIVER" = /* && -f "$NB2_SCENARIO_DRIVER" && -x "$NB2_SCENARIO_DRIVER" ]] ||
    { echo "NB2_SCENARIO_DRIVER must be an absolute path to a local executable" >&2; exit 2; }
fi
pins=scripts/nb2-t7/pins.json
for component in contracts plugin; do
  case "$component" in contracts) checkout=$NB2_CONTRACTS;; plugin) checkout=$NB2_PLUGIN;; esac
  [[ "$(git -C "$checkout" rev-parse HEAD)" = "$(jq -r ".$component" "$pins")" ]]
  [[ -z "$(git -C "$checkout" status --porcelain --untracked-files=no)" ]]
done
[[ "$(go version -m "$AGG_BIN" | sed -n 's/.*vcs.revision=//p')" = "$(jq -r .aggregator "$pins")" ]]
[[ "$(go version -m "$AGG_BIN" | sed -n 's/.*vcs.modified=//p')" = false ]]
[[ "$("$URETH_BIN" --version | awk '/Commit SHA/ {print $3}')" = "$(jq -r .ureth "$pins")" ]]
[[ -x build/ubft && -x build/utb-evidence && -x "$NB2_PLUGIN/node_modules/.bin/tsx" ]]
[[ "$(go version -m build/ubft | sed -n 's/.*vcs.revision=//p')" = "$(git rev-parse HEAD)" ]]
mkdir -m 700 "$NB2_OUT"
cp "$pins" "$NB2_OUT/pins.json"
cp build/utb-evidence "$NB2_OUT/utb-evidence"
export POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$(jq -r .ureth "$pins")"
export UTB_COMPONENTS="contracts=$(jq -r .contracts "$pins") aggregator-commit=$(jq -r .aggregator "$pins") aggregator-binary=sha256:$(sha256sum "$AGG_BIN" | cut -d' ' -f1) ureth=$POST_M2A_URETH_COMMIT"
export NB2_T7_LANE=1 M2_PROFILE2=1 Q3_B1=1 UTB_LANE=1 SIGNING=authority DNB_AGG_SHARDS=1
export M2_RUN_LOG_DIR="$NB2_OUT/paired" UTB_VERIFIER="$NB2_OUT/utb-evidence"
export CI_MONGO_NAME="nb2-t7-$$"
claim=$(scripts/lane-slot.sh acquire --owner nb2-t7 --profile paired-default)
read -r LANE_SLOT lane_token <<<"$claim"
export LANE_SLOT
lane_pid=
cleanup() {
  if [[ -n "$lane_pid" ]]; then
    kill -TERM "$lane_pid" 2>/dev/null || true
    wait "$lane_pid" || true
  fi
  bash scripts/ci/mongo-up.sh down "$NB2_OUT/mongo" || true
  scripts/lane-slot.sh release --owner nb2-t7 --token "$lane_token"
}
trap cleanup EXIT
trap 'exit 143' HUP INT TERM
bash scripts/ci/mongo-up.sh up "$NB2_OUT/mongo"
bash scripts/reth-paired-devnet.sh 4 10 &
lane_pid=$!
rc=0
wait "$lane_pid" || rc=$?
lane_pid=
exit "$rc"
