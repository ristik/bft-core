#!/usr/bin/env bash
# Run from a fresh, dedicated bft-core checkout on the dev server.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${NB2_OUT:?absolute path to a new evidence directory}"
: "${NB2_CONTRACTS:?pinned contracts checkout with full build}"
: "${NB2_PLUGIN:?pinned plug-in source checkout}"
: "${AGG_BIN:?pinned aggregator executable}"
: "${URETH_BIN:?pinned ureth executable}"
: "${NB2_URETH_SOURCE:?checkout containing the pinned Ureth source}"
NB2_LANE_SLOT=${NB2_LANE_SLOT:-2}
case "$NB2_LANE_SLOT" in
  0|2|wait) ;;
  3)
    : "${NB2_HOST_NETNS:?host namespace identity required for slot 3}"
    : "${NB2_MONGO_BIN_DIR:?local MongoDB binaries required for slot 3}"
    [[ "$(readlink /proc/self/ns/net)" != "$NB2_HOST_NETNS" &&
       "$(ip -o link show | wc -l)" -eq 1 ]] && ip -o link show dev lo up | grep -q . ||
      { echo "NB2 slot 3 requires a separate loopback-only namespace" >&2; exit 2; }
    ;;
  *) echo "NB2 T7 requires private slot 0, 2 or isolated slot 3" >&2; exit 2 ;;
esac
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
[[ -x build/ubft && -x build/utb-evidence ]]
[[ "$(go version -m build/ubft | sed -n 's/.*vcs.revision=//p')" = "$(git -C "$PWD" rev-parse HEAD)" ]]
mkdir -m 700 "$NB2_OUT"
cp "$pins" "$NB2_OUT/pins.json"
cp build/utb-evidence "$NB2_OUT/utb-evidence"
export POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$(jq -r .ureth "$pins")"
export UTB_COMPONENTS="contracts=$(jq -r .contracts "$pins") aggregator-commit=$(jq -r .aggregator "$pins") aggregator-binary=sha256:$(sha256sum "$AGG_BIN" | cut -d' ' -f1) ureth=$POST_M2A_URETH_COMMIT"
export NB2_T7_LANE=1 M2_PROFILE2=1 Q3_B1=1 UTB_LANE=1 SIGNING=authority DNB_AGG_SHARDS=1
export M2_RUN_LOG_DIR="$NB2_OUT/paired" UTB_VERIFIER="$NB2_OUT/utb-evidence"
lane_owner=${NB2_LANE_OWNER:-nb2-t7}
lane_token=
lane_pid=
mongo_started=
mongo_pid=
mongo_data=
plugin_build=$(mktemp -d "$NB2_OUT/.plugin.XXXXXX")
cleanup() {
  trap '' TERM HUP INT
  if [[ -n "$lane_pid" ]]; then
    kill -TERM "$lane_pid" 2>/dev/null || true
    wait "$lane_pid" || true
  fi
  if [[ -n "$mongo_pid" ]]; then
    kill -TERM "$mongo_pid" 2>/dev/null || true
    wait "$mongo_pid" || true
  elif [[ -n "$mongo_started" ]]; then
    bash scripts/ci/mongo-up.sh down "$NB2_OUT/mongo" || true
  fi
  if [[ -n "$mongo_data" ]]; then rm -rf -- "$mongo_data"; fi
  if [[ -n "$lane_token" ]]; then
    (unset LANE_SLOT; scripts/lane-slot.sh release --owner "$lane_owner" --token "$lane_token") || true
  fi
  rm -rf -- "$plugin_build"
}
trap cleanup EXIT
trap 'exit 143' HUP INT TERM
bash scripts/nb2-t7/build-plugin.sh "$NB2_PLUGIN" "$(jq -r .plugin "$pins")" "$plugin_build/source"
export NB2_PLUGIN="$plugin_build/source"
(
  cd "$NB2_PLUGIN"
  find packages/native-bridge-plugin/lib -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) >"$NB2_OUT/plugin-lib.sha256"
if [[ "${NB2_QUALIFY_ERC20:-0}" = 1 ]]; then
  source scripts/nb2-t7/erc20-build.sh
fi
lane_token=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
# Bash defers the launcher's signal trap until this foreground acquisition finishes.
# Let the helper finish even when the terminal signals the whole process group.
acquire() (
  trap '' TERM HUP INT
  scripts/lane-slot.sh acquire --owner "$lane_owner" --profile paired-default --token "$lane_token" --slot "$1"
)
if [[ "$NB2_LANE_SLOT" = wait ]]; then
  while :; do
    for slot in 0 2; do
      if claim=$(acquire "$slot" 2>"$plugin_build/acquire.log"); then
        break 2
      else
        rc=$?
      fi
      if [[ "$rc" != 75 ]]; then
        cat "$plugin_build/acquire.log" >&2
        exit "$rc"
      fi
    done
    sleep 10
  done
else
  claim=$(acquire "$NB2_LANE_SLOT")
fi
read -r LANE_SLOT _ <<<"$claim"
export LANE_SLOT
printf '%s\n' "$LANE_SLOT" >"$NB2_OUT/slot.txt"
if [[ "$LANE_SLOT" = 3 ]]; then
  readlink /proc/self/ns/net >"$NB2_OUT/network-namespace.txt"
  cat /proc/sys/net/ipv4/ip_local_port_range >"$NB2_OUT/namespace-port-range.txt"
  ip -o addr show >"$NB2_OUT/namespace-addresses.txt"
  ip route show table main >"$NB2_OUT/namespace-routes.txt"
  source scripts/lib/lane-slot.sh
  port=$((27117 + LANE_PORT_OFFSET))
  mkdir "$NB2_OUT/mongo"
  mongo_data=$(mktemp -d "$NB2_OUT/.mongo-data.XXXXXX")
  cp "$NB2_MONGO_BIN_DIR/image.txt" "$NB2_OUT/mongo/mongo-image.txt"
  sha256sum "$NB2_MONGO_BIN_DIR/"{mongod,mongosh} >"$NB2_OUT/mongo/binaries.sha256"
  "$NB2_MONGO_BIN_DIR/mongod" --dbpath "$mongo_data" --replSet rs0 \
    --bind_ip 127.0.0.1 --port "$port" >"$NB2_OUT/mongo/mongo.log" 2>&1 &
  mongo_pid=$!
  mongo_shell=("$NB2_MONGO_BIN_DIR/mongosh" --quiet --port "$port")
  for _ in $(seq 1 60); do
    kill -0 "$mongo_pid"
    if "${mongo_shell[@]}" --eval 'db.adminCommand({ping:1}).ok' 2>/dev/null | grep -qx 1; then break; fi
    sleep 1
  done
  "${mongo_shell[@]}" --eval "rs.initiate({_id:'rs0',members:[{_id:0,host:'127.0.0.1:$port'}]})" \
    >"$NB2_OUT/mongo/rs-initiate.txt" 2>&1
  for _ in $(seq 1 60); do
    kill -0 "$mongo_pid"
    if "${mongo_shell[@]}" --eval 'db.hello().isWritablePrimary' 2>/dev/null | grep -qx true; then break; fi
    sleep 1
  done
  "${mongo_shell[@]}" --eval 'db.hello().isWritablePrimary' | grep -qx true
  ss -lnt >"$NB2_OUT/loopback-listeners.txt"
else
  export CI_MONGO_NAME="nb2-t7-$lane_token"
  mongo_started=1
  bash scripts/ci/mongo-up.sh up "$NB2_OUT/mongo"
fi
bash scripts/reth-paired-devnet.sh 4 10 &
lane_pid=$!
rc=0
wait "$lane_pid" || rc=$?
lane_pid=
exit "$rc"
