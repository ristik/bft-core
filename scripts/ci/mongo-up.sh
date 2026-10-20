#!/usr/bin/env bash
# A digest-pinned MongoDB replica set rs0 on 127.0.0.1:27117 for the aggregator (scripts/lib/agg-lib.sh needs a replica set, not just an open port).
#   scripts/ci/mongo-up.sh up LOG_DIR      start (fresh storage, this job's container and volume), initiate rs0, wait for a writable primary
#   scripts/ci/mongo-up.sh down LOG_DIR    save the logs, remove only this job's container and volume
# The container and volume are named from the job (CI_MONGO_NAME, default lane-mongo-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT); nothing else is touched.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pins=$here/lane-pins.json
image=$(jq -r '.images.mongo.image' "$pins"); digest=$(jq -r '.images.mongo.digest' "$pins")
ref=${image%%:*}@$digest
name=${CI_MONGO_NAME:-lane-mongo-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}}
vol=$name-data
port=27117
log=${2:?usage: mongo-up.sh up|down LOG_DIR}
mkdir -p "$log"
case "${1:-}" in
  up)
    docker pull -q "$ref" >/dev/null
    got=$(docker image inspect "$ref" --format '{{index .RepoDigests 0}}'); echo "mongo image $got" | tee "$log/mongo-image.txt"
    docker volume create "$vol" >/dev/null
    # Host networking, loopback only: mongod listens on 127.0.0.1:27117 and the replica set member is advertised as 127.0.0.1:27117, the address the aggregator (and
    # mongod itself, to recognise its own member) uses. A port mapping would leave the member unreachable from inside the container.
    docker run -d --name "$name" --network host -v "$vol:/data/db" "$ref" --replSet rs0 --bind_ip 127.0.0.1 --port "$port" >/dev/null
    for _ in $(seq 1 60); do docker exec "$name" mongosh --quiet --port $port --eval 'db.adminCommand({ping:1}).ok' 2>/dev/null | grep -q 1 && break; sleep 1; done
    docker exec "$name" mongosh --quiet --port "$port" --eval "rs.initiate({_id:'rs0',members:[{_id:0,host:'127.0.0.1:$port'}]})" >"$log/rs-initiate.txt" 2>&1 || { cat "$log/rs-initiate.txt" >&2; exit 1; }
    for _ in $(seq 1 60); do
      docker exec "$name" mongosh --quiet --port $port --eval 'db.hello().isWritablePrimary' 2>/dev/null | grep -q true && { echo "mongo primary writable"; exit 0; }
      sleep 1
    done
    docker logs "$name" >"$log/mongo.log" 2>&1 || true; echo "mongo: no writable primary within 60 s" >&2; exit 1 ;;
  down)
    docker logs "$name" >"$log/mongo.log" 2>&1 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm "$vol" >/dev/null 2>&1 || true ;;
  *) echo "usage: $0 up|down LOG_DIR" >&2; exit 2 ;;
esac
