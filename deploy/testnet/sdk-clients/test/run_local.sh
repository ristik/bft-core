#!/usr/bin/env bash
# Run the three SDK acceptance clients natively against a local stub of the aggregator's trust-base endpoint (stub_aggregator.py), serving the shared dev
# trust-base fixture (epochs 1..4, network 3, test/fixtures/dev). No Docker, no devnet. Then check the clients' JSON with the checks the driver applies
# (sdkaccept.py) and prove those checks bite (check_local.py). Exit status is 0 only if every check passed.
#
#   JS_SDK=<checkout of state-transition-sdk-js at the pin> RUST_SDK=<...-rust> JAVA_SDK=<...-java> test/run_local.sh [js] [rust] [java]
#
# The checkouts are only read, except that the JS one is built in place (npm ci, npm run build): pass a scratch clone. Layout of the work: $WORK (default a new
# temp dir; keep it with KEEP=1). Java: JAVA_MODE=gradle (default: the SDK's ./gradlew builds its jar and then the client, as the Dockerfile does) or
# JAVA_MODE=javac with JAVA_CP=<colon separated dependency jars> (when the local JDK is newer than the SDK's Gradle 8.8 can run; the SDK sources and the client
# are then compiled directly).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENTS="$(dirname "$HERE")"
LANGS="${*:-js rust java}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/sdk-clients-local.XXXXXX")}"
FIX="$HERE/fixtures/dev"
BUNDLE="$FIX/bft-trustbase.dev.bundle.cbor"
mkdir -p "$WORK/out" "$WORK/stores"
STUB_PID=""
cleanup() { [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null || true; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

# the genesis the operator ships (the epoch-1 entry alone, as dnb-tool trust-bundle writes it), its pin, and the negatives made from the real entries
PIN="$(python3 -I "$CLIENTS/utbcbor.py" genesis "$BUNDLE" "$WORK/genesis.bundle.cbor")"
[ "$PIN" = "$(tr -d '\n' < "$FIX/bft-trustbase.dev.genesis.entryid")" ] || { echo "the fixture's pin differs from its genesis entry"; exit 1; }
python3 -I "$CLIENTS/utbcbor.py" negatives "$BUNDLE" "$WORK/negatives" > /dev/null

python3 -I "$HERE/stub_aggregator.py" --bundle "$BUNDLE" --port-file "$WORK/port" --log "$WORK/stub.log" > "$WORK/stub.out" 2>&1 &
STUB_PID=$!
for _ in $(seq 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
URL="http://127.0.0.1:$(cat "$WORK/port")"

commit() { python3 -I -c "import json,sys;print(json.load(open('$CLIENTS/pins.json'))['$1']['commit'])"; }
COMMITS="{}"
build() {
  case "$1" in
    js)
      [ -d "$JS_SDK/node_modules" ] || (cd "$JS_SDK" && npm ci --ignore-scripts --no-audit --no-fund)
      [ -d "$JS_SDK/lib" ] || (cd "$JS_SDK" && npm run build)
      RUNNER=(env "SDK_DIR=$JS_SDK" "SDK_COMMIT=$(commit js)" node "$CLIENTS/js/client.mjs") ;;
    rust)
      mkdir -p "$WORK/rust"; ln -sfn "$RUST_SDK" "$WORK/rust/sdk"; rm -rf "$WORK/rust/client"
      mkdir "$WORK/rust/client"; cp -R "$CLIENTS/rust/Cargo.toml" "$CLIENTS/rust/src" "$WORK/rust/client/"; cp "$RUST_SDK/Cargo.lock" "$WORK/rust/client/"
      (cd "$WORK/rust/client" && cargo build --release -q)
      RUNNER=(env "SDK_COMMIT=$(commit rust)" "$WORK/rust/client/target/release/sdk-trustbase-client") ;;
    java)
      if [ "${JAVA_MODE:-gradle}" = javac ]; then
        mkdir -p "$WORK/java/classes" "$WORK/java/gen/org/unicitylabs/sdk"
        printf 'package org.unicitylabs.sdk;\npublic final class SdkVersion { public static final String VERSION = "4.0.0"; private SdkVersion() {} }\n' > "$WORK/java/gen/org/unicitylabs/sdk/SdkVersion.java"
        find "$JAVA_SDK/src/main/java" "$WORK/java/gen" "$CLIENTS/java/src/main/java" -name '*.java' > "$WORK/java/sources.txt"
        javac -nowarn -d "$WORK/java/classes" -cp "$JAVA_CP" @"$WORK/java/sources.txt"
        cp -R "$JAVA_SDK/src/main/resources/." "$WORK/java/classes/" 2>/dev/null || true
        RUNNER=(env "SDK_COMMIT=$(commit java)" java -cp "$WORK/java/classes:$JAVA_CP" acceptance.SdkClient)
      else
        (cd "$JAVA_SDK" && ./gradlew --no-daemon -q jar)
        mkdir -p "$WORK/java/client"; cp -R "$CLIENTS/java/build.gradle.kts" "$CLIENTS/java/settings.gradle.kts" "$CLIENTS/java/src" "$WORK/java/client/"
        SDK_JAR="$(ls "$JAVA_SDK"/build/libs/*.jar | grep -v -e -sources -e -javadoc | head -1)" "$JAVA_SDK/gradlew" --no-daemon -q -p "$WORK/java/client" installDist
        RUNNER=(env "SDK_COMMIT=$(commit java)" "$WORK/java/client/build/install/client/bin/client")
      fi ;;
  esac
}
for lang in $LANGS; do
  echo "== $lang"
  build "$lang"
  for mode in cold warm restart; do
    store="$WORK/stores/$lang-$([ "$mode" = restart ] && echo cold || echo "$mode")"
    extra=(); [ "$mode" = cold ] && extra=(--negatives "$WORK/negatives")
    # a client that fails still prints its JSON error object: keep it for the checks
    "${RUNNER[@]}" --agg-url "$URL" --network-id 3 --genesis-pin "$PIN" --genesis "$WORK/genesis.bundle.cbor" --store "$store" --mode "$mode" ${extra[@]+"${extra[@]}"} \
      2> "$WORK/out/$lang-$mode.stderr" | tail -n 1 > "$WORK/out/$lang-$mode.json" || true
    echo "  $mode: $(cut -c1-160 "$WORK/out/$lang-$mode.json")"
  done
  COMMITS="$(python3 -I -c "import json;d=json.loads('$COMMITS');d['$lang']='$(commit "$lang")';print(json.dumps(d))")"
done
echo "== stub requests"; cat "$WORK/stub.log"
echo "== checks"
python3 -I "$HERE/check_local.py" "$WORK/out" "$BUNDLE" "$COMMITS"
