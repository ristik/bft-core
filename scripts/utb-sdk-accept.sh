#!/usr/bin/env bash
# UTB SDK acceptance: the JS, Rust and Java SDK fetch loops (genesis-only client, bundle client, one entry per page, a forked aggregator refused) against
# running aggregator trust-base servers with GROWN histories. The servers are the aggregator's own HTTP route, in process (scripts/utb-sdk-accept/zz_interop_test.go.txt,
# run inside an aggregator-go checkout), so the same script runs in CI and on the host.
#
#   AGG_GO_DIR=<aggregator-go checkout with internal/trustbase/utb + internal/gateway>  (required)
#   UTB_SDK_JS=<state-transition-sdk-js checkout, built deps>   UTB_SDK_RUST=<sdk-rust checkout>   UTB_SDK_JAVA=<sdk-java checkout>   (each optional; at least one)
#   scripts/utb-sdk-accept.sh [--dry-run] [--workdir DIR]
#
# --dry-run: print what would run (checkouts, files copied, commands) and check every prerequisite; run nothing. Nothing is committed to any checkout: the harness files are copied in
# for the run and removed on exit; a checkout with uncommitted tracked changes is refused. A failing SDK run is a failure of the script (no rerun, no skipping).
# Not covered here: minting and verifying tokens (needs a live aggregator JSON-RPC with real inclusion proofs; the A lane does it for the JS SDK).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ASSETS="$HERE/utb-sdk-accept"
DRY=0; WORK=""
while [ $# -gt 0 ]; do case "$1" in --dry-run) DRY=1;; --workdir) WORK=$2; shift;; *) echo "unknown argument $1" >&2; exit 2;; esac; shift; done
fail() { echo "FAIL: $*" >&2; exit 1; }
say() { echo "== $*"; }
[ -n "${AGG_GO_DIR:-}" ] && [ -d "$AGG_GO_DIR/internal/gateway" ] || fail "AGG_GO_DIR must be an aggregator-go checkout"
sdks=()
[ -n "${UTB_SDK_JS:-}" ] && sdks+=(js)
[ -n "${UTB_SDK_RUST:-}" ] && sdks+=(rust)
[ -n "${UTB_SDK_JAVA:-}" ] && sdks+=(java)
[ ${#sdks[@]} -gt 0 ] || fail "set at least one of UTB_SDK_JS, UTB_SDK_RUST, UTB_SDK_JAVA"
clean() { local st; st=$(git -C "$1" status --porcelain --untracked-files=no) || fail "$1 is not a usable git checkout"; [ -z "$st" ] || fail "$1 has uncommitted tracked changes"; }
clean "$AGG_GO_DIR"
declare -A DIR=([js]="${UTB_SDK_JS:-}" [rust]="${UTB_SDK_RUST:-}" [java]="${UTB_SDK_JAVA:-}")
declare -A DEST=([js]=tests/unit/api/bft/trustbase/ZZAggInteropTest.ts [rust]=tests/agg_interop.rs [java]=src/test/java/org/unicitylabs/sdk/api/bft/trustbase/ZZAggInteropTest.java)
declare -A SRC=([js]=ZZAggInteropTest.ts.txt [rust]=agg_interop.rs.txt [java]=ZZAggInteropTest.java.txt)
for s in "${sdks[@]}"; do
  [ -d "${DIR[$s]}" ] || fail "$s checkout ${DIR[$s]} does not exist"; clean "${DIR[$s]}"
  [ ! -e "${DIR[$s]}/${DEST[$s]}" ] || fail "${DIR[$s]}/${DEST[$s]} already exists"
  [ -f "$ASSETS/${SRC[$s]}" ] || fail "missing asset ${SRC[$s]}"
done
cmd_js='npx jest tests/unit/api/bft/trustbase/ZZAggInteropTest.ts --coverage=false'
cmd_rust='cargo test --features http --test agg_interop'
cmd_java='./gradlew test --tests "org.unicitylabs.sdk.api.bft.trustbase.ZZAggInteropTest"'
if [ "$DRY" = 1 ]; then
  say "dry run: nothing is executed"
  echo "aggregator-go: $AGG_GO_DIR @ $(git -C "$AGG_GO_DIR" rev-parse --short HEAD) (copies zz_interop_test.go.txt to internal/gateway/zz_interop_test.go)"
  for s in "${sdks[@]}"; do v=cmd_$s; echo "$s: ${DIR[$s]} @ $(git -C "${DIR[$s]}" rev-parse --short HEAD): ${SRC[$s]} -> ${DEST[$s]}; run: ${!v}"; done
  exit 0
fi
WORK=${WORK:-$(mktemp -d)}; mkdir -p "$WORK"; SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  rm -f "$AGG_GO_DIR/internal/gateway/zz_interop_test.go"
  for s in "${sdks[@]}"; do rm -f "${DIR[$s]}/${DEST[$s]}"; done; }
trap cleanup EXIT
cp "$ASSETS/zz_interop_test.go.txt" "$AGG_GO_DIR/internal/gateway/zz_interop_test.go"
say "building the grown-history server (aggregator route, in process)"
SERVER_BIN="$WORK/utb-sdk-accept-server.test"
( cd "$AGG_GO_DIR" && go test -c -o "$SERVER_BIN" ./internal/gateway/ ) >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log" >&2; fail "the server did not build"; }
rm -f "$AGG_GO_DIR/internal/gateway/zz_interop_test.go"
# exec: the background process IS the test binary, so $! is what cleanup kills and waits for (a wrapper subshell would leave the binary serving after the script exits)
( cd "$AGG_GO_DIR/internal/gateway" && UTB_INTEROP_DIR="$WORK" exec "$SERVER_BIN" -test.run TestZZServeForSDKs -test.timeout 0 -test.count=1 -test.v >"$WORK/server.log" 2>&1 ) &
SERVER_PID=$!
for _ in $(seq 1 120); do [ -f "$WORK/manifest.json" ] && break; kill -0 "$SERVER_PID" 2>/dev/null || { tail -20 "$WORK/server.log" >&2; fail "the server exited before writing the manifest"; }; sleep 1; done
[ -f "$WORK/manifest.json" ] || fail "no manifest after 120 s"
rc=0
for s in "${sdks[@]}"; do
  say "$s SDK"
  cp "$ASSETS/${SRC[$s]}" "${DIR[$s]}/${DEST[$s]}"
  v=cmd_$s
  ( cd "${DIR[$s]}" && AGG_MANIFEST="$WORK/manifest.json" bash -c "${!v}" ) >"$WORK/$s.log" 2>&1 && echo "PASS $s" || { echo "FAIL $s (log $WORK/$s.log)"; tail -25 "$WORK/$s.log"; rc=1; }
done
exit $rc
