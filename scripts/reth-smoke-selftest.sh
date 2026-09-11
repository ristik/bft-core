#!/bin/bash
# reth-smoke-selftest.sh - exercise every refusal and collection path of the pinned-client packaging
# (scripts/lib/reth-pin.sh, scripts/reth-pin.sh, scripts/reth-smoke.sh) without reth, a network or a
# devnet. Stand-in "reth" binaries are shell scripts that print a chosen revision; "downloads" are
# file:// URLs to archives built here, with digests computed here — so this tests the LOGIC of the
# pin, the cache and the evidence path, not the real artifact, which the real runs recorded in
# docs/design/f1-baseline.md §6.4 do.
#
# Usage: ./scripts/reth-smoke-selftest.sh     (exit 0 only if every check passes)

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
. scripts/lib/reth-pin.sh

ok=0 bad=0
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
check() { # check <description> <command...> : passes when the command succeeds
  local d=$1; shift
  if "$@" >"$T/.out" 2>&1; then ok=$((ok + 1)); echo "  ok   $d"; else bad=$((bad + 1)); echo "  BAD  $d"; sed 's/^/         /' "$T/.out" | tail -5; fi
}
refuses() { # refuses <description> <expected-text> <command...> : passes when it fails SAYING WHY
  local d=$1 want=$2 status; shift 2
  "$@" >"$T/.out" 2>&1; status=$?
  if [ "$status" -ne 0 ] && grep -qF -- "$want" "$T/.out"; then ok=$((ok + 1)); echo "  ok   $d"
  else bad=$((bad + 1)); echo "  BAD  $d (exit $status; wanted '$want')"; sed 's/^/         /' "$T/.out" | tail -5; fi
}

fakereth() { # fakereth <path> <commit|--no-commit|--fail|--hang>
  mkdir -p "$(dirname "$1")"
  case "$2" in
    --no-commit) printf '#!/bin/sh\necho "reth Version: 2.5.0"\n' >"$1" ;;
    --fail) printf '#!/bin/sh\necho "cannot execute binary file" >&2\nexit 126\n' >"$1" ;;
    --hang) printf '#!/bin/sh\nsleep 100\n' >"$1" ;;
    *) printf '#!/bin/sh\necho "reth Version: 2.5.0"\necho "Commit SHA: %s"\n' "$2" >"$1" ;;
  esac
  chmod +x "$1"
}
mkarchive() { # mkarchive <archive> <commit|--empty>
  local d; d=$(mktemp -d "$T/arc.XXXX")
  if [ "$2" = --empty ]; then echo nothing >"$d/README"; tar czf "$1" -C "$d" README
  else fakereth "$d/reth" "$2"; tar czf "$1" -C "$d" reth; fi
}
W=0000000000000000000000000000000000000bad

echo "=== binary verification: the check that runs on every path ==="
fakereth "$T/good/reth" "$RETH_PIN_COMMIT"
check   "a binary reporting the pinned commit is accepted" rethPinVerifyBinary "$T/good/reth"
refuses "a missing binary is refused, with no fallback" "no reth binary at" rethPinVerifyBinary "$T/nowhere/reth"
printf 'x' >"$T/noexec"; refuses "a non-executable file is refused" "is not an executable file" rethPinVerifyBinary "$T/noexec"
fakereth "$T/wrong/reth" "$W"
refuses "a binary reporting another commit is refused" "reports commit $W, pinned is $RETH_PIN_COMMIT" rethPinVerifyBinary "$T/wrong/reth"
fakereth "$T/nocommit/reth" --no-commit
refuses "a binary that reports no revision is refused" "reports no 'Commit SHA:' line" rethPinVerifyBinary "$T/nocommit/reth"
fakereth "$T/fails/reth" --fail
refuses "a binary that cannot run (e.g. another platform's) is refused" "--version' failed (exit 126)" rethPinVerifyBinary "$T/fails/reth"
fakereth "$T/hangs/reth" --hang
RETH_PIN_VERSION_BUDGET=2 refuses "a binary that hangs is refused within its budget" "--version' failed (exit 124)" rethPinVerifyBinary "$T/hangs/reth"

echo "=== the archive cache: a hit is verified exactly as thoroughly as a download ==="
mkdir -p "$T/mirror"
mkarchive "$T/mirror/good.tar.gz" "$RETH_PIN_COMMIT"; good=$(rethPinSha256 "$T/mirror/good.tar.gz")
obtain() { rethPinObtain "$T/cache" "$T/dest" "$1" "$2" "${3:-file://$T/mirror}"; }
check "a cache miss downloads, verifies the digest and the binary" obtain good.tar.gz "$good"
check "…and reports the miss" test "$(obtain good.tar.gz "$good" >/dev/null 2>&1; rm -f "$T/cache/good.tar.gz"; obtain good.tar.gz "$good" >/dev/null 2>&1; echo "$RETH_PIN_CACHE_STATE")" = miss
check "…leaves the verified archive in the cache" test -f "$T/cache/good.tar.gz"
check "a cache hit needs no download: the mirror is unreachable and it still succeeds" obtain good.tar.gz "$good" "file://$T/no-such-mirror"
check "…and reports the hit" test "$(obtain good.tar.gz "$good" "file://$T/no-such-mirror" >/dev/null 2>&1; echo "$RETH_PIN_CACHE_STATE")" = hit
cp "$T/cache/good.tar.gz" "$T/good.bak"; printf 'tamper' >>"$T/cache/good.tar.gz"; tampered=$(rethPinSha256 "$T/cache/good.tar.gz")
refuses "a tampered cached archive is refused, not silently refetched" "refusing the cache hit" obtain good.tar.gz "$good"
check "…the tampered archive is left in place to be seen" test "$(rethPinSha256 "$T/cache/good.tar.gz")" = "$tampered"
check "…and no binary is left at the destination" test ! -e "$T/dest/reth"
rm -f "$T/cache/good.tar.gz"
refuses "a download with the wrong digest is refused" "refused, nothing cached" obtain good.tar.gz "$(printf '%064d' 0)" "file://$T/mirror"
check "…and nothing of it is cached, not even a partial file" test -z "$(ls -A "$T/cache")"
cp "$T/good.bak" "$T/cache/good.tar.gz"
mkarchive "$T/mirror/empty.tar.gz" --empty
refuses "an archive without a reth binary is refused" "contains no top-level 'reth' binary" obtain empty.tar.gz "$(rethPinSha256 "$T/mirror/empty.tar.gz")"
mkarchive "$T/mirror/wrong.tar.gz" "$W"
refuses "a correctly-digested archive whose binary reports another commit is refused" "reports commit $W" obtain wrong.tar.gz "$(rethPinSha256 "$T/mirror/wrong.tar.gz")"
check "…and its binary is removed rather than left for a later caller" test ! -e "$T/dest/reth"
refuses "a failed download is refused" "download of" obtain absent.tar.gz "$good"
refuses "a platform with no pinned artifact is refused, naming the alternative" "Use --reth-bin" rethPinObtainPinned "$T/cache" "$T/dest" solaris-sparc

echo "=== the pin is one value, everywhere ==="
pinTable() { local p e bad=0; for p in linux-x86_64 linux-aarch64 darwin-arm64; do
  e=$(rethPinAsset "$p") || { echo "no entry for $p"; bad=1; continue; }
  echo "${e%% *}" | grep -q "^reth-$RETH_PIN_TAG-" || { echo "$p asset ${e%% *} is not for $RETH_PIN_TAG"; bad=1; }
  echo "${e##* }" | grep -qE '^[0-9a-f]{64}$' || { echo "$p digest ${e##* } is not a sha256"; bad=1; }
done; return $bad; }
check "every pinned artifact names the pinned tag and carries a sha256" pinTable
lanePins() { local bad=0 f v; for f in scripts/*.sh scripts/lib/*.sh; do
  v=$(sed -n 's/^[: "{]*pinnedRethCommit[:=]*\([0-9a-f]\{40\}\).*/\1/p' "$f" | head -1)
  [ -z "$v" ] || [ "$v" = "$RETH_PIN_COMMIT" ] || { echo "$f pins $v"; bad=1; }
done; return $bad; }
check "every lane's pinnedRethCommit equals RETH_PIN_COMMIT" lanePins
workflowPins() { ! grep -lE '[0-9a-f]{40}|RETH_(COMMIT|SHA256|ASSET):' .github/workflows/reth-*.yml; }
check "no real-reth workflow carries its own pin; each derives it from the library" workflowPins

echo "=== evidence: secrets excluded by construction, then checked independently ==="
N=$T/nodes; mkdir -p "$N/evm1/dd" "$N/reth1"
echo "certified round 3" >"$N/evm1/debug.log"; echo "reth ok" >"$N/reth1/reth.log"
jwt=$(printf 'ab%.0s' $(seq 1 32)); echo "$jwt" >"$N/evm1/jwt.hex"
printf '{"sigKey":{"algorithm":"secp256k1","privateKey":"0x%s"}}' "$(printf 'cd%.0s' $(seq 1 32))" >"$N/evm1/keys.json"
echo 1234 >"$N/evm1/pid"; echo '{"networkId":3}' >"$N/trust-base.json"; echo "state" >"$N/evm1/dd/db"
mkrun() { rm -rf "$T/run" "$T/run.tar.gz"; mkdir -p "$T/run"; echo "lane=test" >"$T/run/provenance.txt"; echo "log" >"$T/run/run.log"; rethEvidenceCollect "$N" "$T/run/nodes" >/dev/null; }
mkrun
check "collection copies logs and configuration" test -f "$T/run/nodes/evm1/debug.log" -a -f "$T/run/nodes/reth1/reth.log" -a -f "$T/run/nodes/trust-base.json"
check "collection never copies keys.json, jwt.hex, pid files or datadirs" test ! -e "$T/run/nodes/evm1/keys.json" -a ! -e "$T/run/nodes/evm1/jwt.hex" -a ! -e "$T/run/nodes/evm1/pid" -a ! -e "$T/run/nodes/evm1/dd"
tar czf "$T/run.tar.gz" -C "$T" run
check "a clean archive validates" rethEvidenceValidate "$T/run.tar.gz" "$N" 2 provenance.txt run.log
cp "$N/evm1/jwt.hex" "$T/run/nodes/evm1/"; tar czf "$T/run.tar.gz" -C "$T" run
refuses "an archive containing jwt.hex is refused by name" "secret file(s) in archive" rethEvidenceValidate "$T/run.tar.gz" "" 0
mkrun; echo '{"privateKey":"0x01"}' >"$T/run/nodes/evm1/node-info.json"; tar czf "$T/run.tar.gz" -C "$T" run
refuses "an archive containing a privateKey field is refused by content" 'a "privateKey" field appears' rethEvidenceValidate "$T/run.tar.gz" "" 0
mkrun; echo "authorization header $jwt" >>"$T/run/nodes/evm1/debug.log"; tar czf "$T/run.tar.gz" -C "$T" run
refuses "a JWT secret leaked into a log line is refused by value" "appears verbatim in: run/nodes/evm1/debug.log" rethEvidenceValidate "$T/run.tar.gz" "$N" 0
mkrun; rm "$T/run/provenance.txt"; tar czf "$T/run.tar.gz" -C "$T" run
refuses "an archive missing a required file is refused" "no provenance.txt" rethEvidenceValidate "$T/run.tar.gz" "" 0 provenance.txt run.log
mkrun; rm "$T/run/nodes/evm1/debug.log" "$T/run/nodes/reth1/reth.log"; tar czf "$T/run.tar.gz" -C "$T" run
refuses "an archive without node logs is refused when logs are required" "0 node log(s), at least 1 required" rethEvidenceValidate "$T/run.tar.gz" "" 1
printf 'not a tarball' >"$T/junk.tar.gz"
refuses "an unreadable archive is refused" "is unreadable" rethEvidenceValidate "$T/junk.tar.gz" "" 0
refuses "a missing archive is refused" "is missing or empty" rethEvidenceValidate "$T/none.tar.gz" "" 0

# A copy that fails is a failed collection, even when another node's log would satisfy the minimum
# log count (the review's reproduction of #131: a regular file where the first node's destination
# directory should be).
N2=$T/nodes2; mkdir -p "$N2/evm1" "$N2/evm2"; echo one >"$N2/evm1/debug.log"; echo two >"$N2/evm2/debug.log"
rm -rf "$T/obst"; mkdir -p "$T/obst"; : >"$T/obst/evm1"
refuses "a collection whose copy fails returns nonzero, naming what is missing" "cannot create $T/obst/evm1" rethEvidenceCollect "$N2" "$T/obst"
check "…having still copied everything else it could" test -f "$T/obst/evm2/debug.log"
check "…and a successful collection still returns 0" sh -c "rm -rf '$T/obst2'; . scripts/lib/reth-pin.sh; rethEvidenceCollect '$N2' '$T/obst2'"

echo "=== the lane's supervisor (stub scenarios; no reth, no devnet) ==="
SN=$T/snodes
stub='mkdir -p "$NODES/evm1" && echo "certified" >"$NODES/evm1/debug.log" && echo '"$jwt"' >"$NODES/evm1/jwt.hex" && { sleep 300 & echo $! >"$NODES/evm1/pid"; }'
# stoppedRecorded: the stub DID record a pid, and that process is no longer alive. Without the first
# half this passes when nothing was ever started, which is how an earlier revision of it passed.
stoppedRecorded() { local p; p=$(cat "$SN/evm1/pid" 2>/dev/null) && [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; }
smoke() { RETH_SMOKE_NODES_DIR=$SN RETH_SMOKE_TEST_SCENARIOS=$1 ./scripts/reth-smoke.sh --reth-bin "$T/good/reth" --run-dir "$T/ev/$2" "${@:3}"; }
rm -rf "$SN"; check "a passing run exits 0 with a validated archive" smoke "$stub" pass
check "…the stub scenario actually ran" sh -c "tar tzf '$T/ev/pass.tar.gz' | grep -q 'pass/nodes/evm1/debug.log'"
check "…its archive carries provenance marked as a self-test, and the run log" sh -c "tar xzf '$T/ev/pass.tar.gz' -O pass/provenance.txt | grep -q 'SELF-TEST STUB'"
check "…and teardown stopped the process the run recorded" stoppedRecorded
check "…and the provenance records the invocation" sh -c "tar xzf '$T/ev/pass.tar.gz' -O pass/provenance.txt | grep -q 'invocation=.*--reth-bin'"
rm -rf "$SN"; refuses "an injected failure exits nonzero" "reth-smoke: FAIL" smoke "$stub" inject --inject-failure
check "…and still produces a validated archive recording the injection" sh -c "tar xzf '$T/ev/inject.tar.gz' -O inject/run.log | grep -q 'INJECTED FAILURE'"
check "…with the node logs in it" sh -c "tar tzf '$T/ev/inject.tar.gz' | grep -q 'inject/nodes/evm1/debug.log'"
check "…and teardown stopped the recorded process" stoppedRecorded
# The orphan: the scenario process starts something that is recorded nowhere — as reth-paired-devnet.sh
# is, beneath the lane's own process — and is then killed outright. Killing only the scenario process
# would leave that orphan running, able to start clients after teardown has finished.
rm -rf "$SN"; refuses "a scenario process killed outright is an incomplete run, not a pass" "incomplete run" smoke "$stub"' && { sleep 301 & echo $! >'"$T"'/orphan.pid; } && kill -9 $RETH_SMOKE_CHILD_PID' killed
check "…whose evidence is still archived" test -s "$T/ev/killed.tar.gz"
orphanStopped() { local p; p=$(cat "$T/orphan.pid" 2>/dev/null) && [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; }
check "…and whatever it had started, recorded or not, is stopped too" orphanStopped
# Cancellation: the supervisor itself is signalled, as a CI cancel or ^C does, while the scenarios hold
# a recorded process and an unrecorded one. The count it reports must be taken at that first stop
# signal — an earlier revision counted later, at teardown, and reported 0 for a real cancelled run
# whose eleven clients the signal had just stopped.
interruptRun() {
  rm -rf "$SN" "$T/orphan2.pid"
  RETH_SMOKE_NODES_DIR=$SN RETH_SMOKE_TEST_SCENARIOS="$stub"' && { sleep 301 & echo $! >'"$T"'/orphan2.pid; } && sleep 300' \
    ./scripts/reth-smoke.sh --reth-bin "$T/good/reth" --run-dir "$T/ev/interrupt" >"$T/interrupt.out" 2>&1 &
  local sup=$! i
  for i in $(seq 1 100); do [ -s "$T/orphan2.pid" ] && [ -s "$SN/evm1/pid" ] && break; sleep 0.1; done
  kill -TERM "$sup"; wait "$sup"
}
interruptRun; interruptStatus=$?
check "an interrupted run exits nonzero, reported as interrupted" sh -c "[ $interruptStatus -ne 0 ] && grep -q 'reth-smoke: FAIL run interrupted' '$T/interrupt.out'"
groupedAtInterrupt() { local n; n=$(sed -n "s/.*teardown complete — \([0-9]*\) process(es) in the run's group at its first stop signal (on interrupt).*/\1/p" "$T/interrupt.out"); [ -n "$n" ] && [ "$n" -ge 2 ]; }
check "…counting the run's processes at the interrupt itself, not after they had gone" groupedAtInterrupt
interruptStopped() { local a b; a=$(cat "$T/orphan2.pid" 2>/dev/null) && b=$(cat "$SN/evm1/pid" 2>/dev/null) && [ -n "$a" ] && [ -n "$b" ] && ! kill -0 "$a" 2>/dev/null && ! kill -0 "$b" 2>/dev/null; }
check "…stopping both the recorded and the unrecorded process" interruptStopped
check "…and still archiving validated evidence" grep -q "reth-evidence: archive .*interrupt.tar.gz validated" "$T/interrupt.out"
# The same obstruction inside the real supervisor: the scenarios pass and the archive validates (the
# remaining node log meets the minimum), and the lane must still fail because a required copy failed.
obstruct='mkdir -p "$NODES/evm1" "$NODES/evm2" && echo one >"$NODES/evm1/debug.log" && echo two >"$NODES/evm2/debug.log" && mkdir -p "$RUN_DIR/nodes" && : >"$RUN_DIR/nodes/evm1"'
rm -rf "$SN"; refuses "a supervised run whose evidence copy fails exits nonzero, though its scenarios passed" "reth-smoke: FAIL evidence collection incomplete" smoke "$obstruct" obstructed
cp "$T/.out" "$T/obstructed.out"
check "…the scenarios did pass, so collection is what failed it" grep -q "reth-smoke: scenario failures: 0" "$T/obstructed.out"
check "…the archive is still produced and inspectable, holding what could be copied" sh -c "tar tzf '$T/ev/obstructed.tar.gz' | grep -q 'obstructed/nodes/evm2/debug.log'"
check "…it validates on its own, which is why validation alone was not enough" grep -q "reth-evidence: archive .*obstructed.tar.gz validated" "$T/obstructed.out"
check "…and the failed copy is recorded in the archived run log" sh -c "tar xzf '$T/ev/obstructed.tar.gz' -O obstructed/run.log | grep -q 'cannot create .*nodes/evm1'"
rm -rf "$SN"; refuses "a leaked secret fails the lane even when the scenarios pass" "appears verbatim" smoke "$stub"' && echo "jwt $(cat $NODES/evm1/jwt.hex)" >>"$NODES/evm1/debug.log"' leak
rm -rf "$SN"
refuses "the wrong client stops the lane before any scenario" "reth-smoke: FAIL" \
  env RETH_SMOKE_NODES_DIR=$SN RETH_SMOKE_TEST_SCENARIOS="touch $T/scenario-ran" ./scripts/reth-smoke.sh --reth-bin "$T/wrong/reth" --run-dir "$T/ev/wrongpin"
check "…no scenario ran" test ! -e "$T/scenario-ran"
check "…and the refusal is in the archived run log" sh -c "tar xzf '$T/ev/wrongpin.tar.gz' -O wrongpin/run.log | grep -q 'reports commit $W'"
refuses "neither --reth-bin nor --fetch is a usage error" "exactly one of" ./scripts/reth-smoke.sh --run-dir "$T/ev/usage"
check "…that creates nothing" test ! -e "$T/ev/usage"
refuses "an existing run directory is never written into" "already exists" smoke "$stub" pass

echo
echo "selftest: $ok ok, $bad bad"
[ "$bad" -eq 0 ]
