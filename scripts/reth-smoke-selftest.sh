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
spawned= # every stand-in process this test starts itself, stopped on exit whatever happened
trap 'kill $spawned 2>/dev/null; rm -rf "$T"' EXIT
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
    --hang) printf '#!/bin/sh\nsleep 177 &\necho $! >"$(dirname "$0")/child.pid"\nwait\n' >"$1" ;;
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
# The hang is a shell whose CHILD holds the output: killing only the shell once left that child
# holding the $(...) pipe, and a 1-second budget took as long as the child did. Measured, not assumed:
# wall time and the child's survival, not just the exit status.
# Milliseconds: bash 5's EPOCHREALTIME, else perl's Time::HiRes (macOS's bash 3.2 has no
# EPOCHREALTIME; a minimal Linux perl may lack Time::HiRes). Neither available is a failure, never a
# silent 0 — an earlier revision measured "0ms" on such a host and passed a timing check vacuously.
nowMs() {
  if [ -n "${EPOCHREALTIME:-}" ]; then local t=${EPOCHREALTIME/,/.}; echo $(( ${t%.*} * 1000 + 10#$(printf '%.3s' "${t#*.}") ))
  else perl -MTime::HiRes=time -e 'printf "%d", time * 1000' 2>/dev/null; fi
}
t0=$(nowMs)
RETH_PIN_VERSION_BUDGET=1 refuses "a binary that hangs is refused within its budget" "--version' failed (exit 124)" rethPinVerifyBinary "$T/hangs/reth"
t1=$(nowMs)
case "$t0$t1" in *[!0-9]* | "") hangMs=unmeasured ;; *) hangMs=$((t1 - t0)) ;; esac
check "…within bounded wall time (budget 1s; took ${hangMs}ms, must be measured and under 3000)" sh -c "[ '$hangMs' != unmeasured ] && [ '$hangMs' -gt 0 ] && [ '$hangMs' -lt 3000 ]"
check "…and nothing it started survives, the child holding its output included" sh -c "p=\$(cat '$T/hangs/child.pid') && [ -n \"\$p\" ] && ! kill -0 \"\$p\" 2>/dev/null"

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
check "…and a successful collection still returns 0" bash -c "rm -rf '$T/obst2'; . scripts/lib/reth-pin.sh; rethEvidenceCollect '$N2' '$T/obst2'"

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
# Publication. Each workflow's selection step is run here verbatim — extracted from the YAML, in a
# directory laid out the way the runner's checkout is — against archives the real supervisor just
# produced: one whose scenarios leaked the JWT, and one of an ordinary (injected) failure, whose safe
# evidence must still be published. The stub writes the same JWT on every run, so $SN holds it.
wfStep() { awk -v n="name: $2" 'index($0,n){f=1} f&&/run: >-/{r=1;next} r&&NF==0{exit} r{printf "%s ",$0}' "$1"; }
wfDir() { rm -rf "$T/wf"; mkdir -p "$T/wf"; ln -s "$PWD/scripts" "$T/wf/scripts"; ln -s "$SN" "$T/wf/test-nodes"; }
smokeSelect=$(wfStep .github/workflows/reth-smoke.yml "Select publishable evidence")
faultSelect=$(wfStep .github/workflows/reth-fault.yml "Validate and select publishable evidence")
check "both workflows have a selection step, and upload only its directory" sh -c "[ -n '$smokeSelect' ] && [ -n '$faultSelect' ] && [ \$(grep -c 'path: evidence-upload/' .github/workflows/reth-smoke.yml) -eq 1 ] && [ \$(grep -c 'path: evidence-upload/' .github/workflows/reth-fault.yml) -eq 1 ] && ! grep -q 'path: .*tar.gz' .github/workflows/reth-smoke.yml .github/workflows/reth-fault.yml"
wfDir; cp "$T/ev/leak.tar.gz" "$T/wf/reth-smoke-evidence.tar.gz"; leakSha=$(rethPinSha256 "$T/wf/reth-smoke-evidence.tar.gz")
refuses "the smoke workflow's selection rejects the archive with the leaked JWT" "is not publishable" sh -c "cd '$T/wf' && $smokeSelect"
check "…nothing of it is in the upload directory" sh -c "! ls '$T/wf/evidence-upload' | grep -q 'tar.gz\$'"
check "…it is quarantined, intact, outside the upload directory" test "$(rethPinSha256 "$T/wf/evidence-quarantine/reth-smoke-evidence.tar.gz" 2>/dev/null)" = "$leakSha" -a ! -e "$T/wf/reth-smoke-evidence.tar.gz"
check "…a diagnostic is published in its place, naming where the secret was" grep -q "appears verbatim in: .*debug.log" "$T/wf/evidence-upload/reth-smoke-evidence.tar.gz.REJECTED.txt"
check "…and no published file carries the secret value" sh -c "! grep -rqF '$jwt' '$T/wf/evidence-upload'"
check "…the manifest records the rejection" grep -q "reth-smoke-evidence.tar.gz sha256=$leakSha REJECTED" "$T/wf/evidence-upload/MANIFEST.txt"
wfDir; cp "$T/ev/inject.tar.gz" "$T/wf/reth-smoke-evidence.tar.gz"; injSha=$(rethPinSha256 "$T/wf/reth-smoke-evidence.tar.gz")
check "the smoke workflow's selection publishes an ordinary failed run's evidence" sh -c "cd '$T/wf' && $smokeSelect"
check "…byte-identical, and recorded as published" bash -c "[ \"\$(. scripts/lib/reth-pin.sh; rethPinSha256 '$T/wf/evidence-upload/reth-smoke-evidence.tar.gz')\" = '$injSha' ] && grep -q 'sha256=$injSha published (validated)' '$T/wf/evidence-upload/MANIFEST.txt'"
# The fault lane selects per archive: one run's leak must not withhold another run's evidence.
wfDir; mkdir -p "$T/wf/evidence-runs"
fa() { local d; d=$(mktemp -d "$T/fa.XXXX"); mkdir -p "$d/$1/nodes/evm1"; echo "run $1" >"$d/$1/manifest.txt"; echo "certified ${2:-}" >"$d/$1/nodes/evm1/debug.log"; tar czf "$T/wf/evidence-runs/$1.tar.gz" -C "$d" "$1"; }
fa run-a; fa run-b "authorization $jwt"; fa run-c; printf 'not a tarball' >"$T/wf/evidence-runs/run-d.tar.gz"
refuses "the fault workflow's selection rejects only the leaking and the unreadable archive" "run-b.tar.gz is not publishable" sh -c "cd '$T/wf' && $faultSelect"
check "…publishing the other two" test -s "$T/wf/evidence-upload/run-a.tar.gz" -a -s "$T/wf/evidence-upload/run-c.tar.gz"
check "…quarantining the leaking one and the unreadable one, which cannot be vouched for" test -s "$T/wf/evidence-quarantine/run-b.tar.gz" -a -s "$T/wf/evidence-quarantine/run-d.tar.gz" -a ! -e "$T/wf/evidence-upload/run-b.tar.gz" -a ! -e "$T/wf/evidence-upload/run-d.tar.gz"
check "…and no published file carries the secret value" sh -c "! grep -rqF '$jwt' '$T/wf/evidence-upload'"
wfDir
refuses "the fault workflow's selection with no archive at all fails, and says so" "no archive at" sh -c "cd '$T/wf' && $faultSelect"
check "…still leaving a manifest to upload" grep -q "MISSING" "$T/wf/evidence-upload/MANIFEST.txt"
rm -rf "$SN"
refuses "the wrong client stops the lane before any scenario" "reth-smoke: FAIL" \
  env RETH_SMOKE_NODES_DIR=$SN RETH_SMOKE_TEST_SCENARIOS="touch $T/scenario-ran" ./scripts/reth-smoke.sh --reth-bin "$T/wrong/reth" --run-dir "$T/ev/wrongpin"
check "…no scenario ran" test ! -e "$T/scenario-ran"
check "…and the refusal is in the archived run log" sh -c "tar xzf '$T/ev/wrongpin.tar.gz' -O wrongpin/run.log | grep -q 'reports commit $W'"
refuses "neither --reth-bin nor --fetch is a usage error" "exactly one of" ./scripts/reth-smoke.sh --run-dir "$T/ev/usage"
check "…that creates nothing" test ! -e "$T/ev/usage"
refuses "an existing run directory is never written into" "already exists" smoke "$stub" pass

echo "=== teardown is this checkout's, nested cleanups included: a separately owned sentinel survives ==="
# A scratch checkout holding the real teardown code — the lane, its library, helper.sh and
# stop-evm.sh — and an "other checkout" running harmless sentinels whose command lines match every
# name a sweep might look for: `build/ubft root-node`, `build/ubft shard-node run`, `reth node`. They
# are perl sleeps, not nodes: nothing of anybody else's is touched. stop-evm.sh -a once stopped every
# `build/ubft root-node` on the machine, from inside reth-paired-devnet.sh's cleanup, beneath this lane.
CO=$T/co OTHER=$T/other
mkdir -p "$CO/scripts/lib" "$CO/build" "$CO/fake" "$OTHER/build" "$OTHER/fake"
cp scripts/reth-smoke.sh "$CO/scripts/"; cp scripts/lib/reth-pin.sh "$CO/scripts/lib/"; cp helper.sh stop-evm.sh "$CO/"
for d in "$CO" "$OTHER"; do
  printf '#!/usr/bin/perl\nsleep 600;\n' >"$d/build/ubft"; cp "$d/build/ubft" "$d/fake/reth"; chmod +x "$d/build/ubft" "$d/fake/reth"
done
startIn() { (cd "$1" && exec "${@:2}" >/dev/null 2>&1 </dev/null) & echo $!; }
execd() { local i; for i in $(seq 1 50); do ps -o command= -p "$1" 2>/dev/null | grep -q perl && return 0; sleep 0.1; done; return 1; }
sentinels=()
for c in "build/ubft root-node run --home test-nodes/root1" "build/ubft shard-node run --home test-nodes/evm1" "fake/reth node --datadir dd"; do
  sentinels+=("$(startIn "$OTHER" $c)")
done
spawned="$spawned ${sentinels[*]}"
for p in "${sentinels[@]}"; do execd "$p"; done
sentinelsAlive() { local p; for p in "${sentinels[@]}"; do kill -0 "$p" 2>/dev/null || { echo "sentinel $p was stopped"; return 1; }; done; }
allStopped() { local p i; for i in $(seq 1 30); do for p in "$@"; do kill -0 "$p" 2>/dev/null && break; done; kill -0 "$p" 2>/dev/null || return 0; sleep 0.1; done; echo "still alive: $(for p in "$@"; do kill -0 "$p" 2>/dev/null && echo "$p"; done)"; return 1; }
check "the sentinels are running, and a name-based sweep would match every one of them" sh -c "pgrep -f 'build/ubft root-node' | grep -qx ${sentinels[0]} && pgrep -f 'ubft shard-node run' | grep -qx ${sentinels[1]} && pgrep -f 'reth node' | grep -qx ${sentinels[2]}"

# stop-evm.sh -a directly: this checkout's nodes with a pid file, one without, and stale pid files in
# this checkout naming the sentinels.
mkdir -p "$CO/test-nodes/root1" "$CO/test-nodes/root2" "$CO/test-nodes/evm1" "$CO/test-nodes/evm2"
own=()
for c in "build/ubft root-node run --home test-nodes/root1" "build/ubft shard-node run --home test-nodes/evm1" "build/ubft root-node run --home test-nodes/root3"; do
  own+=("$(startIn "$CO" $c)")
done
spawned="$spawned ${own[*]}"
for p in "${own[@]}"; do execd "$p"; done
echo "${own[0]}" >"$CO/test-nodes/root1/pid"; echo "${own[1]}" >"$CO/test-nodes/evm1/pid"
echo "${sentinels[0]}" >"$CO/test-nodes/root2/pid"; echo "${sentinels[1]}" >"$CO/test-nodes/evm2/pid"
check "stop-evm.sh -a runs" sh -c "cd '$CO' && ./stop-evm.sh -a"
check "…stopping this checkout's nodes, with a pid file or without" allStopped "${own[@]}"
check "…and no sentinel, not even those named by stale pid files in this checkout" sentinelsAlive
check "…whose stale pid files are removed rather than left for the next caller" test ! -e "$CO/test-nodes/root2/pid" -a ! -e "$CO/test-nodes/evm2/pid"

# The lane itself, with scenarios that tear down with reth-paired-devnet.sh's OWN cleanup function —
# extracted from that script, not re-typed — on an EXIT trap, reached on success, on failure and when
# the lane is cancelled. The stale pid files here also reach the supervisor's own ownership sweep.
sed -n '/^cleanup() {/,/^}/p' scripts/reth-paired-devnet.sh >"$CO/paired-cleanup.sh"
check "reth-paired-devnet.sh's cleanup is extracted for the nested case" grep -q 'stop-evm.sh -a' "$CO/paired-cleanup.sh"
cat >"$T/nested.sh" <<STUB
mode=\$1
. ./helper.sh
validators=2 negativeReths="reth-wrong reth-laterfork"
. ./paired-cleanup.sh
trap 'cleanup; echo ran >"$T/nested-\$mode.ran"' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
mkdir -p test-nodes/root1 test-nodes/root2 test-nodes/evm1 test-nodes/evm2 test-nodes/reth1 test-nodes/reth2 test-nodes/reth-wrong
build/ubft root-node run --home test-nodes/root1 >test-nodes/root1/debug.log 2>&1 & echo \$! >test-nodes/root1/pid; echo \$! >"$T/nested-\$mode.owned"
build/ubft shard-node run --home test-nodes/evm1 >test-nodes/evm1/debug.log 2>&1 & echo \$! >test-nodes/evm1/pid; echo \$! >>"$T/nested-\$mode.owned"
fake/reth node --datadir test-nodes/reth1/dd >test-nodes/reth1/reth.log 2>&1 & echo \$! >test-nodes/reth1/pid; echo \$! >>"$T/nested-\$mode.owned"
echo ${sentinels[0]} >test-nodes/root2/pid; echo ${sentinels[1]} >test-nodes/evm2/pid
echo ${sentinels[2]} >test-nodes/reth2/pid; echo ${sentinels[2]} >test-nodes/reth-wrong/pid
# ...and one in a directory no nested cleanup touches, so it is still there for the supervisor's sweep
mkdir -p test-nodes/leftover; echo ${sentinels[0]} >test-nodes/leftover/pid
case \$mode in
  fail) exit 1 ;;
  cancel) touch "$T/nested-cancel.up"; sleep 300 ;;
esac
STUB
nestedRun() { rm -rf "$CO/test-nodes" "$T/nested-$1".*; RETH_SMOKE_TEST_SCENARIOS="bash $T/nested.sh $1" "$CO/scripts/reth-smoke.sh" --reth-bin "$T/good/reth" --run-dir "$T/ev/nested-$1"; }
nestedCancel() {
  rm -rf "$CO/test-nodes" "$T/nested-cancel".*
  RETH_SMOKE_TEST_SCENARIOS="bash $T/nested.sh cancel" "$CO/scripts/reth-smoke.sh" --reth-bin "$T/good/reth" --run-dir "$T/ev/nested-cancel" &
  local sup=$! i
  for i in $(seq 1 100); do [ -e "$T/nested-cancel.up" ] && break; sleep 0.1; done
  kill -TERM "$sup"; wait "$sup"
}
ownedStopped() { local p; [ -s "$T/nested-$1.owned" ] || { echo "nothing was started"; return 1; }; for p in $(cat "$T/nested-$1.owned"); do kill -0 "$p" 2>/dev/null && { echo "$p still alive"; return 1; }; done; return 0; }
check "a passing run whose scenarios clean up with the paired devnet's cleanup passes" nestedRun pass
check "…the nested cleanup did run" test -e "$T/nested-pass.ran"
check "…its own processes were stopped" ownedStopped pass
check "…and every sentinel survived" sentinelsAlive
check "…the stale pid file no nested cleanup removed was still there for the supervisor's sweep" test -f "$CO/test-nodes/leftover/pid"
refuses "a failing run whose scenarios clean up with the paired devnet's cleanup fails" "reth-smoke: FAIL" nestedRun fail
check "…the nested cleanup did run" test -e "$T/nested-fail.ran"
check "…its own processes were stopped" ownedStopped fail
check "…and every sentinel survived" sentinelsAlive
refuses "a cancelled run whose scenarios clean up with the paired devnet's cleanup fails as interrupted" "reth-smoke: FAIL run interrupted" nestedCancel
check "…the nested cleanup did run, on the cancellation" test -e "$T/nested-cancel.ran"
check "…its own processes were stopped" ownedStopped cancel
check "…and every sentinel survived" sentinelsAlive

echo
echo "selftest: $ok ok, $bad bad"
[ "$bad" -eq 0 ]
