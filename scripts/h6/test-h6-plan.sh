#!/usr/bin/env bash
# Exercise the helper and tee statuses without starting a devnet.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/h6-abort-lib.sh"

Q3_DIR=$(mktemp -d)
trap 'rm -rf "$Q3_DIR"' EXIT
h3_root_rpcs() { echo 'http://127.0.0.1:1'; }
fake_helper() {
  echo 'helper diagnostic' >&2
  return "$helper_status"
}
H6_PY=fake_helper

check_plan() {
  local name=$1 helper_status=$2 expected=$3 actual=0
  local H6_ROOT_DUMP_REASON=
  h6_plan 2 -fixture "$name" >/dev/null 2>&1 || actual=$?
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $name returned $actual, expected $expected" >&2
    return 1
  fi
  if [ "$helper_status" = 4 ]; then
    [ "$H6_ROOT_DUMP_REASON" = "H6 $name handoff timed out" ]
  else
    [ -z "$H6_ROOT_DUMP_REASON" ]
  fi
}

check_plan success 0 0
grep -qx 'helper diagnostic' "$Q3_DIR/h6-success.log"
check_plan refusal 1 1
check_plan timeout 4 4
grep -qx 'helper diagnostic' "$Q3_DIR/h6-timeout.log"
mkdir "$Q3_DIR/h6-unwritable.log" "$Q3_DIR/h6-unwritable-timeout.log"
check_plan unwritable 0 1
check_plan unwritable-timeout 4 4
echo 'PASS: H6 plan keeps helper and log-write failures'
