#!/usr/bin/env bash
# The always-reporting result of the CI lane on a pull request (the `lane-gate` job). It passes when everything the plan SELECTED succeeded; a job that was not selected is
# skipped and does not count against the PR, but a selected job that failed, was cancelled or was skipped (because a build it needs failed) FAILS the gate. So a skipped lane
# never blocks a required check, and a failed or never-run selected lane never passes it.
#   scripts/ci/gate.sh                  reads PLAN_* and R_* from the environment (see the workflow) and prints one line per job
#   scripts/ci/gate.sh selftest
# PLAN_RESULT, PLAN_LANES (JSON array), PLAN_T6, PLAN_TARGETED, PLAN_SELFTESTS, PLAN_NEED_URETH, PLAN_NEED_LANE_BUILDS (true|false), PLAN_NOTE (free text, e.g. "draft")
# R_BUILD_URETH, R_BUILD_TOOLS, R_BUILD_SOURCES, R_RUN_LANE, R_RUN_T6, R_URETH_TARGETED, R_SELFTESTS: each job's result (success|failure|cancelled|skipped)
set -uo pipefail

gate() {
  local bad=0 want
  line() { printf '%-18s selected=%-5s result=%-9s %s\n' "$1" "$2" "$3" "$4"; }
  need() { # NAME SELECTED RESULT
    if [ "$2" = true ]; then
      if [ "$3" = success ]; then line "$1" "$2" "$3" ok; else line "$1" "$2" "$3" "FAIL: selected but not successful"; bad=1; fi
    else line "$1" "$2" "$3" "not selected"; fi
  }
  [ "${PLAN_RESULT:-}" = success ] || { echo "plan: ${PLAN_RESULT:-missing}  FAIL: the plan did not succeed, nothing can be said about the lanes"; return 1; }
  [ -z "${PLAN_NOTE:-}" ] || echo "note: $PLAN_NOTE"
  local lanes_sel=false; [ "${PLAN_LANES:-[]}" = '[]' ] || lanes_sel=true
  need build-ureth "${PLAN_NEED_URETH:-false}" "${R_BUILD_URETH:-skipped}"
  need build-tools "${PLAN_NEED_LANE_BUILDS:-false}" "${R_BUILD_TOOLS:-skipped}"
  need build-sources "${PLAN_NEED_LANE_BUILDS:-false}" "${R_BUILD_SOURCES:-skipped}"
  need "run-lane ${PLAN_LANES:-[]}" "$lanes_sel" "${R_RUN_LANE:-skipped}"
  need run-t6 "${PLAN_T6:-false}" "${R_RUN_T6:-skipped}"
  need ureth-targeted "${PLAN_TARGETED:-false}" "${R_URETH_TARGETED:-skipped}"
  need selftests "${PLAN_SELFTESTS:-false}" "${R_SELFTESTS:-skipped}"
  if [ "$lanes_sel" = false ] && [ "${PLAN_T6:-false}" = false ] && [ "${PLAN_TARGETED:-false}" = false ] && [ "${PLAN_SELFTESTS:-false}" = false ]; then
    echo "no live lane is relevant to this change: the gate reports success without running any"
  fi
  want=$bad; return "$want"
}

selftest() {
  local n=0 fails=0
  t() { # NAME EXPECTED_RC then env assignments
    local name=$1 want=$2; shift 2; n=$((n + 1))
    env -i PATH="$PATH" "$@" "$0" >/dev/null 2>&1; local rc=$?
    if [ "$rc" = "$want" ]; then echo "  ok    $name"; else echo "  FAIL  $name (exit $rc, wanted $want)"; fails=$((fails + 1)); fi
  }
  t "nothing relevant passes with every job skipped" 0 PLAN_RESULT=success
  t "a draft note still passes" 0 PLAN_RESULT=success PLAN_NOTE=draft
  t "selected and successful passes" 0 PLAN_RESULT=success 'PLAN_LANES=["combined"]' PLAN_NEED_URETH=true PLAN_NEED_LANE_BUILDS=true R_BUILD_URETH=success R_BUILD_TOOLS=success R_BUILD_SOURCES=success R_RUN_LANE=success
  t "a selected lane that failed fails" 1 PLAN_RESULT=success 'PLAN_LANES=["combined"]' PLAN_NEED_URETH=true PLAN_NEED_LANE_BUILDS=true R_BUILD_URETH=success R_BUILD_TOOLS=success R_BUILD_SOURCES=success R_RUN_LANE=failure
  t "a selected lane skipped because a build failed fails" 1 PLAN_RESULT=success 'PLAN_LANES=["combined"]' PLAN_NEED_URETH=true PLAN_NEED_LANE_BUILDS=true R_BUILD_URETH=failure R_BUILD_TOOLS=success R_BUILD_SOURCES=success R_RUN_LANE=skipped
  t "a cancelled selected job fails" 1 PLAN_RESULT=success PLAN_T6=true PLAN_NEED_URETH=true R_BUILD_URETH=success R_RUN_T6=cancelled
  t "a selected job that never ran fails" 1 PLAN_RESULT=success PLAN_TARGETED=true
  t "a failed plan fails" 1 PLAN_RESULT=failure
  t "a missing plan result fails" 1
  t "selftests only" 0 PLAN_RESULT=success PLAN_SELFTESTS=true R_SELFTESTS=success
  t "failed selftests fail" 1 PLAN_RESULT=success PLAN_SELFTESTS=true R_SELFTESTS=failure
  echo "gate self-test: $n cases, $fails failures"; [ "$fails" -eq 0 ]
}

case "${1:-}" in
  selftest) selftest ;;
  "") gate ;;
  *) echo "usage: $0 [selftest]" >&2; exit 2 ;;
esac
