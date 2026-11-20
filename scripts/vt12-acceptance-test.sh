#!/usr/bin/env bash
# Regression tests for the acceptance harness. All requests and process operations below are local stubs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/vt12-acceptance.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
log() { printf '%s\n' "$*"; }
api() { printf '%s\n' "$response"; }

for response in \
  '{"status":"error","data":{"alerts":[]}}' \
  '{"status":"success","data":{"alerts":{}}}' \
  '{"status":"success","data":{"alerts":null}}' \
  '{"status":"success","data":{"alerts":[{"labels":{"alertname":"Probe"}}]}}' \
  '{"status":"success","data":{"alerts":[{"state":"firing","labels":{}}]}}' \
  '{"status":"success","data":{"alerts":[{"state":"firing","labels":{"alertname":"Probe"}},{}]}}'
do
  rc=0
  firing Probe || rc=$?
  if [ "$rc" != 2 ] || expect_quiet Probe >/dev/null; then
    echo "Malformed alert response passed: $response" >&2
    exit 1
  fi
done
response='{"status":"success","data":{"alerts":[{"state":"firing","labels":{"alertname":"Probe","validator":"2"}}]}}'
firing Probe validator=2
expect_quiet Probe validator=1
echo "PASS: only valid Prometheus responses can satisfy an alert check"

for failure in timeout evidence interrupt restart none; do
  set +e
  (
    set -e
    MON=$tmp
    work=$tmp/cleanup
    mkdir -p "$work"
    stopped_exporter_pid= paused_pid= blocked= dpid= spid= disk_mount=
    original_running=1
    restart_attempts=0
    echo 812 >"$MON/exporter3.pid"
    owned_pid() { [ "$1" = 812 ] && [ "$original_running" = 1 ]; }
    kill() {
      [ "$1" = 812 ]
      original_running=0
      echo stop >>"$tmp/$failure.trace"
      if [ "$failure" = interrupt ]; then builtin kill -TERM "$BASHPID"; fi
    }
    start_exporter() {
      [ "$1" = 3 ]
      echo restart >>"$tmp/$failure.trace"
      restart_attempts=$((restart_attempts+1))
      [ "$failure" != restart ] || [ "$restart_attempts" -gt 1 ]
    }
    expect_quiet() { :; }
    wait_for() {
      if [ "$failure" = timeout ] && [ "$1" = firing ]; then return 1; fi
    }
    snap() { [ "$failure" != evidence ]; }
    restore_scrapes() { :; }
    trap cleanup EXIT
    trap 'exit 143' TERM
    check_scrape
  )
  rc=$?
  set -e
  expected=1
  trace=$'stop\nrestart'
  case "$failure" in
    interrupt) expected=143 ;;
    restart) trace=$'stop\nrestart\nrestart' ;;
    none) expected=0 ;;
  esac
  if [ "$rc" != "$expected" ] || [ "$(cat "$tmp/$failure.trace")" != "$trace" ]; then
    echo "Scrape check violated the exporter restart contract ($failure, exit $rc)" >&2
    exit 1
  fi
  echo "PASS: exporter restored ($failure)"
done
