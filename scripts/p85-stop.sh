#!/usr/bin/env bash
# Stops ONE P85 lane run, by the pids it recorded (<evidence-dir>/.runner-pids: the lock wrapper and the runner), never by a name pattern.
# The runner's own trap tears its devnet down and only then does the wrapper release the lock, so the lock is released after the cleanup.
# Usage: scripts/p85-stop.sh <evidence-dir>
set -euo pipefail
f=${1:?usage: p85-stop.sh <evidence-dir>}/.runner-pids
[ -s "$f" ] || { echo "no $f: this run did not record its pids" >&2; exit 2; }
read -r wrapper runner <"$f"
# only a process that is still a P85 lane process of this checkout is signalled (a recycled pid is not)
ours() { ps -o command= -p "$1" 2>/dev/null | grep -Eq "p85-lane\.sh|devnet-lock\.sh p85-recovery"; }
ours "$runner" || { echo "runner $runner is not a running p85 lane process" >&2; exit 1; }
kill -TERM "$runner"
for _ in $(seq 1 180); do kill -0 "$runner" 2>/dev/null || break; sleep 1; done
kill -0 "$runner" 2>/dev/null && { echo "runner $runner still running after 180 s; nothing else is killed" >&2; exit 1; }
for _ in $(seq 1 30); do kill -0 "$wrapper" 2>/dev/null || exit 0; sleep 1; done
echo "lock wrapper $wrapper still running" >&2; exit 1
