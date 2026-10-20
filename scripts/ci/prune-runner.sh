#!/usr/bin/env bash
# Frees disk on a GitHub-hosted Ubuntu runner by removing toolchains and images this repository's jobs never use, and prints df before and after.
# CI only (it deletes system directories); refuses to run anywhere else.
set -uo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] && [ "$(uname -s)" = Linux ] || { echo "prune-runner: refusing to run outside a GitHub-hosted Linux runner" >&2; exit 2; }
df -h / | tail -1 | sed 's/^/before: /'
for d in /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup /usr/local/share/boost /usr/share/swift /opt/hostedtoolcache/CodeQL /usr/local/share/chromium /usr/local/share/powershell; do
  [ -e "$d" ] && sudo rm -rf "$d"
done
sudo docker image prune --all --force >/dev/null 2>&1 || true
sudo apt-get clean >/dev/null 2>&1 || true
df -h / | tail -1 | sed 's/^/after:  /'
