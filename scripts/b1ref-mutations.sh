#!/usr/bin/env bash
# Mutation check of the b1ref reference (bft-core #606 review): applies each row of b1ref/testdata/mutations.tsv to a clean
# checkout, runs the b1ref tests and requires the row's expectation: "red" (some test fails) or "survives" (a documented
# unreachable check; the note says why, and the row proves the documentation is still true). Every file is restored from HEAD
# after each row and on exit. Run from the repository root of your own checkout; it edits b1ref source files while it runs.
#
#   scripts/b1ref-mutations.sh            # all rows
#   scripts/b1ref-mutations.sh seal-key   # rows whose id contains the argument
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [ -n "$(git status --porcelain -- b1ref)" ]; then
  echo "b1ref has uncommitted changes; run on a clean tree" >&2
  exit 2
fi
restore() { git checkout -q HEAD -- b1ref; }
trap restore EXIT
filter=${1:-}
bad=0
while IFS=$'\t' read -r id file expr expect note; do
  case "$id" in ''|'#'*) continue ;; esac
  [ -n "$filter" ] && [[ "$id" != *"$filter"* ]] && continue
  restore
  sed -i.bak -e "$expr" "$file" && rm -f "$file.bak"
  if git diff --quiet -- "$file"; then
    echo "NOT APPLIED  $id  ($file)"; bad=1; continue
  fi
  if go test ./b1ref/... -count=1 >/dev/null 2>&1; then got=survives; else got=red; fi
  if [ "$got" = "$expect" ]; then echo "ok           $id: $got"; else echo "MISMATCH     $id: $got, expected $expect ($note)"; bad=1; fi
done < b1ref/testdata/mutations.tsv
exit $bad
