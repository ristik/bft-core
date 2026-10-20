#!/usr/bin/env bash
# Verifies the components of a lane run against the reviewed manifest scripts/ci/lane-pins.json and refuses a wrong pin.
#   scripts/ci/check-pins.sh component NAME VALUE      VALUE (a 40-hex commit) must equal the pinned commit of NAME
#   scripts/ci/check-pins.sh git NAME DIR              the HEAD of the checkout DIR (clean, no local change) must equal the pinned commit of NAME
#   scripts/ci/check-pins.sh env                       every component the lane reads from the environment (AGG_COMMIT + the aggregator provenance, P85_CONTRACTS, NBP_DIR,
#                                                      UTB_SDK_JS, M2_URETH_COMMIT + M2_URETH_BIN's reported commit, FOUNDRY) against the manifest; prints one line each
#   scripts/ci/check-pins.sh env-core                  the same for a lane without the aggregator, NBP and the SDK (ureth, contracts, Foundry)
#   scripts/ci/check-pins.sh selftest                  chain-free tests: a right pin is accepted, a wrong one, a short one and an unknown component are refused
# PINS=<file> selects another manifest (the self-test uses it). Exit status 0 only when everything checked matches.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PINS=${PINS:-$here/lane-pins.json}
bad=0
say() { printf '%s\n' "$*"; }
pin_of() { jq -er --arg n "$1" '.components[$n].commit // empty' "$PINS" 2>/dev/null; }

check_component() { # NAME VALUE
  local name=$1 value=$2 pin
  pin=$(pin_of "$name") || { say "FAIL  $name: not in the manifest"; return 1; }
  [[ $pin =~ ^[0-9a-f]{40}$ ]] || { say "FAIL  $name: the manifest commit '$pin' is not 40 hex"; return 1; }
  [[ $value =~ ^[0-9a-f]{40}$ ]] || { say "FAIL  $name: '$value' is not a full 40-hex commit"; return 1; }
  [ "$value" = "$pin" ] || { say "FAIL  $name: $value is not the pinned ${pin}"; return 1; }
  say "ok    $name = $pin"
}
check_git() { # NAME DIR
  local name=$1 dir=$2 head
  [ -d "$dir" ] || { say "FAIL  $name: $dir is not a directory"; return 1; }
  head=$(git -C "$dir" rev-parse HEAD 2>/dev/null) || { say "FAIL  $name: $dir is not a git checkout"; return 1; }
  [ -z "$(git -C "$dir" status --porcelain --untracked-files=no 2>/dev/null)" ] || { say "FAIL  $name: $dir has local changes"; return 1; }
  check_component "$name" "$head"
}

case "${1:-}" in
  component) check_component "${2:?NAME}" "${3:?VALUE}" || bad=1 ;;
  git) check_git "${2:?NAME}" "${3:?DIR}" || bad=1 ;;
  t6)   # the defaults of scripts/t6-rehearsal.sh against this manifest's t6 record (the script keeps its own pins; they must be the recorded ones)
    t6s=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/t6-rehearsal.sh
    c=$(jq -r '.t6.contracts.commit' "$PINS"); f=$(jq -r '.t6.foundry.linuxSha256' "$PINS"); v=$(jq -r '.t6.foundry.version' "$PINS")
    u=$(jq -r '.components.ureth.commit' "$PINS")
    grep -q "T6_CONTRACTS_COMMIT:-$c}" "$t6s" && say "ok    t6 contracts $c" || { say "FAIL  t6: the script's default contracts commit is not $c"; bad=1; }
    grep -q "digest=$f" "$t6s" && say "ok    t6 foundry linux asset $f" || { say "FAIL  t6: the script's Linux Foundry digest is not $f"; bad=1; }
    grep -q "foundry/releases/download/v$v/" "$t6s" && say "ok    t6 foundry v$v" || { say "FAIL  t6: the script does not download Foundry v$v"; bad=1; }
    grep -q "T6_URETH_COMMIT:-$u}" "$t6s" && say "ok    t6 ureth default is the lane's $u" || { say "FAIL  t6: the script's default ureth commit is not the lane's $u"; bad=1; }
    ;;
  env-core)   # the components a P85 / H6 lane without the aggregator reads: ureth (binary + provenance), contracts, Foundry
    check_git contracts "${P85_CONTRACTS:-/nonexistent}" || bad=1
    reported=$("${M2_URETH_BIN:-/nonexistent}" --version 2>&1 | sed -n 's/^Commit SHA: //p' | head -1)
    check_component ureth "${reported:-none}" || bad=1
    check_component ureth "${M2_URETH_COMMIT:-none}" || bad=1
    want=$(jq -r '.toolchains.foundry.version' "$PINS"); got=$(cast --version 2>/dev/null | sed -n 's/^cast Version: *\([0-9.]*\).*/\1/p; s/^cast \([0-9.]*\).*/\1/p' | head -1)
    if [ -n "$got" ] && [ "$got" = "${want#v}" ]; then say "ok    foundry $got"; else say "FAIL  foundry: cast reports '${got:-nothing}', the manifest pins '$want'"; bad=1; fi
    ;;
  env)
    check_component aggregator-go "${AGG_COMMIT:-none}" || bad=1
    if [ -n "${AGG_BIN:-}" ]; then
      prov=$(dirname "$AGG_BIN"); [ -s "$prov/commit.txt" ] && check_component aggregator-go "$(tr -d '[:space:]' <"$prov/commit.txt")" || { say "FAIL  aggregator-go: no provenance commit.txt beside AGG_BIN"; bad=1; }
    else say "FAIL  aggregator-go: AGG_BIN is not set"; bad=1; fi
    check_git contracts "${P85_CONTRACTS:-/nonexistent}" || bad=1
    check_git native-bridge-plugins "${NBP_DIR:-/nonexistent}" || bad=1
    check_git state-transition-sdk-js "${UTB_SDK_JS:-/nonexistent}" || bad=1
    reported=$("${M2_URETH_BIN:-/nonexistent}" --version 2>&1 | sed -n 's/^Commit SHA: //p' | head -1)
    check_component ureth "${reported:-none}" || bad=1
    check_component ureth "${M2_URETH_COMMIT:-none}" || bad=1
    want=$(jq -r '.toolchains.foundry.version' "$PINS"); got=$(cast --version 2>/dev/null | sed -n 's/^cast Version: *\([0-9.]*\).*/\1/p; s/^cast \([0-9.]*\).*/\1/p' | head -1)
    if [ -n "$got" ] && [ "$got" = "${want#v}" ]; then say "ok    foundry $got"; else say "FAIL  foundry: cast reports '${got:-nothing}', the manifest pins '$want'"; bad=1; fi
    ;;
  selftest)
    t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
    good=0123456789abcdef0123456789abcdef01234567
    printf '{"components":{"demo":{"commit":"%s"}}}\n' "$good" >"$t/pins.json"
    n=0; fails=0
    t_ok()  { n=$((n + 1)); if PINS=$t/pins.json "$0" component "$@" >/dev/null 2>&1; then echo "  ok    accepted: $*"; else echo "  FAIL  refused: $*"; fails=$((fails + 1)); fi; }
    t_no()  { n=$((n + 1)); if PINS=$t/pins.json "$0" component "$@" >/dev/null 2>&1; then echo "  FAIL  accepted: $*"; fails=$((fails + 1)); else echo "  ok    refused: $*"; fi; }
    t_ok demo "$good"
    t_no demo 1123456789abcdef0123456789abcdef01234567      # one hex digit different
    t_no demo "${good:0:12}"                                # abbreviated
    t_no demo ""                                            # empty
    t_no unknown "$good"                                    # not in the manifest
    mkdir "$t/repo" && git -C "$t/repo" init -q && git -C "$t/repo" -c user.email=a@b -c user.name=a commit -q --allow-empty -m x
    head=$(git -C "$t/repo" rev-parse HEAD); printf '{"components":{"demo":{"commit":"%s"}}}\n' "$head" >"$t/pins2.json"
    n=$((n + 1)); if PINS=$t/pins2.json "$0" git demo "$t/repo" >/dev/null 2>&1; then echo "  ok    a checkout at the pin is accepted"; else echo "  FAIL  a checkout at the pin was refused"; fails=$((fails + 1)); fi
    printf '{"components":{"demo":{"commit":"%s"}}}\n' "$good" >"$t/pins3.json"
    n=$((n + 1)); if PINS=$t/pins3.json "$0" git demo "$t/repo" >/dev/null 2>&1; then echo "  FAIL  a checkout at a wrong pin was accepted"; fails=$((fails + 1)); else echo "  ok    a checkout at a wrong pin is refused"; fi
    git -C "$t/repo" -c user.email=a@b -c user.name=a commit -q --allow-empty -m y; echo x >"$t/repo/f"; git -C "$t/repo" add f
    printf '{"components":{"demo":{"commit":"%s"}}}\n' "$(git -C "$t/repo" rev-parse HEAD)" >"$t/pins4.json"; echo y >>"$t/repo/f"
    n=$((n + 1)); if PINS=$t/pins4.json "$0" git demo "$t/repo" >/dev/null 2>&1; then echo "  FAIL  a dirty checkout was accepted"; fails=$((fails + 1)); else echo "  ok    a checkout with a local change is refused"; fi
    # the T6 script's own defaults against the manifest's t6 record: the real record is accepted, a record that differs (contracts commit, Foundry digest) is refused
    n=$((n + 1)); if "$0" t6 >/dev/null 2>&1; then echo "  ok    the T6 script's defaults match the record"; else echo "  FAIL  the T6 script's defaults do not match the record"; fails=$((fails + 1)); fi
    jq '.t6.contracts.commit="0123456789abcdef0123456789abcdef01234567"' "$PINS" >"$t/t6a.json"; jq '.t6.foundry.linuxSha256="00"' "$PINS" >"$t/t6b.json"
    for m in t6a t6b; do n=$((n + 1)); if PINS=$t/$m.json "$0" t6 >/dev/null 2>&1; then echo "  FAIL  a T6 record that differs from the script ($m) was accepted"; fails=$((fails + 1)); else echo "  ok    a T6 record that differs from the script ($m) is refused"; fi; done
    echo "check-pins self-test: $n cases, $fails failures"; [ "$fails" -eq 0 ]; exit $? ;;
  *) echo "usage: $0 component NAME VALUE | git NAME DIR | env | env-core | t6 | selftest" >&2; exit 2 ;;
esac
exit $bad
