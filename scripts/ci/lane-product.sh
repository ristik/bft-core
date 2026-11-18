#!/usr/bin/env bash
# The dependency set of the product a lane run builds (bft-core#1139), and the check that the product and its ureth agree on the native precompiles.
#   scripts/ci/lane-product.sh manifest              prints the path of the manifest this run's jobs read. LANE_PRODUCT=checkout (or unset): scripts/ci/lane-pins.json
#                                                    itself. LANE_PRODUCT=pinned: a generated copy in which every component named in components["bft-core"].dependencies
#                                                    takes that record's commit (and its nativePrecompiles), so the frozen product is built and checked with its own ureth
#                                                    and contracts, never with the checkout's
#   scripts/ci/lane-product.sh compat [checkout|pinned|all]
#                                                    the product's engineapi/profile.go unicityNativePrecompiles is exactly the nativePrecompiles of the ureth it is paired
#                                                    with: checkout = this tree against the components' ureth; pinned = the bft-core pin's file (git show, so the
#                                                    commit must be in this clone's history) against the dependency set's ureth; all (the default) = both
#   scripts/ci/lane-product.sh compat-dir DIR        the same for the product checkout DIR against the manifest of LANE_PRODUCT (build-tools.sh: the product it builds)
#   scripts/ci/lane-product.sh selftest              chain-free tests of the above
# PINS=<file> selects another source manifest (the self-test uses it). Exit status 0 only when everything checked agrees.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/../.." && pwd)
PINS=${PINS:-$here/lane-pins.json}
say() { printf '%s\n' "$*"; }

# effective PRODUCT OUT: the manifest of PRODUCT written to OUT (checkout: a copy; pinned: the dependency set applied)
effective() {
  case "$1" in
    checkout) jq '.product = "checkout"' "$PINS" >"$2" ;;
    pinned)
      jq -e '.components["bft-core"].dependencies | type == "object" and ([to_entries[] | select(.value | type == "object")] | length > 0)' "$PINS" >/dev/null 2>&1 \
        || { say "FAIL  pinned: components[\"bft-core\"].dependencies names no dependency set (the frozen product would run with the checkout's components)" >&2; return 1; }
      jq -e '[.components["bft-core"].dependencies | to_entries[] | select(.value | type == "object") | .value.commit | test("^[0-9a-f]{40}$")] | all' "$PINS" >/dev/null 2>&1 \
        || { say "FAIL  pinned: a dependency commit is not 40 hex" >&2; return 1; }
      jq '.product = "pinned" | . as $m | reduce ($m.components["bft-core"].dependencies | to_entries[] | select(.value | type == "object")) as $d (.;
            .components[$d.key].commit = $d.value.commit
            | if $d.value.nativePrecompiles then .components[$d.key].nativePrecompiles = $d.value.nativePrecompiles else del(.components[$d.key].nativePrecompiles) end)' "$PINS" >"$2" ;;
    *) say "FAIL  unknown product '$1' (checkout or pinned)" >&2; return 1 ;;
  esac
}

manifest() {
  local product=${LANE_PRODUCT:-checkout} dir out
  [ "$product" = checkout ] && { printf '%s\n' "$PINS"; return 0; }
  dir=${LANE_PINS_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}; mkdir -p "$dir"; out=$dir/lane-pins.$product.json
  effective "$product" "$out" || return 1
  printf '%s\n' "$out"
}

# the unicityNativePrecompiles map of a profile.go on stdin, as sorted "name address" lines
profile_set() {
  awk '/^var unicityNativePrecompiles = map\[string\]string\{/ {on=1; next} on && /^\}/ {exit} on && match($0, /"[^"]+":[ \t]*"0x[0-9a-fA-F]+"/) {
         s = substr($0, RSTART, RLENGTH); gsub(/[" \t]/, "", s); split(s, kv, ":"); print kv[1], tolower(kv[2]) }' | LC_ALL=C sort
}
declared_set() { jq -r '.components.ureth.nativePrecompiles // {} | to_entries[] | "\(.key) \(.value | ascii_downcase)"' "$1" | LC_ALL=C sort; }

# agree LABEL PROFILE_TEXT_FILE MANIFEST
agree() {
  local label=$1 prof=$2 man=$3 want got ureth
  ureth=$(jq -r '.components.ureth.commit' "$man")
  want=$(declared_set "$man"); got=$(profile_set <"$prof")
  [ -n "$want" ] || { say "FAIL  $label: the manifest declares no nativePrecompiles for ureth $ureth"; return 1; }
  [ -n "$got" ] || { say "FAIL  $label: no unicityNativePrecompiles map in the product's engineapi/profile.go"; return 1; }
  if [ "$want" = "$got" ]; then say "ok    $label: the product's native precompiles are ureth ${ureth:0:8}'s ($(tr '\n' ' ' <<<"$want" | sed 's/ $//'))"; return 0; fi
  say "FAIL  $label: the product and ureth ${ureth:0:8} disagree on the native precompiles"
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^< /        only ureth declares: /p; s/^> /        only the product requires: /p'
  return 1
}

compat_one() { # PRODUCT
  local t m p rc=0; t=$(mktemp -d)
  m=$t/m.json; p=$t/profile.go
  effective "$1" "$m" || { rm -rf "$t"; return 1; }
  if [ "$1" = checkout ]; then
    cp "$repo/engineapi/profile.go" "$p" 2>/dev/null || { say "FAIL  checkout: no engineapi/profile.go in $repo"; rm -rf "$t"; return 1; }
  else
    local c; c=$(jq -er '.components["bft-core"].commit' "$m") || { say "FAIL  pinned: no bft-core commit"; rm -rf "$t"; return 1; }
    git -C "$repo" show "$c:engineapi/profile.go" >"$p" 2>/dev/null || { say "FAIL  pinned: bft-core $c is not in this clone's history (fetch it, or a full clone)"; rm -rf "$t"; return 1; }
  fi
  agree "$1 product" "$p" "$m" || rc=1
  rm -rf "$t"; return $rc
}

case "${1:-}" in
  manifest) manifest ;;
  compat)
    rc=0
    case "${2:-all}" in
      checkout|pinned) compat_one "$2" || rc=1 ;;
      all) compat_one checkout || rc=1; compat_one pinned || rc=1 ;;
      *) say "usage: lane-product.sh compat [checkout|pinned|all]" >&2; exit 2 ;;
    esac
    exit $rc ;;
  compat-dir)
    d=${2:?DIR}; t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
    effective "${LANE_PRODUCT:-checkout}" "$t/m.json" || exit 1
    [ -f "$d/engineapi/profile.go" ] || { say "FAIL  $d has no engineapi/profile.go"; exit 1; }
    agree "${LANE_PRODUCT:-checkout} product at $(git -C "$d" rev-parse --short HEAD 2>/dev/null || echo "$d")" "$d/engineapi/profile.go" "$t/m.json" ;;
  selftest)
    unset LANE_PRODUCT LANE_PINS_DIR   # each case names its product; a pinned job's environment must not leak into them
    t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
    n=0; fails=0
    ok() { n=$((n + 1)); if "$@" >"$t/out" 2>&1; then echo "  ok    $label"; else echo "  FAIL  $label"; sed 's/^/        /' "$t/out"; fails=$((fails + 1)); fi; }
    no() { n=$((n + 1)); if "$@" >"$t/out" 2>&1; then echo "  FAIL  accepted: $label"; fails=$((fails + 1)); else echo "  ok    refused: $label"; fi; }
    # a fake product history: commit A requires 0x0105, commit B (HEAD) does not
    r=$t/repo; mkdir -p "$r/engineapi" "$r/scripts/ci"; git -C "$r" init -q
    gofile() { printf 'package engineapi\n\nvar unicityNativePrecompiles = map[string]string{\n'; for kv in "$@"; do printf '\t"%s": "%s",\n' "${kv%%=*}" "${kv#*=}"; done; printf '}\n'; }
    a=unicity-b1-cert-batch-v2=0x0000000000000000000000000000000000000100; b=unicity-b2-sdk3=0x0000000000000000000000000000000000000104
    c=unicity-bridge-compose-v2=0x0000000000000000000000000000000000000105
    gofile "$a" "$b" "$c" >"$r/engineapi/profile.go"; git -C "$r" add -A; git -C "$r" -c user.email=a@b -c user.name=a commit -qm old; old=$(git -C "$r" rev-parse HEAD)
    gofile "$a" "$b" >"$r/engineapi/profile.go"; git -C "$r" -c user.email=a@b -c user.name=a commit -qam new
    cp "$0" "$r/scripts/ci/lane-product.sh"
    set3='{"unicity-b1-cert-batch-v2":"0x0000000000000000000000000000000000000100","unicity-b2-sdk3":"0x0000000000000000000000000000000000000104","unicity-bridge-compose-v2":"0x0000000000000000000000000000000000000105"}'
    set2='{"unicity-b1-cert-batch-v2":"0x0000000000000000000000000000000000000100","unicity-b2-sdk3":"0x0000000000000000000000000000000000000104"}'
    mk() { # OUT CHECKOUT_SET PINNED_SET_OR_null [extra jq]
      jq -n --arg old "$old" --argjson s "$2" --argjson ps "$3" '{components:{ureth:{commit:("2"*40),nativePrecompiles:$s},contracts:{commit:("3"*40)},
        "bft-core":{commit:$old,dependencies:(if $ps == null then {note:"x"} else {note:"x",ureth:{commit:("4"*40),nativePrecompiles:$ps},contracts:{commit:("5"*40)}} end)}}}' >"$1"; }
    run() { PINS=$1 bash "$r/scripts/ci/lane-product.sh" "${@:2}"; }
    mk "$t/good.json" "$set2" "$set3"
    label="checkout and pinned each agree with their own ureth"; ok run "$t/good.json" compat all
    mk "$t/shared.json" "$set2" null
    label="a pinned product without its own dependency set"; no run "$t/shared.json" compat pinned
    mk "$t/old-ureth.json" "$set3" "$set3"
    label="the checkout paired with a ureth that still registers 0x0105"; no run "$t/old-ureth.json" compat checkout
    mk "$t/new-ureth.json" "$set2" "$set2"
    label="the frozen product (requires 0x0105) paired with a ureth without it"; no run "$t/new-ureth.json" compat pinned
    moved=$(jq -c '."unicity-b2-sdk3" = "0x0000000000000000000000000000000000000106"' <<<"$set2"); mk "$t/moved.json" "$moved" "$set3"
    label="a moved address"; no run "$t/moved.json" compat checkout
    jq 'del(.components.ureth.nativePrecompiles)' "$t/good.json" >"$t/undeclared.json"
    label="a ureth with no declared set"; no run "$t/undeclared.json" compat checkout
    jq --arg c "$(printf 'f%.0s' {1..40})" '.components["bft-core"].commit = $c' "$t/good.json" >"$t/absent.json"
    label="a pinned product outside the clone's history"; no run "$t/absent.json" compat pinned
    label="the pinned manifest takes the dependency set's ureth and contracts"
    ok bash -c "m=\$(LANE_PRODUCT=pinned LANE_PINS_DIR='$t/eff' PINS='$t/good.json' bash '$r/scripts/ci/lane-product.sh' manifest) && [ \"\$(jq -r .components.ureth.commit \"\$m\")\" = $(printf '4%.0s' {1..40}) ] && [ \"\$(jq -r .components.contracts.commit \"\$m\")\" = $(printf '5%.0s' {1..40}) ] && [ \"\$(jq -r '.components.ureth.nativePrecompiles | length' \"\$m\")\" = 3 ]"
    label="the checkout manifest is the file itself"
    ok bash -c "[ \"\$(PINS='$t/good.json' bash '$r/scripts/ci/lane-product.sh' manifest)\" = '$t/good.json' ]"
    label="compat-dir: the checkout tree against the checkout set"; ok bash -c "PINS='$t/good.json' bash '$r/scripts/ci/lane-product.sh' compat-dir '$r'"
    label="compat-dir: the checkout tree against the pinned set"; no bash -c "LANE_PRODUCT=pinned PINS='$t/good.json' bash '$r/scripts/ci/lane-product.sh' compat-dir '$r'"
    label="the real manifest: both products agree with their ureth"; ok bash "$0" compat all
    echo "lane-product self-test: $n checks, $fails failures"
    [ "$fails" -eq 0 ] ;;
  *) sed -n '2,13p' "$0" >&2; exit 2 ;;
esac
