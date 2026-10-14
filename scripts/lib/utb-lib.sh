# The combined UTB acceptance lane (briefs/utb-signed-entries-design.md §11.4): the any-age/P85 lane machinery (ANYAGE_LANE=1: one aggregation partition, the
# EVM shard, exact-K recovery) with the signed trust-base entry profile on from the first voting epoch. Definitions only: sourcing this file starts nothing,
# reads nothing and takes no port.
#
# The caller defines (before calling a function): info (optional), and runs from the repository root (test-nodes/, build/ubft). UBFT overrides build/ubft.

UBFT=${UBFT:-build/ubft}
UTB_DIR=${UTB_DIR:-test-nodes/utb}

# The genesis artifacts of the deployment, generated once, in dependency order, from the epoch-1 trust base the lane already wrote (test-nodes/trust-base.json):
# the canonical genesis entry, its EntryID (the pin) and the manifest every later check recomputes. UTB_COMPONENTS is a space-separated list of name=value
# pins recorded in the manifest (ureth commit, contracts commit, the aggregator binary digest...).
utb_prepare_genesis() {
  local tb=${1:-test-nodes/trust-base.json} comp=() c out id
  for c in ${UTB_COMPONENTS:-}; do comp+=(--component "$c"); done
  mkdir -p "$UTB_DIR"
  out=$("$UBFT" trust-base utb-manifest --trust-base "$tb" --out-dir "$UTB_DIR" ${comp[@]+"${comp[@]}"}) || { echo "utb_prepare_genesis: the manifest could not be generated: $out" >&2; return 1; }
  id=$(sed -n 's/^utb genesis id *//p' <<<"$out")
  case "$id" in 0x????????????????????????????????????????????????????????????????) ;; *) echo "utb_prepare_genesis: no genesis EntryID in the tool's output: $out" >&2; return 1 ;; esac
  cp "$UTB_DIR/utb-genesis.cbor" test-nodes/utb-genesis.cbor
  printf '%s\n' "$id" >test-nodes/utb-genesis.id
  "$UBFT" trust-base utb-manifest --check "$UTB_DIR/utb-manifest.json" >/dev/null || { echo "utb_prepare_genesis: the generated manifest does not check out" >&2; return 1; }
}

# The flags a root or a shard node of the lane starts with. The pin is read from the file the generation wrote, never from a value copied into a script.
utb_pin() { tr -d '[:space:]' <test-nodes/utb-genesis.id; }
utb_root_flags() { # node (unused: every root has the same profile)
  [ -s test-nodes/utb-genesis.cbor ] && [ -s test-nodes/utb-genesis.id ] || { echo "utb_root_flags: no UTB genesis (utb_prepare_genesis first)" >&2; return 1; }
  echo "--utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id $(utb_pin)"
}
utb_shard_flags() { utb_root_flags "$@"; }

# The environment of the patched aggregator (dev4's local build, briefs/builds/aggregator-utb-<patch sha8>/README.md): UTB mode is enabled by UTB_GENESIS_ID; the
# genesis entry file is the fresh chain's history (UTB_BUNDLE_FILE would be a complete tagged history instead); UTB_ENTRIES_DB is its own append-only store. In UTB mode
# the binary uses neither the V1 trust-base files nor root REST.
utb_agg_env() { # K (1-based)
  local k=${1:-1}
  [ -s test-nodes/utb-genesis.cbor ] && [ -s test-nodes/utb-genesis.id ] || { echo "utb_agg_env: no UTB genesis (utb_prepare_genesis first)" >&2; return 1; }
  echo "UTB_GENESIS_FILE=$PWD/test-nodes/utb-genesis.cbor UTB_GENESIS_ID=$(utb_pin) UTB_ENTRIES_DB=$PWD/test-nodes/utb-agg$k.db"
}
# The aggregator's read-only binary history range (design 11.3 item 4): GET /api/v1/trustbases?from=E[&to=E]..., the PR6 response codec. The same endpoint serves the
# lane's reference client; port is the aggregator's (agg_port from scripts/lib/agg-lib.sh when it is loaded).
utb_agg_history_url() { local k=${1:-1} port=${AGG_PORT:-3001}; echo "http://127.0.0.1:$((port + k - 1))/api/v1/trustbases"; }

# The patched aggregator's provenance directory: the one whose sha256.txt records this binary's digest. It must also hold the base, the patch and a sha256.txt that
# records the patch's digest. Prints the directory.
utb_agg_provenance() { # BIN [BUILDS_DIR]
  local bin=$1 builds=${2:-${AGRE_ROOT:-..}/briefs/builds} sum d psum
  sum=$(shasum -a 256 "$bin" 2>/dev/null | cut -d' ' -f1)
  [ -n "$sum" ] || { echo "utb_agg_provenance: cannot read $bin" >&2; return 1; }
  for d in "$builds"/aggregator-utb-*/; do
    [ -s "${d}sha256.txt" ] && grep -q "^$sum " "${d}sha256.txt" || continue
    for f in base.txt patch.diff; do [ -s "${d}$f" ] || { echo "utb_agg_provenance: ${d}$f is missing or empty" >&2; return 1; }; done
    psum=$(shasum -a 256 "${d}patch.diff" | cut -d' ' -f1)
    grep -q "^$psum " "${d}sha256.txt" || { echo "utb_agg_provenance: ${d}sha256.txt does not record the patch digest $psum" >&2; return 1; }
    echo "${d%/}"; return 0
  done
  echo "utb_agg_provenance: no aggregator-utb-* provenance under $builds records the binary digest $sum" >&2
  return 1
}

# The components pinned in the manifest, from what the lane was given: the aggregator's base commit, patch and binary digests (from its provenance) and the other
# builds by their environment names.
utb_lane_components() {
  local d out=()
  [ -z "${M2_URETH_COMMIT:-}" ] || out+=("ureth=$M2_URETH_COMMIT")
  if [ -n "${AGG_BIN:-}" ] && d=$(utb_agg_provenance "$AGG_BIN" 2>/dev/null); then
    out+=("aggregator-base=$(awk 'NR==1{print $3}' "$d/base.txt")" "aggregator-patch=sha256:$(shasum -a 256 "$d/patch.diff" | cut -d' ' -f1)" "aggregator-binary=sha256:$(shasum -a 256 "$AGG_BIN" | cut -d' ' -f1)")
  fi
  [ -z "${P85_CONTRACTS:-}" ] || ! git -C "$P85_CONTRACTS" rev-parse HEAD >/dev/null 2>&1 || out+=("contracts=$(git -C "$P85_CONTRACTS" rev-parse HEAD)")
  [ -z "${NBP_DIR:-}" ] || ! git -C "$NBP_DIR" rev-parse HEAD >/dev/null 2>&1 || out+=("native-bridge-plugins=$(git -C "$NBP_DIR" rev-parse HEAD)")
  printf '%s ' "${out[@]+"${out[@]}"}"
}

# The evidence the lane must leave (design §11.4); a root log saying "signed" or a client printing the new epoch number is not evidence.
utb_evidence_required() {
  cat <<'LIST'
manifest/utb-manifest.json
manifest/build.txt
manifest/aggregator/base.txt
manifest/aggregator/patch.diff
manifest/aggregator/sha256.txt
bundle/initial.cbor
bundle/final.cbor
entries/ordinary-handoff.cbor
entries/recovery-first.cbor
entries/recovery-second.cbor
ucresp/piggyback-sample.cbor
verifier/ordinary.txt
verifier/recovery-first.txt
verifier/recovery-second.txt
catchup/client-gap-two-entries.log
catchup/aggregator-peer-repair.log
catchup/restart.log
handoff/ordinary-ack.log
handoff/recovery-closure.log
proofs/original-proof.sha256
proofs/historical-verify.log
proofs/bridge-receipt.json
history/client-reload.log
LIST
}

# utb_check_evidence DIR: every required file exists and is non-empty; the manifest still checks out; the original proof digest is the one the historical
# verification recorded (no refetch); the final bundle differs from the initial one (the chain advanced) and is the one the client reloaded.
utb_check_evidence() {
  local dir=$1 f missing=0
  [ -d "$dir" ] || { echo "utb_check_evidence: $dir is not a directory" >&2; return 1; }
  while read -r f; do
    [ -s "$dir/$f" ] || { echo "evidence missing or empty: $f" >&2; missing=1; }
  done < <(utb_evidence_required)
  [ "$missing" -eq 0 ] || return 1
  "$UBFT" trust-base utb-manifest --check "$dir/manifest/utb-manifest.json" >/dev/null 2>&1 || { echo "the evidence manifest does not check out against its trust base" >&2; return 1; }
  local want have
  want=$(tr -d '[:space:]' <"$dir/proofs/original-proof.sha256")
  grep -q "$want" "$dir/proofs/historical-verify.log" || { echo "the historical verification did not record the original proof digest $want" >&2; return 1; }
  [ "$(shasum -a 256 <"$dir/bundle/initial.cbor")" != "$(shasum -a 256 <"$dir/bundle/final.cbor")" ] || { echo "the final bundle equals the initial one: the chain did not advance" >&2; return 1; }
  have=$(shasum -a 256 <"$dir/bundle/final.cbor" | cut -d' ' -f1)
  grep -q "$have" "$dir/history/client-reload.log" || { echo "the client reload did not record the final bundle digest $have" >&2; return 1; }
  local e
  for e in ordinary recovery-first recovery-second; do
    grep -q "epoch" "$dir/verifier/$e.txt" && grep -qi "threshold" "$dir/verifier/$e.txt" || { echo "verifier/$e.txt lacks the predecessor epoch and the weighted threshold the independent verifier must print" >&2; return 1; }
  done
}

# ---- chain-free self-tests -----------------------------------------------------------------------------------------------------------------------------
utb_st() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "  ok    $what"; else echo "  FAIL  $what"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); fi; }
utb_st_no() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL  $what (accepted)"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); else echo "  ok    $what"; fi; }

# needs a built ubft ($UBFT) and a genesis trust base file: UTB_ST_TRUSTBASE (the Go test of the tool writes none; the lane's own preflight builds one)
utb_selftest() {
  UTB_ST_BAD=0
  local t cwd; cwd=$PWD; t=$(mktemp -d)
  trap 'rm -rf "$t"' RETURN
  [ -x "$UBFT" ] && [ -n "${UTB_ST_TRUSTBASE:-}" ] && [ -s "$UTB_ST_TRUSTBASE" ] || { echo "utb_selftest: set UBFT to a built ubft and UTB_ST_TRUSTBASE to an epoch-1 trust base file" >&2; return 1; }
  mkdir -p "$t/test-nodes"
  cp "$UTB_ST_TRUSTBASE" "$t/test-nodes/trust-base.json"
  ( cd "$t" || exit 1
    UBFT=$(cd "$cwd" && realpath "$UBFT") UTB_DIR="$t/test-nodes/utb" UTB_COMPONENTS="ureth=6e59b68c aggregator=sha256:00" utb_prepare_genesis ) \
    && echo "  ok    the genesis, its pin and the manifest are generated and check out" || { echo "  FAIL  utb_prepare_genesis"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); }
  ( cd "$t" || exit 1
    flags=$(utb_root_flags 1) && [ "$flags" = "--utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id $(tr -d '[:space:]' <test-nodes/utb-genesis.id)" ] ) \
    && echo "  ok    root and shard flags carry the generated file and the pin read from it" || { echo "  FAIL  utb_root_flags"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); }
  utb_st_no "no flags without a generated genesis" bash -c "cd '$t/empty' 2>/dev/null || mkdir -p '$t/empty' && cd '$t/empty' && source '$cwd/scripts/lib/utb-lib.sh' && utb_root_flags 1"
  # the aggregator provenance: the directory that records the binary and the patch is found; a missing patch, an unrecorded patch digest or an unknown binary is refused
  local bld="$t/builds" bin="$t/agg"
  mkdir -p "$bld/aggregator-utb-aaaaaaaa"
  printf 'binary\n' >"$bin"; printf 'patch\n' >"$bld/aggregator-utb-aaaaaaaa/patch.diff"; printf 'aggregator-go base: 63cdca1 (x)\n' >"$bld/aggregator-utb-aaaaaaaa/base.txt"
  printf '%s  patch.diff\n%s  binary\n' "$(shasum -a 256 <"$bld/aggregator-utb-aaaaaaaa/patch.diff" | cut -d' ' -f1)" "$(shasum -a 256 <"$bin" | cut -d' ' -f1)" >"$bld/aggregator-utb-aaaaaaaa/sha256.txt"
  utb_st "the aggregator provenance is found by the binary digest" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; [ \"\$(utb_agg_provenance '$bin' '$bld')\" = '$bld/aggregator-utb-aaaaaaaa' ]"
  utb_st_no "an unrecorded binary is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'other\n' >'$t/other'; utb_agg_provenance '$t/other' '$bld'"
  utb_st_no "a provenance that does not record the patch digest is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'edited\n' >>'$bld/aggregator-utb-aaaaaaaa/patch.diff'; utb_agg_provenance '$bin' '$bld'"
  printf 'patch\n' >"$bld/aggregator-utb-aaaaaaaa/patch.diff"
  utb_st "the aggregator environment carries the genesis, the pin and its own store" bash -c "cd '$t' && source '$cwd/scripts/lib/utb-lib.sh' && env=\$(utb_agg_env 2) && grep -q 'UTB_GENESIS_FILE=$t/test-nodes/utb-genesis.cbor' <<<\"\$env\" && grep -q 'UTB_GENESIS_ID=0x' <<<\"\$env\" && grep -q 'UTB_ENTRIES_DB=$t/test-nodes/utb-agg2.db' <<<\"\$env\""
  utb_st "the history URL follows the aggregator's port" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; [ \"\$(AGG_PORT=3100 utb_agg_history_url 2)\" = http://127.0.0.1:3101/api/v1/trustbases ]"
  # the evidence checker: a complete synthetic pack passes, and each broken property is refused by its own check
  local ev="$t/ev"
  mkdir -p "$ev"
  while read -r f; do mkdir -p "$ev/$(dirname "$f")"; printf 'x\n' >"$ev/$f"; done < <(utb_evidence_required)
  cp "$t/test-nodes/utb/utb-manifest.json" "$ev/manifest/utb-manifest.json"
  printf 'aa11\n' >"$ev/proofs/original-proof.sha256"; printf 'verified aa11 in the historical epoch\n' >"$ev/proofs/historical-verify.log"
  printf 'initial\n' >"$ev/bundle/initial.cbor"; printf 'final\n' >"$ev/bundle/final.cbor"
  printf 'reloaded %s\n' "$(shasum -a 256 <"$ev/bundle/final.cbor" | cut -d' ' -f1)" >"$ev/history/client-reload.log"
  for e in ordinary recovery-first recovery-second; do printf 'predecessor epoch 2 EntryID ab weight 3 threshold 3\n' >"$ev/verifier/$e.txt"; done
  UBFT=$(realpath "$UBFT") utb_st "a complete evidence pack is accepted" utb_check_evidence "$ev"
  UBFT=$(realpath "$UBFT") utb_st_no "a missing file is refused" bash -c "rm '$ev/catchup/restart.log'; source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' utb_check_evidence '$ev'"
  printf 'x\n' >"$ev/catchup/restart.log"
  UBFT=$(realpath "$UBFT") utb_st_no "an empty file is refused" bash -c ": >'$ev/catchup/restart.log'; source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' utb_check_evidence '$ev'"
  printf 'x\n' >"$ev/catchup/restart.log"
  UBFT=$(realpath "$UBFT") utb_st_no "a refetched (different) original proof is refused" bash -c "printf 'bb22\n' >'$ev/proofs/original-proof.sha256'; source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' utb_check_evidence '$ev'"
  printf 'aa11\n' >"$ev/proofs/original-proof.sha256"
  UBFT=$(realpath "$UBFT") utb_st_no "an unchanged chain (final bundle = initial) is refused" bash -c "cp '$ev/bundle/initial.cbor' '$ev/bundle/final.cbor'; printf 'reloaded %s\\n' \"\$(shasum -a 256 <'$ev/bundle/final.cbor' | cut -d' ' -f1)\" >'$ev/history/client-reload.log'; source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' utb_check_evidence '$ev'"
  printf 'final\n' >"$ev/bundle/final.cbor"; printf 'reloaded %s\n' "$(shasum -a 256 <"$ev/bundle/final.cbor" | cut -d' ' -f1)" >"$ev/history/client-reload.log"
  UBFT=$(realpath "$UBFT") utb_st_no "a verifier output without the threshold is refused" bash -c "printf 'epoch 2\n' >'$ev/verifier/ordinary.txt'; source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' utb_check_evidence '$ev'"
  printf 'predecessor epoch 2 EntryID ab weight 3 threshold 3\n' >"$ev/verifier/ordinary.txt"
  UBFT=$(realpath "$UBFT") utb_st_no "a manifest that does not match its trust base is refused" bash -c "sed -i.bak 's/\"networkId\": [0-9]*/\"networkId\": 99/' '$ev/manifest/utb-manifest.json'; sed -i.bak 's/utbGenesisEntryId\": \"0x[0-9a-f]*/utbGenesisEntryId\": \"0x00/' '$ev/manifest/utb-manifest.json'; source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' utb_check_evidence '$ev'"
  echo "utb lane self-test: $UTB_ST_BAD failures"
  [ "$UTB_ST_BAD" -eq 0 ]
}
