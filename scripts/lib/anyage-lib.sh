# Library of the any-age final lane (briefs/anyage-final-lane-plan.md). Definitions only: sourcing this file starts nothing and reads nothing.
# Needs cast (Foundry), jq and python3; registry reads are `cast storage` at a block, so they work against any ureth node and any historical block.

ANYAGE_REGISTRY=${ANYAGE_REGISTRY:-0xff00000000000000000000000000000000000002}
ANYAGE_CHECK=${ANYAGE_CHECK:-scripts/anyage/registry_check.py}
anyage_die() { echo "anyage: $*" >&2; return 1; }

# slot of a fixed registry word: keccak256("unicity.seal-registry/" || name)
anyage_slot() { "${ANYAGE_CAST:-cast}" keccak "unicity.seal-registry/$1"; }
# slot of entry word f of epoch e: keccak256(abi.encode(F("b1.entry"), e, f))
anyage_entry_slot() { # epoch field
  local enc; enc=$("${ANYAGE_CAST:-cast}" abi-encode 'f(bytes32,uint256,uint256)' "$(anyage_slot b1.entry)" "$1" "$2") || return 1
  "${ANYAGE_CAST:-cast}" keccak "$enc"
}
anyage_word() { # slot block -> the 32-byte word as a decimal integer (words here are small integers)
  local w; w=$("${ANYAGE_CAST:-cast}" storage "$ANYAGE_REGISTRY" "$1" --block "$2" --rpc-url "${ANYAGE_RPC:?set ANYAGE_RPC}") || return 1
  "${ANYAGE_CAST:-cast}" to-dec "$w"
}
anyage_fixed() { anyage_word "$(anyage_slot "$1")" "$2"; } # name block

# One block's registry as the JSON registry_check.py reads: the fixed words and, for every epoch g..I, the entry words the checks use.
anyage_registry_dump() { # block
  local b=$1 g i fmt init ready ue o e
  fmt=$(anyage_fixed b1.format "$b") && init=$(anyage_fixed b1.initialized "$b") && g=$(anyage_fixed b1.genesisEpoch "$b") && i=$(anyage_fixed b1.importedTipEpoch "$b") &&
    ready=$(anyage_fixed b1.originReady "$b") && ue=$(anyage_fixed origin.rootEpoch "$b") && o=$(anyage_fixed clock.rootRound "$b") || return 1
  printf '{"block":%s,"format":%s,"initialized":%s,"genesisEpoch":%s,"importedTipEpoch":%s,"originReady":%s,"originEpoch":%s,"originRound":%s,"entries":[' "$b" "$fmt" "$init" "$g" "$i" "$ready" "$ue" "$o"
  for e in $(seq "$g" "$i"); do
    local p s en h mc
    p=$(anyage_word "$(anyage_entry_slot "$e" 0)" "$b") && s=$(anyage_word "$(anyage_entry_slot "$e" 4)" "$b") && en=$(anyage_word "$(anyage_entry_slot "$e" 5)" "$b") &&
      h=$(anyage_word "$(anyage_entry_slot "$e" 6)" "$b") && mc=$(anyage_word "$(anyage_entry_slot "$e" 9)" "$b") || return 1
    [ "$e" = "$g" ] || printf ','
    printf '{"epoch":%s,"present":%s,"start":%s,"end":%s,"hasEnd":%s,"memberCount":%s}' "$e" "$p" "$s" "$en" "$h" "$mc"
  done
  printf ']}\n'
}

# The first block in [lo, hi] at which the imported tip is >= target (the tip never decreases): the acknowledgement block of an install.
anyage_first_block_with_tip() { # target lo hi
  local t=$1 lo=$2 hi=$3 mid v
  v=$(anyage_fixed b1.importedTipEpoch "$hi") || return 1
  [ "$v" -ge "$t" ] || { anyage_die "tip at block $hi is $v, below $t"; return 1; }
  while [ "$lo" -lt "$hi" ]; do
    mid=$(((lo + hi) / 2)); v=$(anyage_fixed b1.importedTipEpoch "$mid") || return 1
    if [ "$v" -ge "$t" ]; then hi=$mid; else lo=$((mid + 1)); fi
  done
  echo "$lo"
}

# hash forms: 0x-hex, bare hex, or base64 of 32 bytes -> lowercase bare hex
anyage_norm_hash() { python3 -I - "$1" <<'PY'
import base64, re, sys
v = sys.argv[1].strip().strip('"')
h = v[2:] if v.lower().startswith('0x') else v
if re.fullmatch(r'[0-9a-fA-F]{64}', h): print(h.lower())
else:
    b = base64.b64decode(v)
    assert len(b) == 32, 'not a 32-byte hash: ' + v
    print(b.hex())
PY
}

# Records the frozen parent while the shard is frozen (after the activation, before the acknowledgement): the root's certified input record of the EVM
# partition names the block the root froze (the Prepare binds it, the Freeze commits it, the Ack transition carries it); the reth head must be that very block.
anyage_record_frozen() { # dir rootRow(JSON of the EVM partition's row in the root's round info)
  local dir=$1 row=$2 rowhash head headhash num
  mkdir -p "$dir"
  rowhash=$(printf '%s' "$row" | jq -r '[.. | objects | select(has("blockHash")) | .blockHash][0] // empty') || return 1
  [ -n "$rowhash" ] || { anyage_die "the root's EVM partition row has no blockHash field: $row"; return 1; }
  rowhash=$(anyage_norm_hash "$rowhash") || return 1
  num=$(anyage_latest) || return 1
  headhash=$(anyage_norm_hash "$("${ANYAGE_CAST:-cast}" block "$num" --field hash --rpc-url "$ANYAGE_RPC")") || return 1
  [ "$rowhash" = "$headhash" ] || { anyage_die "the root's frozen block $rowhash is not the reth head $headhash at block $num"; return 1; }
  printf '{"frozenParentHash":"%s","frozenParentNumber":%s,"importedTipEpoch":%s,"originReady":%s,"recordCursor":%s,"recordCount":%s}\n' "$rowhash" "$num" \
    "$(anyage_fixed b1.importedTipEpoch "$num")" "$(anyage_fixed b1.originReady "$num")" "$(anyage_custody_cursor "$num")" "$(anyage_registry_count "$num")" >"$dir/frozen-parent.json"
}
anyage_custody_cursor() { "${ANYAGE_CAST:-cast}" call "${ANYAGE_CUSTODY:?}" 'recordCursor()(uint64)' --block "$1" --rpc-url "$ANYAGE_RPC" | awk '{print $1}'; }
anyage_election_cursor() { "${ANYAGE_CAST:-cast}" call "${ANYAGE_ELECTION:?}" 'attemptCursor()(uint64)' --block "$1" --rpc-url "$ANYAGE_RPC" | awk '{print $1}'; }
anyage_election_last() { "${ANYAGE_CAST:-cast}" call "${ANYAGE_ELECTION:?}" 'lastAttemptResult()(bytes32)' --block "$1" --rpc-url "$ANYAGE_RPC" | tail -n1; }
anyage_registry_count() { "${ANYAGE_CAST:-cast}" call "${ANYAGE_POS_REGISTRY:?}" 'recordCount()(uint64)' --block "$1" --rpc-url "$ANYAGE_RPC" | awk '{print $1}'; }

# L2: find the block that took the imported tip to E = (tip while frozen) + span, dump it and its parent, and run the offline checks. Beyond the dumps:
#  - the Ack block's PARENT is exactly the frozen parent the root froze (hash and number from anyage_record_frozen);
#  - the custody record cursor advanced ONCE in that block: cursor(n) - cursor(n-1) = min(H, recordCount(n) - cursor(n-1)), never beyond the count;
#  - the block's receipts are kept (eth_getBlockReceipts).
# E is derived, never assumed: it is the tip at the freeze plus the span.
anyage_check_ack() { # dir fromBlock toBlock hRecords [span]
  local dir=$1 lo=$2 hi=$3 h=$4 span=${5:-2} f e n ph fh fnum c0 c1 cnt want ec0 ec1 el0 el1
  f="$dir/frozen-parent.json"; [ -s "$f" ] || { anyage_die "no $f: the frozen parent was not recorded"; return 1; }
  e=$(( $(jq -r .importedTipEpoch "$f") + span )); fh=$(jq -r .frozenParentHash "$f"); fnum=$(jq -r .frozenParentNumber "$f")
  mkdir -p "$dir"
  n=$(anyage_first_block_with_tip "$e" "$lo" "$hi") || return 1
  anyage_registry_dump $((n - 1)) >"$dir/l2-before.json" && anyage_registry_dump "$n" >"$dir/l2-after.json" || return 1
  python3 -I "$ANYAGE_CHECK" ack "$dir/l2-before.json" "$dir/l2-after.json" --span "$span" || return 1
  ph=$(anyage_norm_hash "$("${ANYAGE_CAST:-cast}" block $((n - 1)) --field hash --rpc-url "$ANYAGE_RPC")") || return 1
  [ "$ph" = "$fh" ] && [ $((n - 1)) -eq "$fnum" ] || { anyage_die "the Ack block $n is not built on the frozen parent: parent $((n - 1)) $ph, frozen $fnum $fh"; return 1; }
  c0=$(anyage_custody_cursor $((n - 1))) && c1=$(anyage_custody_cursor "$n") && cnt=$(anyage_registry_count "$n") || return 1
  want=$(python3 -I -c "print(min($h, $cnt - $c0))") || return 1
  [ "$((c1 - c0))" -eq "$want" ] && [ "$c1" -le "$cnt" ] || { anyage_die "custody cursor $c0 -> $c1 in the Ack block (records $cnt, H $h): expected an advance of $want"; return 1; }
  # the election hook: elect(origin) runs once per block, so the attempt cursor moves by at most one, and the last attempt result changes exactly when it does
  ec0=$(anyage_election_cursor $((n - 1))) && ec1=$(anyage_election_cursor "$n") && el0=$(anyage_election_last $((n - 1))) && el1=$(anyage_election_last "$n") || return 1
  [ $((ec1 - ec0)) -ge 0 ] && [ $((ec1 - ec0)) -le 1 ] || { anyage_die "election attempt cursor $ec0 -> $ec1 in the Ack block: the hook ran more than once"; return 1; }
  if [ "$ec1" = "$ec0" ]; then [ "$el0" = "$el1" ] || { anyage_die "the last attempt result changed without the attempt cursor"; return 1; }
  else [ "$el0" != "$el1" ] || { anyage_die "the attempt cursor advanced but the last attempt result did not change"; return 1; }; fi
  printf '{"ackBlock":%s,"parentBlock":%s,"frozenParentHash":"%s","tipBefore":%s,"tipAfter":%s,"cursorBefore":%s,"cursorAfter":%s,"recordCount":%s,"hRecords":%s,"electionAttemptBefore":%s,"electionAttemptAfter":%s,"lastAttemptResultBefore":"%s","lastAttemptResultAfter":"%s"}\n' \
    "$n" "$((n - 1))" "$ph" "$(jq -r .importedTipEpoch "$dir/l2-before.json")" "$e" "$c0" "$c1" "$cnt" "$h" "$ec0" "$ec1" "$el0" "$el1" >"$dir/l2-summary.json"
  "${ANYAGE_CAST:-cast}" block "$n" --json --rpc-url "$ANYAGE_RPC" >"$dir/l2-ack-block.json" || return 1
  "${ANYAGE_CAST:-cast}" rpc eth_getBlockReceipts "$(printf '0x%x' "$n")" --rpc-url "$ANYAGE_RPC" >"$dir/l2-ack-receipts.json" 2>"$dir/l2-ack-receipts.err" ||
    { anyage_die "eth_getBlockReceipts failed: $(head -c 200 "$dir/l2-ack-receipts.err")"; return 1; }
  echo "L2: block $n (parent $((n - 1)) = the frozen parent) installed $span entries (I=U=$e) and the custody cursor advanced $c0 -> $c1 once; receipts kept"
}

# Tooling self-test, no chain: the slot derivations equal b1state.FixedSlot / EntrySlot (values taken from the Go functions) and the offline checker's own tests pass.
anyage_selftest() {
  [ "$(anyage_slot b1.format)" = 0xc20ac95bd1f18a98e5ed96b1b03ef2b328ecb52f3bbcd1e981a85385fa0fb5ba ] || { anyage_die "fixed slot derivation differs from b1state.FixedSlot"; return 1; }
  [ "$(anyage_entry_slot 3 4)" = 0x34b51344c5e6d4ad3c4c4ec51cd9fbf82f4d20c905d8bea69796f5b73d8b5c4b ] || { anyage_die "entry slot derivation differs from b1state.EntrySlot"; return 1; }
  python3 -I "$ANYAGE_CHECK" --selftest
}

# ---- lane steps (ANYAGE_LANE=1; sourced by scripts/p85-recovery-steps.sh, which supplies p85_eth, p85_paid, H3_DIR, p85_view ...) --------------------------------
# Each step is a function the P85 step runner calls like its own (nonzero return = the lane fails and tears down). The plug-in driver is the nbp checkout's
# tests/live/anyage.ts (save / verify --epoch current|historical / release, protocol 4); NOTHING is refreshed between its commands.
ANYAGE_WINDOW=${ANYAGE_WINDOW:-30}   # the retired certificate window, in root rounds
# absolute: the driver runs from the nbp checkout, so a relative evidence path would land there
anyage_dir() { mkdir -p "${H3_DIR:?}" && echo "$(cd "$H3_DIR" && pwd)/anyage"; }
anyage_nbp() { (cd "${NBP_DIR:?set NBP_DIR}" && DNB_TOOL="${DNB_TOOL:?set DNB_TOOL}" npx --no-install tsx tests/live/anyage.ts "$@"); }
anyage_O() { anyage_fixed clock.rootRound latest; }
anyage_latest() { "${ANYAGE_CAST:-cast}" block-number --rpc-url "$ANYAGE_RPC"; }
anyage_saved_round() { jq -r '[.anchors[].round | tonumber] | max' "$(anyage_dir)/l1/saved.json"; }

# After the baseline: deploy the verifier and the vault on the live devnet, write the driver's lane config, and save the L1 token proof (L1a).
anyage_step_setup() {
  local out; out=$(anyage_dir); mkdir -p "$out/l1"
  export ANYAGE_RPC; ANYAGE_RPC=$(p85_eth)
  CONTRACTS=${P85_CONTRACTS:?} BRIDGE_IDENTITIES=test-nodes/b1-identities.json bridge_deploy_vault >"$out/vault-deploy.out" 2>&1 || { tail -20 "$out/vault-deploy.out" >&2; return 1; }
  BRIDGE_FULL_CONF=test-nodes/evm-full-shard-conf-v2.json BRIDGE_ARCHIVE=test-nodes/h3-archives bridge_write_config || return 1
  cp test-nodes/lane-config.json test-nodes/bridge-addresses.json test-nodes/bridge-deployment.json "$out/"
  anyage_latest >"$out/setup-block.txt"
  anyage_registry_dump "$(cat "$out/setup-block.txt")" >"$out/l1a-registry.json" || return 1
  python3 -I "$ANYAGE_CHECK" shape "$out/l1a-registry.json" || return 1
  anyage_nbp save "$PWD/test-nodes/lane-config.json" "$out/l1" 2>&1 | tee "$out/l1/save.log" || return 1
  [ -s "$out/l1/saved.json" ] && [ -s "$out/l1/envelope.bin" ] || { echo "save wrote no saved.json / envelope.bin" >&2; return 1; }
  (cd "$out/l1" && shasum -a 256 saved.json token.cbor envelope.bin batch-request.bin >SHA256SUMS)
  echo "L1a: the original proof bytes are saved ($(cut -c1-16 "$out/l1/SHA256SUMS" | head -1)...), anchors' latest round $(anyage_saved_round)"
}

# L1b: once the registry clock is more than the retired window past the saved anchors, the SAME bytes verify in the current epoch (eth_call only).
anyage_step_l1b() {
  local out r i o; out=$(anyage_dir); r=$(anyage_saved_round)
  for i in $(seq 1 120); do
    o=$(anyage_O) || return 1
    [ $((o - r)) -gt "$ANYAGE_WINDOW" ] && break
    p85_paid 1 >/dev/null 2>&1 || true   # a paid transaction makes the EVM shard build a block, which carries the clock forward
    sleep 2
  done
  [ $((o - r)) -gt "$ANYAGE_WINDOW" ] || { echo "the registry clock O=$o never passed the saved round $r by more than $ANYAGE_WINDOW" >&2; return 1; }
  (cd "$out/l1" && shasum -a 256 -c SHA256SUMS >/dev/null) || { echo "the saved proof bytes changed" >&2; return 1; }
  anyage_registry_dump "$(anyage_latest)" >"$out/l1b-registry.json" && python3 -I "$ANYAGE_CHECK" shape "$out/l1b-registry.json" || return 1
  anyage_nbp verify "$PWD/test-nodes/lane-config.json" "$out/l1/saved.json" --epoch current 2>&1 | tee "$out/l1/verify-current.log" || return 1
  jq -e '.batch.valid == true' "$out/l1/verify-current.json" >/dev/null || { echo "the native verdict on the saved request is not valid" >&2; return 1; }
  echo "L1b: saved proofs verify in the current epoch with O - r = $((o - r)) > $ANYAGE_WINDOW (retired window)"
}

# Between the activation and the acknowledgement the shard is frozen: record the block the root froze (and the cursors) for L2.
anyage_step_frozen() {
  local out; out=$(anyage_dir); export ANYAGE_RPC; ANYAGE_RPC=$(p85_eth)
  ANYAGE_CUSTODY=$(p85_custody) ANYAGE_POS_REGISTRY=$(p85_registry) anyage_record_frozen "$out" "$(h3_evm_row)" || return 1
  echo "frozen parent $(jq -r '.frozenParentHash' "$out/frozen-parent.json") (block $(jq -r .frozenParentNumber "$out/frozen-parent.json")), tip $(jq -r .importedTipEpoch "$out/frozen-parent.json")"
}

# L2: the acknowledgement block of the primary -> stalled successor -> exact recovery installed both entries on the frozen parent.
anyage_step_l2() {
  local out lo hi h; out=$(anyage_dir); lo=$(cat "$out/setup-block.txt"); hi=$(anyage_latest)
  h=$(jq -r .hRecords "$H3_DIR/b1-profile.json") || return 1
  export ANYAGE_CUSTODY ANYAGE_POS_REGISTRY ANYAGE_ELECTION; ANYAGE_CUSTODY=$(p85_custody); ANYAGE_POS_REGISTRY=$(p85_registry); ANYAGE_ELECTION=$(p85_election)
  anyage_check_ack "$out" "$lo" "$hi" "$h" 2 || return 1
  anyage_registry_dump "$hi" >"$out/l2-final-registry.json" && python3 -I "$ANYAGE_CHECK" shape "$out/l2-final-registry.json" || return 1
}

# L1c: after L2 the same saved bytes verify against the now-historical epoch; then the ONE vault release and the claim.
anyage_step_l1c() {
  local out; out=$(anyage_dir)
  (cd "$out/l1" && shasum -a 256 -c SHA256SUMS >/dev/null) || { echo "the saved proof bytes changed" >&2; return 1; }
  anyage_nbp verify "$PWD/test-nodes/lane-config.json" "$out/l1/saved.json" --epoch historical 2>&1 | tee "$out/l1/verify-historical.log" || return 1
  jq -e '.batch.valid == true' "$out/l1/verify-historical.json" >/dev/null || { echo "the native verdict on the saved request is not valid in the historical epoch" >&2; return 1; }
  anyage_nbp release "$PWD/test-nodes/lane-config.json" "$out/l1/saved.json" 2>&1 | tee "$out/l1/release.log" || return 1
  [ -s "$out/l1/release.json" ] || { echo "release wrote no release.json" >&2; return 1; }
  # the L1 evidence the matrix asks for: gas, the nullifier the vault recorded, and the balance delta of the claim
  jq -e --slurpfile s "$out/l1/saved.json" '(.redeem.gasUsed | tonumber) > 0 and .nullifier == $s[0].nullifier and (.balanceDelta | tostring) == ($s[0].amountWei | tostring) and (.claim.gasUsed | tonumber) > 0'     "$out/l1/release.json" >/dev/null || { echo "release.json lacks gas / the saved nullifier / the balance delta equal to the locked amount" >&2; return 1; }
  echo "L1c: the same saved bytes verified historically and the one vault release completed (release.json)"
}

# Chain-free test of the L2 shell logic (scripts/anyage/fakechain.py answers cast): the lawful scenario passes, each false claim is refused.
anyage_selftest_ack() {
  local d; d=$(mktemp -d) || return 1
  export FAKE_REAL_CAST FAKE_CACHE; FAKE_REAL_CAST=$(command -v cast); FAKE_CACHE=$d/fake-cache.json
  local fake; fake="$(cd "$(dirname "${BASH_SOURCE[0]}")/../anyage" && pwd)/fakecast.sh"
  (
    ANYAGE_CAST=$fake ANYAGE_RPC=fake ANYAGE_CUSTODY=0xc ANYAGE_POS_REGISTRY=0xd ANYAGE_ELECTION=0xe
    printf '{"frozenParentHash":"%s","frozenParentNumber":4,"importedTipEpoch":1}\n' "$(printf '%064x' $((0xA0000 + 4)))" >"$d/frozen-parent.json"
    anyage_check_ack "$d" 1 6 8 2 >/dev/null || { echo "selftest: the lawful scenario was refused" >&2; exit 1; }
    for bad in parent cursor election election-result; do
      FAKE_BAD=$bad anyage_check_ack "$d" 1 6 8 2 >/dev/null 2>&1 && { echo "selftest: a false $bad claim was accepted" >&2; exit 1; }
    done
    printf '{"frozenParentHash":"%s","frozenParentNumber":3,"importedTipEpoch":1}\n' "$(printf '%064x' $((0xA0000 + 4)))" >"$d/frozen-parent.json"
    anyage_check_ack "$d" 1 6 8 2 >/dev/null 2>&1 && { echo "selftest: a wrong frozen block number was accepted" >&2; exit 1; }
    printf '{"frozenParentHash":"%s","frozenParentNumber":4,"importedTipEpoch":1}\n' "$(printf '%064x' $((0xA0000 + 7)))" >"$d/frozen-parent.json"
    anyage_check_ack "$d" 1 6 8 2 >/dev/null 2>&1 && { echo "selftest: a wrong frozen hash was accepted" >&2; exit 1; }
    exit 0
  ) || { rm -rf "$d"; return 1; }
  rm -rf "$d"; echo "anyage L2 shell logic selftest: ok"
}
