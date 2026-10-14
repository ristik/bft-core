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

# L2: find the block that took the tip to E, dump it and its parent, and run the offline checks. Writes l2-before.json / l2-after.json into DIR.
anyage_check_ack() { # dir expectedTip fromBlock toBlock [span]
  local dir=$1 e=$2 lo=$3 hi=$4 span=${5:-2} n
  mkdir -p "$dir"
  n=$(anyage_first_block_with_tip "$e" "$lo" "$hi") || return 1
  anyage_registry_dump $((n - 1)) >"$dir/l2-before.json" && anyage_registry_dump "$n" >"$dir/l2-after.json" || return 1
  python3 -I "$ANYAGE_CHECK" ack "$dir/l2-before.json" "$dir/l2-after.json" --span "$span" || return 1
  echo "L2: block $n installed $span entries atomically on its parent $((n - 1)) (I=U=$e)"
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
anyage_dir() { echo "${H3_DIR:?}/anyage"; }
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

# L2: the acknowledgement block of the primary -> stalled successor -> exact recovery installed both entries on the frozen parent.
anyage_step_l2() {
  local out lo hi; out=$(anyage_dir); lo=$(cat "$out/setup-block.txt"); hi=$(anyage_latest)
  anyage_check_ack "$out" 3 "$lo" "$hi" 2 || return 1
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
  echo "L1c: the same saved bytes verified historically and the one vault release completed (release.json)"
}
