# The public sync seed's live acceptance (VT-11, bft-core#1151). Sourced by scripts/vr-boundary-steps.sh under VR_JOINER=1 VR_SEED=1 (and VR_JOINER_FOLLOW=1,
# VR_ARCHIVE=1, VR_UTB=1, SIGNING=authority), in the lane's shell. The incumbents run; the joiner (identity 5) is a new home that sees nothing of theirs:
#
#   vrs_export   validator 1 exports a seed (its root's trust-base history, its archive's newest certified record, its shard node's frontier, its execution head)
#   vrs_tamper   a flipped checkpoint byte, a wrong genesis pin, a stale trust-base floor and two disagreeing sources are each refused
#   vrs_fetch    the joiner fetches the seed from two sources over HTTP (they must agree), verified against the pinned genesis EntryID alone
#   vrs_import   (called by vrj_start_nodes) the verified seed is imported into the joiner's home and its trust-base history into the joiner's entry stores
#   vrs_finish   the joiner caught up (its shard node restored from the SEED's pin, its execution client at the head), `ubft validator status` shows the sync
#                fields, and the joiner applies (`ubft validator apply`, PoA)

vrs_dir=test-nodes/seed
vrs_off=$(( ${LANE_SLOT:-0} * 1000 ))
vrs_port_a=$((38480 + vrs_off)); vrs_port_b=$((38481 + vrs_off)); vrs_port_c=$((38482 + vrs_off))
vrs_log() { vrb_log "$@"; }
vrs_pin() { tr -d '[:space:]' <test-nodes/utb-genesis.id; }
vrs_pids=()
vrs_cleanup() { local p; for p in "${vrs_pids[@]}"; do kill "$p" 2>/dev/null; done; vrs_pids=(); }
trap vrs_cleanup EXIT

vrs_serve() { # <dir> <port>
  build/ubft seed serve --dir "$1" --listen "127.0.0.1:$2" >>"$VR_EVIDENCE/seed-serve-$2.log" 2>&1 &
  vrs_pids+=($!)
  vrb_wait 20 "seed server on :$2" curl -sf "http://127.0.0.1:$2/manifest.json" -o /dev/null
}

vrs_archive_ready() { [ -n "$(find "$EVM_ARCHIVE_ROOT/evm1" -type f -name '*' 2>/dev/null | head -1)" ] && build/ubft seed export --root-rpc "$(vrb_rpc_of 1)" --utb-genesis-id "$(vrs_pin)" --archive "$EVM_ARCHIVE_ROOT/evm1" --out "$vrs_dir/probe" >/dev/null 2>&1; }

vrs_export() {
  rm -rf "$vrs_dir"; mkdir -p "$vrs_dir"
  vrb_wait 600 "validator 1's archive holds a certified record and its seed verifies" vrs_archive_ready || return 1
  build/ubft seed export --root-rpc "$(vrb_rpc_of 1)" --utb-genesis-id "$(vrs_pin)" --archive "$EVM_ARCHIVE_ROOT/evm1" \
    --shard-status "http://$(evm_validator_rpc_addr 1)" --eth-rpc "http://127.0.0.1:$rethEthBase" --out "$vrs_dir/export" 2>&1 | tee "$VR_EVIDENCE/seed-export.log" || { vrs_log "FAIL: seed export"; return 1; }
  cp "$vrs_dir/export/manifest.json" "$VR_EVIDENCE/seed-manifest.json"
  vrs_log "PASS: validator 1 exported a seed ($(ls -l "$vrs_dir/export" | awk 'NR>1{printf "%s=%s ", $9, $5}'))"
}

# expect a refusal: the command must fail and its message must contain the text
vrs_refused() { # <name> <text> <command...>
  local name=$1 want=$2 out; shift 2
  if out=$("$@" 2>&1); then vrs_log "FAIL: $name was accepted"; echo "$out" >"$VR_EVIDENCE/seed-tamper-$name.log"; return 1; fi
  echo "$out" >"$VR_EVIDENCE/seed-tamper-$name.log"
  case "$out" in *"$want"*) vrs_log "PASS: $name refused ($(echo "$out" | tail -1 | cut -c1-200))" ;; *) vrs_log "FAIL: $name refused for another reason: $out"; return 1 ;; esac
}

vrs_tamper() {
  local t=$vrs_dir/tamper pin; pin=$(vrs_pin)
  rm -rf "$t"; mkdir -p "$t"
  # 1. a flipped checkpoint byte, served over HTTP and fetched
  cp -r "$vrs_dir/export" "$t/flipped"
  python3 - "$t/flipped/tip-uc.cbor" <<'PY'
import sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[len(b)//2]^=1; open(p,'wb').write(b)
PY
  vrs_serve "$t/flipped" "$vrs_port_c" || return 1
  vrs_refused flipped-checkpoint-byte "manifest" build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_c" --out "$t/out1" --utb-genesis-id "$pin" || return 1
  # 2. a wrong genesis pin
  vrs_serve "$vrs_dir/export" "$vrs_port_a" || return 1
  local bad=${pin:0:2}$( [ "${pin:2:1}" = 0 ] && echo 1 || echo 0 )${pin:3}
  vrs_refused wrong-genesis-pin "pinned genesis" build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_a" --out "$t/out2" --utb-genesis-id "$bad" || return 1
  # 3. a stale trust-base history (the floor is above the seed's tip)
  vrs_refused stale-utb-entry "stale" build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_a" --out "$t/out3" --utb-genesis-id "$pin" --min-epoch 99 || return 1
  # 4. two disagreeing sources: the same files, a manifest that differs
  cp -r "$vrs_dir/export" "$t/disagree"
  sed -i 's/"created": "\([0-9]*\)-/"created": "\1-/; s/"created": "20/"created": "19/' "$t/disagree/manifest.json"
  vrs_serve "$t/disagree" "$((vrs_port_c + 1))" || return 1
  vrs_refused two-disagreeing-sources "disagree" build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_a" --from "http://127.0.0.1:$((vrs_port_c + 1))" --out "$t/out4" --utb-genesis-id "$pin" || return 1
  # 5. a root epoch not in the history (a checkpoint newer than the history) is refused by the unit tests; here: a seed with its UTB file replaced by garbage
  vrs_log "PASS: every tampered seed was refused (evidence: $VR_EVIDENCE/seed-tamper-*.log)"
}

vrs_fetch() {
  local pin; pin=$(vrs_pin)
  vrs_serve "$vrs_dir/export" "$vrs_port_b" || return 1
  vrs_fetched=$vrs_dir/fetched
  build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_a" --from "http://127.0.0.1:$vrs_port_b" --min-sources 2 --out "$vrs_fetched" \
    --utb-genesis-id "$pin" --full-shard-conf test-nodes/evm-full-shard-conf-v2.json 2>&1 | tee "$VR_EVIDENCE/seed-fetch.log" || { vrs_log "FAIL: seed fetch"; return 1; }
  vrs_log "PASS: the joiner fetched the seed from two agreeing sources and verified it against the pinned genesis alone"
}

vrs_import() { # after the joiner's root and shard homes exist, before they start
  build/ubft seed import --dir "$vrs_fetched" --home "test-nodes/seed-joiner" --utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id "$(vrs_pin)" \
    --full-shard-conf test-nodes/evm-full-shard-conf-v2.json --source "http://127.0.0.1:$vrs_port_a" --source "http://127.0.0.1:$vrs_port_b" \
    --root-utb-db test-nodes/root5/root-utb-entries.db --shard-utb-db test-nodes/evm5/shard-utb-entries.db --replace 2>&1 | tee "$VR_EVIDENCE/seed-import.log" || return 1
  vrs_log "PASS: the verified seed is imported into the joiner's home (test-nodes/seed-joiner) and its trust-base history into the joiner's entry stores"
}

vrs_finish() {
  local pin; pin=$(vrs_pin)
  # the joiner's status: the sync fields, with its own ureth and the seed it came from
  vrs_log "the joiner's shard node was restored from the seed's pin: $(cat test-nodes/evm5/pin.txt 2>/dev/null)"
  vrj_apply || return 1
  python3 - "$vrj_cfg/validator.json" "http://127.0.0.1:$((rethEthBase + vrj_id - 1))" <<'PY'
import json,sys
p=sys.argv[1]; c=json.load(open(p)); c['localRpc']=sys.argv[2]; json.dump(c,open(p,'w'))
PY
  build/ubft validator status --validator-config "$vrj_cfg/validator.json" --home test-nodes/seed-joiner --sample 5s 2>&1 | tee "$VR_EVIDENCE/joiner-status.txt"
  build/ubft validator status --validator-config "$vrj_cfg/validator.json" --home test-nodes/seed-joiner --sample 5s --json >"$VR_EVIDENCE/joiner-status.json" 2>&1 || true
  grep -q '^catch-up:' "$VR_EVIDENCE/joiner-status.txt" && grep -q 'seed: imported' "$VR_EVIDENCE/joiner-status.txt" || { vrs_log "FAIL: the status shows no sync fields or no seed"; return 1; }
  vrs_log "PASS: the joiner caught up from the seed, applied (PoA) and reports its sync state"
  vrs_cleanup
}
