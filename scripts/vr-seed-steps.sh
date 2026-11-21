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
# the seed servers' ports: 38480..38483 shifted by the lane's port offset (#1218: LANE_SLOT * 1000, or LANE_PORT_BASE); scripts/lib/lane-slot.sh lists them
declare -F utb_pin >/dev/null || source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/utb-lib.sh"
vrs_port_a=$(lane_port 38480); vrs_port_b=$(lane_port 38481); vrs_port_c=$(lane_port 38482)
vrs_log() { vrb_log "$@"; }
vrs_pin() { tr -d '[:space:]' <test-nodes/utb-genesis.id; }
vrs_pids=()
vrs_bundle_url=http://127.0.0.1:$(lane_port 38600)   # root 1's isolated bundle listener (utb_root_flags)
vrs_cleanup() { local p; for p in "${vrs_pids[@]}"; do kill "$p" 2>/dev/null; done; vrs_pids=(); }
# NO trap here: this file is sourced into the harness shell, whose EXIT trap stops the devnet. Cleanup is vrs_cleanup, called by the steps that end
# the seed work and by the harness failure path (vr-boundary-steps.sh); every server is also recorded in the lane's extra-pids (vrs_serve).

# a server of an earlier (killed) run of THIS tree is stopped first: its pid is in the lane's extra-pids, checked by command and working directory
vrs_kill_extra() {
  local f=test-nodes/q3/extra-pids p pat keep=
  [ -f "$f" ] || return 0
  # only this file's own entries (command 'ubft seed serve', owned by this checkout) are signalled and dropped; every other helper's entry stays
  while read -r p pat; do
    [ -n "${p:-}" ] || continue
    if [ "${pat:-}" = 'ubft seed serve' ]; then
      declare -F owned_pid >/dev/null && owned_pid "$p" "$pat" && kill -INT "$p" 2>/dev/null
    else
      keep+="$p $pat"$'\n'
    fi
  done <"$f"
  if [ -n "$keep" ]; then printf '%s' "$keep" >"$f"; else rm -f "$f"; fi
  sleep 1
}
vrs_serve() { # <dir> <port>
  declare -F q3_record_extra_pid >/dev/null || source scripts/lib/q3-lib.sh
  if (exec 3<>"/dev/tcp/127.0.0.1/$2") 2>/dev/null; then vrs_log "FAIL: port $2 (this lane's seed server port) is already in use by a process this lane does not own"; return 1; fi
  build/ubft seed serve --dir "$1" --listen "127.0.0.1:$2" >>"$VR_EVIDENCE/seed-serve-$2.log" 2>&1 &
  vrs_pids+=($!)
  q3_record_extra_pid $! 'ubft seed serve'   # the lane's cleanup and the next run's preflight (vrs_kill_extra) stop it
  vrb_wait 20 "seed server on :$2" curl -sf "http://127.0.0.1:$2/manifest.json" -o /dev/null
}

vrs_archive_ready() { [ -n "$(find "$EVM_ARCHIVE_ROOT/evm1" -type f -name '*' 2>/dev/null | head -1)" ] && build/ubft seed export --bundle-url "$vrs_bundle_url" --utb-genesis-id "$(vrs_pin)" --archive "$EVM_ARCHIVE_ROOT/evm1" --out "$vrs_dir/probe" >/dev/null 2>&1; }

vrs_export() {
  vrs_kill_extra
  declare -F m2_rpc_port >/dev/null || vrj_source_libs || return 1   # m2_rpc_port, evm_validator_rpc_addr: the lane libraries
  rm -rf "$vrs_dir"; mkdir -p "$vrs_dir"
  vrb_wait 600 "validator 1's archive holds a certified record and its seed verifies" vrs_archive_ready || return 1
  build/ubft seed export --bundle-url "$vrs_bundle_url" --utb-genesis-id "$(vrs_pin)" --archive "$EVM_ARCHIVE_ROOT/evm1" \
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
  cp "$vrj_cfg/validator.json" test-nodes/seed-joiner/validator.json   # the validator home holds validator.json and the seed import (status reads seed/import.json beside the config)
  build/ubft validator status --validator-config "$PWD/test-nodes/seed-joiner/validator.json" --sample 5s 2>&1 | tee "$VR_EVIDENCE/joiner-status.txt"
  build/ubft validator status --validator-config "$PWD/test-nodes/seed-joiner/validator.json" --sample 5s --json >"$VR_EVIDENCE/joiner-status.json" 2>&1 || true
  grep -q '^catch-up:' "$VR_EVIDENCE/joiner-status.txt" && grep -q 'seed: imported' "$VR_EVIDENCE/joiner-status.txt" || { vrs_log "FAIL: the status shows no sync fields or no seed"; return 1; }
  vrs_log "PASS: the joiner caught up from the seed, applied (PoA) and reports its sync state"
  vrs_cleanup
}

# vrs_second (VR_SEED2=1, after the Boundary): a seed whose trust-base history has two entries and whose checkpoint is of root epoch 2, fetched and
# imported into a fresh home and fresh entry stores: the cross-epoch verification live. A history cut back to epoch 1 under the same checkpoint is refused.
vrs_epoch_ready() { # the exported seed's checkpoint is of root epoch >= 2 and its history tip is >= 2
  rm -rf "$vrs_dir/export2"
  build/ubft seed export --bundle-url "$vrs_bundle_url" --utb-genesis-id "$(vrs_pin)" --archive "$EVM_ARCHIVE_ROOT/evm1" --out "$vrs_dir/export2" >/dev/null 2>&1 \
    && python3 -c "import json,sys;m=json.load(open('$vrs_dir/export2/manifest.json'));sys.exit(0 if m['checkpoint']['rootEpoch']>=2 and m['network']['utbTipEpoch']>=2 else 1)"
}
vrs_second() {
  vrs_kill_extra
  declare -F m2_rpc_port >/dev/null || vrj_source_libs || return 1
  local pin d=$vrs_dir/second; pin=$(vrs_pin); mkdir -p "$vrs_dir" "$d"
  vrb_wait 900 "validator 1's archive holds a root epoch 2 certified record and the history tip is epoch 2" vrs_epoch_ready || return 1
  build/ubft seed export --bundle-url "$vrs_bundle_url" --utb-genesis-id "$pin" --archive "$EVM_ARCHIVE_ROOT/evm1" --out "$vrs_dir/export2" --replace 2>&1 | tee "$VR_EVIDENCE/seed2-export.log"
  cp "$vrs_dir/export2/manifest.json" "$VR_EVIDENCE/seed2-manifest.json"
  vrs_serve "$vrs_dir/export2" "$vrs_port_a" || return 1
  vrs_serve "$vrs_dir/export2" "$vrs_port_b" || return 1
  build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_a" --from "http://127.0.0.1:$vrs_port_b" --min-sources 2 --out "$d/fetched" --utb-genesis-id "$pin" \
    --full-shard-conf test-nodes/evm-full-shard-conf-v2.json 2>&1 | tee "$VR_EVIDENCE/seed2-fetch.log" || { vrs_log "FAIL: second seed fetch"; return 1; }
  build/ubft seed import --dir "$d/fetched" --home "$d/home" --utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id "$pin" \
    --root-utb-db "$d/root-utb-entries.db" --shard-utb-db "$d/shard-utb-entries.db" 2>&1 | tee "$VR_EVIDENCE/seed2-import.log" || { vrs_log "FAIL: second seed import"; return 1; }
  grep -q 'tip epoch [2-9]' "$VR_EVIDENCE/seed2-import.log" || { vrs_log "FAIL: the entry stores did not reach epoch 2"; return 1; }
  vrs_log "PASS: a seed with trust-base tip epoch >= 2 and a root epoch >= 2 checkpoint was fetched from two sources, verified from the pinned genesis and imported (entry stores at epoch >= 2)"
  # a history cut back to the pre-Boundary tip (the epoch-1 entry only) under the epoch-2 checkpoint: refused. The manifest is re-written consistently, so
  # only the "checkpoint newer than its history" check can refuse it. The epoch-1 history is what a fresh entry store (genesis only) exports.
  build/ubft trust-base utb-export --utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id "$pin" --utb-entries-db "$d/genesis-only.db" --out "$d/epoch1-bundle.cbor" \
    >"$VR_EVIDENCE/seed2-epoch1-export.log" 2>&1 || { vrs_log "FAIL: the epoch-1 history export"; return 1; }
  build/ubft trust-base utb-verify --bundle "$d/epoch1-bundle.cbor" --utb-genesis-id "$pin" >"$d/epoch1-verify.txt" 2>&1 || { vrs_log "FAIL: the epoch-1 history does not verify"; return 1; }
  rm -rf "$d/cut"; cp -r "$vrs_dir/export2" "$d/cut"; cp "$d/epoch1-bundle.cbor" "$d/cut/utb-bundle.cbor"
  python3 - "$d/cut" "$d/epoch1-verify.txt" <<'PY'
import json,sys,hashlib,re
d,v=sys.argv[1:3]; m=json.load(open(d+'/manifest.json'))
for f in m['files']:
    b=open(d+'/'+f['name'],'rb').read(); f['size']=len(b); f['sha256']=hashlib.sha256(b).hexdigest()
m['network']['utbTipEpoch']=1; m['network']['utbTipId']=re.search(r'tip (0x[0-9a-f]+)',open(v).read()).group(1)
open(d+'/manifest.json','w').write(json.dumps(m,indent=2)+'\n')
PY
  vrs_serve "$d/cut" "$vrs_port_c" || return 1
  vrs_refused history-older-than-checkpoint-epoch "history ends at epoch" build/ubft seed fetch --from "http://127.0.0.1:$vrs_port_c" --out "$d/out" --utb-genesis-id "$pin" || return 1
  vrs_restore_epoch2 || return 1
  vrs_cleanup
}

# The epoch-2 restore end to end (astra, #1227): an incumbent shard node (validator 4, a member of epoch 2) is restored from the seed's epoch-2 checkpoint.
# First a REJECTED seed (a flipped checkpoint byte): the preflight refuses it and the running validator is untouched (same process, journal unchanged).
# Then the good seed: the BodyID comes from the authenticated activation history (the genesis trust base and the epoch-2 activation bundle), the restore
# runs, and the restored shard node answers and its execution client follows the head.
vrs_restore_epoch2() {
  local v=4 d=$vrs_dir/second good=$vrs_dir/second/fetched bad=$vrs_dir/second/bad e b i pid0 j0 j1 jf
  e=$(python3 -c "import json;print(json.load(open('$good/manifest.json'))['checkpoint']['rootEpoch'])")
  [ "$e" -ge 2 ] || { vrs_log "FAIL: the seed's checkpoint is of root epoch $e"; return 1; }
  rm -rf "$bad"; cp -r "$good" "$bad"
  python3 - "$bad/tip-uc.cbor" <<'PY'
import sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[len(b)//2]^=1; open(p,'wb').write(b)
PY
  # the activation bundles of epochs 2..e, from a root (untrusted bytes: the preflight verifies them from the genesis trust base)
  local bundles=
  for i in $(seq 2 "$e"); do
    build/ubft q3 proof-envelope --root-rpc "$(vrb_rpc_of 1)" --epoch "$i" --out "$d/bundle-$i.cbor" >/dev/null 2>&1 || { vrs_log "FAIL: the activation bundle of epoch $i"; return 1; }
    bundles+="$d/bundle-$i.cbor "
  done
  declare -F h3_restore_validator >/dev/null || source scripts/lib/h3-lib.sh
  declare -F reth_trust >/dev/null || source scripts/lib/reth-peers.sh
  export H3_ARCHIVES=$EVM_ARCHIVE_ROOT H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json H3_ONLINE="1 2 3 4" EVM_ARCHIVE_REPLICA_POOL="1 2 3 4"
  export H3_RESTORE_SEED_BUNDLES="$bundles"
  pid0=$(cat "test-nodes/evm$v/pid"); j0=$(stat -c '%Y %s' "test-nodes/evm$v/execution-journal.db" 2>/dev/null || stat -c '%Y %s' "$EVM_EXECUTION_JOURNAL_ROOT/evm$v.db" 2>/dev/null || echo none)
  if H3_RESTORE_SEED_DIR=$bad h3_restore_validator "$v" 1 >"$VR_EVIDENCE/seed2-restore-rejected.log" 2>&1; then vrs_log "FAIL: the tampered seed was accepted by the restore"; return 1; fi
  grep -q "nothing of the validator was touched" "$VR_EVIDENCE/seed2-restore-rejected.log" || { vrs_log "FAIL: the rejection did not come from the preflight"; cat "$VR_EVIDENCE/seed2-restore-rejected.log"; return 1; }
  [ "$(cat "test-nodes/evm$v/pid")" = "$pid0" ] && kill -0 "$pid0" 2>/dev/null || { vrs_log "FAIL: validator $v was stopped by a rejected seed"; return 1; }
  j1=$(stat -c '%Y %s' "test-nodes/evm$v/execution-journal.db" 2>/dev/null || stat -c '%Y %s' "$EVM_EXECUTION_JOURNAL_ROOT/evm$v.db" 2>/dev/null || echo none)
  [ "$j0" = "$j1" ] || { vrs_log "FAIL: validator $v's journal changed under a rejected seed ($j0 -> $j1)"; return 1; }
  [ -d "$H3_ARCHIVES/evm$v" ] && kill -0 "$(cat "test-nodes/reth$v/pid")" 2>/dev/null || { vrs_log "FAIL: validator $v's archive or execution client was touched by a rejected seed"; return 1; }
  vrs_log "PASS: a rejected seed left validator $v untouched (the preflight refused it before anything was stopped; same pid $pid0, archive and execution client present)"
  # a VALID seed for another shard: the target's shard configuration names another partition than the seed's checkpoint, so the preflight must refuse it
  # (a seed for another shard cannot be signed here; the target's configuration is the one that differs) and leave the validator untouched
  python3 - "$EVM_FULL_SHARD_CONF" "$d/other-shard-conf.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1])); c['partitionId']=c['partitionId']+1; json.dump(c,open(sys.argv[2],'w'))
PY
  if EVM_FULL_SHARD_CONF=$d/other-shard-conf.json H3_RESTORE_SEED_DIR=$good h3_restore_validator "$v" 1 >"$VR_EVIDENCE/seed2-restore-other-shard.log" 2>&1; then vrs_log "FAIL: a seed for another shard was accepted by the restore"; return 1; fi
  grep -qE "another shard|this node.s (is|shard)" "$VR_EVIDENCE/seed2-restore-other-shard.log" && grep -q "nothing of the validator was touched" "$VR_EVIDENCE/seed2-restore-other-shard.log" || { vrs_log "FAIL: the other-shard refusal did not come from the preflight"; cat "$VR_EVIDENCE/seed2-restore-other-shard.log"; return 1; }
  [ "$(cat "test-nodes/evm$v/pid")" = "$pid0" ] && kill -0 "$pid0" 2>/dev/null && [ -d "$H3_ARCHIVES/evm$v" ] && kill -0 "$(cat "test-nodes/reth$v/pid")" 2>/dev/null \
    || { vrs_log "FAIL: validator $v was touched by a seed for another shard"; return 1; }
  vrs_log "PASS: a valid seed for another shard was refused by the preflight and validator $v is untouched (same pid $pid0)"
  # the epoch-2 restore itself
  export "EVM_ENGINE_URL_$v=http://127.0.0.1:$((rethEngineBase + v - 1))" "EVM_ETH_URL_$v=http://127.0.0.1:$((rethEthBase + v - 1))"
  H3_RESTORE_SEED_DIR=$good h3_restore_validator "$v" 1 || { vrs_log "FAIL: the epoch-$e restore from the seed"; return 1; }
  cp "test-nodes/evm$v/pin.txt" "$VR_EVIDENCE/seed2-restore-pin.txt" 2>/dev/null
  vrb_wait 600 "the restored validator $v's shard node answers" curl -fsS -m 5 -X POST -H 'content-type: application/json' -d '{}' "http://$(evm_validator_rpc_addr "$v")/api/v1/q3/status" || return 1
  vrb_wait 600 "the restored validator $v's execution client follows the head" vrs_reth_follows "$v" || return 1
  vrs_log "PASS: validator $v was restored from the epoch-$e seed (the BodyID resolved from the authenticated activation history: $(cat "test-nodes/evm$v/pin.txt"))"
}
vrs_eth_number() { curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$1" | python3 -c "import json,sys;print(int(json.load(sys.stdin)['result'],16))"; }
vrs_reth_follows() { local a b; a=$(vrs_eth_number $((rethEthBase + $1 - 1))) || return 1; b=$(vrs_eth_number "$rethEthBase") || return 1; vrb_log "reth$1 $a, reth1 $b"; [ "$a" -gt 0 ] && [ $((b - a)) -le 3 ]; }
