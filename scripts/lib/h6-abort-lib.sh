#!/usr/bin/env bash
# The H6 Abort rehearsal's functions (owner decisions section 16: emergency procedures exercised, not only written). Definitions only: sourcing starts
# nothing, reads nothing and creates nothing; scripts/h6/abort-rehearsal-lane.sh --selftest proves it. Needs the paired-devnet context of
# scripts/reth-paired-devnet.sh (rpc, pyget, rethEthBase, ...) and sources scripts/lib/m2-handoff-lib.sh itself when the steps run.
#
# One chain, two handoffs of the Q3 flow (same members, unit weights, no EVM assignment change):
#   epoch 1 -> 2: Abort BEFORE H. One old root endorses (prepare-handoff.py), the documented `root handoff abort` commits the Abort, the EVM unfreezes (a paid
#                 transaction certifies in root epoch 1), then attempt+1 of the same handoff commits and installs (a paid transaction certifies in epoch 2).
#   epoch 2 -> 3: Abort AFTER H. Every old root endorses, H commits (the helper sees `too_late`), the same `root handoff abort` is refused with "too late",
#                 and the handoff still installs (a paid transaction certifies in epoch 3).

H6_PY=${H6_PY:-python3}

# the evidence directory of one rehearsed attempt: $Q3_DIR/h6-<name>
h6_dir() { echo "$Q3_DIR/h6-$1"; }

# the receipts of the staged candidate, comma-separated, for the entities of the handoff in hand
h6_receipt_files() { # suffix
  local i out=
  for i in ${Q3_ENTITIES:-1 2 3 4}; do out+="${out:+,}$Q3_DIR/receipt$1-$i.json"; done
  echo "$out"
}

# The same preamble as the M2 lane: the seeded transactions are certified in root epoch 1 and the next nonce is the chain's.
h6_preamble() {
  local initialHash initialReady i initialReceipt initialBlock fundedNonce
  cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
  for initialHash in $(printf '%b' "$txHashes"); do
    initialReady=false
    for i in $(seq 1 90); do
      initialReceipt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$initialHash\"]")
      initialBlock=$(echo "$initialReceipt" | pyget "['result']['blockHash']")
      if [ "$(echo "$initialReceipt" | pyget "['result']['status']")" = 0x1 ] && [ -n "$initialBlock" ] && [ "$initialBlock" != None ] &&
         grep -Eq "msg=\"certificate admitted\" block=${initialBlock#0x} .*rootEpoch=1([[:space:]]|$)" test-nodes/evm1/debug.log; then
        initialReady=true; break
      fi
      sleep 2
    done
    $initialReady || return 1
  done
  fundedNonce=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionCount "[\"$(go run ./scripts/evmtx -address)\",\"pending\"]" | pyget "['result']") || fundedNonce=
  case "$fundedNonce" in 0x*) M2_NEXT_NONCE=${M2_NEXT_NONCE:-$((fundedNonce))} ;; *) M2_NEXT_NONCE=${M2_NEXT_NONCE:-3} ;; esac
}

# The candidate and one readiness receipt per successor entity for the CURRENT attempt of the handoff to <epoch> (what q3_attempt does before it proposes).
h6_stage_candidate() { # epoch suffix
  Q3_NEXT_EPOCH=$1 Q3_SUFFIX=$2 Q3_NO_ASSIGNMENT=1 q3_derive_candidate || return 1
  Q3_NEXT_EPOCH=$1 Q3_SUFFIX=$2 Q3_NO_ASSIGNMENT=1 q3_receipts || return 1
}

# The rehearsal helper against the live roots: one endorsement (the default) or all of them (endorse-all). Leaves $dir/target.json and status.json.
h6_plan() { # epoch suffix name [--endorse-all]
  local epoch=$1 suffix=$2 name=$3 dir; shift 3
  dir=$(h6_dir "$name"); rm -rf "$dir"
  "$H6_PY" scripts/h6/prepare-handoff.py \
    --old-trust-base "test-nodes/trust-base-epoch$((epoch - 1)).json" --next-trust-base "test-nodes/trust-base-epoch$epoch.json" \
    --receipts "$(h6_receipt_files "$suffix")" --v3-body-id "$Q3_DIR/v3-body-id$suffix.txt" \
    --root-rpc "$(h3_root_rpcs)" --out "$dir" "$@" | tee "$Q3_DIR/h6-$name.log"
  [ "${PIPESTATUS[0]}" = 0 ]
}

# The documented Abort (docs/operations/root-handoff-abort.md) for the exact target the helper saved. Its output and exit status are the evidence.
h6_abort() { # name: leaves h6-<name>/abort.out and abort.status; returns the CLI's exit status
  local dir; dir=$(h6_dir "$1")
  local network oldEpoch predecessor attempt next
  network=$(jq -r .network "$dir/target.json"); oldEpoch=$(jq -r .oldEpoch "$dir/target.json")
  predecessor=$(jq -r .predecessorBodyId "$dir/target.json"); attempt=$(jq -r .attempt "$dir/target.json"); next=$(jq -r .nextBodyId "$dir/target.json")
  h6_x build/ubft root handoff abort --network "$network" --old-epoch "$oldEpoch" --predecessor-body-id "$predecessor" --attempt "$attempt" \
    --next-body-id "$next" --root-rpc "$(h3_root_rpcs)" --timeout 2m >"$dir/abort.out" 2>&1
  local status=$?
  echo "$status" >"$dir/abort.status"
  cat "$dir/abort.out"
  return "$status"
}
h6_x() { printf '%s\n' "$*" >>"$Q3_DIR/commands.log"; "$@"; }

# the roots' own record of the Abort (the phase and the round), as extra evidence next to the CLI's committed record
h6_abort_logged() { # name
  grep -h "root handoff abort ordered" test-nodes/root*/debug.log | sort -u >"$(h6_dir "$1")/roots-abort-ordered.log"
  [ -s "$(h6_dir "$1")/roots-abort-ordered.log" ]
}

# ---- Abort BEFORE H, then attempt+1 ----------------------------------------------------------------------------------------------------------
h6_abort_before_h() { # epoch (the successor epoch; the old epoch is epoch-1)
  local epoch=$1 old=$(($1 - 1)) roots='1 2 3 4' suffix=-h6e$1 dir
  m2_b1_prepare "$roots" || return 1
  Q3_NEXT_EPOCH=$epoch Q3_SUFFIX=$suffix Q3_NO_ASSIGNMENT=1 q3_trust_base_v3 "$epoch" || return 1
  h6_stage_candidate "$epoch" "$suffix" || { echo "no candidate or receipts for the first attempt" >&2; return 1; }
  h6_plan "$epoch" "$suffix" "before-h" || { echo "the rehearsal helper did not leave an interrupted, pending handoff" >&2; return 1; }
  dir=$(h6_dir before-h)
  [ "$(jq -r .state "$dir/status.json")" = pending ] || return 1
  h6_abort before-h || { echo "the documented Abort did not commit" >&2; return 1; }
  grep -q '^committed Abort record ' "$dir/abort.out" || { echo "no committed Abort record in the CLI output" >&2; return 1; }
  h6_abort_logged before-h || { echo "the roots did not log the ordered Abort" >&2; return 1; }
  echo "PASS: Abort before H committed: $(grep '^committed Abort record ' "$dir/abort.out")"
  # the EVM is unfrozen: a paid transaction certifies in the OLD epoch, because no handoff happened
  m2_send_paid "$old" "${M2_NEXT_NONCE:-3}" || { echo "no paid certified transaction after the Abort: the EVM did not unfreeze" >&2; return 1; }
  echo "PASS: a paid transaction certified in root epoch $old after the Abort (the EVM unfroze)"
  # attempt+1 of the same handoff: a fresh candidate and receipts, proposed normally
  Q3_NEXT_EPOCH=$epoch Q3_SUFFIX=$suffix Q3_NO_ASSIGNMENT=1 h3_retry_handoff "$old" q3_attempt || { echo "attempt+1 after the Abort did not commit" >&2; return 1; }
  m2_install_epoch "$epoch" "$roots" || return 1
  echo "PASS: attempt+1 after the Abort committed and installed; a paid transaction certified in root epoch $epoch"
}

# ---- Abort AFTER H ---------------------------------------------------------------------------------------------------------------------------
h6_abort_after_h() { # epoch
  local epoch=$1 old=$(($1 - 1)) roots='1 2 3 4' suffix=-h6e$1 dir
  m2_b1_prepare "$roots" || return 1
  Q3_NEXT_EPOCH=$epoch Q3_SUFFIX=$suffix Q3_NO_ASSIGNMENT=1 q3_trust_base_v3 "$epoch" || return 1
  h6_stage_candidate "$epoch" "$suffix" || return 1
  h3_loop_mark
  h6_plan "$epoch" "$suffix" "after-h" --endorse-all || { echo "the rehearsal helper did not take the handoff past H" >&2; return 1; }
  dir=$(h6_dir after-h)
  [ "$(jq -r .state "$dir/status.json")" = too_late ] || return 1
  h3_wait_committed "$old" || { echo "H did not commit in the old epoch" >&2; return 1; }
  if h6_abort after-h; then echo "the Abort of a committed handoff was not refused" >&2; return 1; fi
  grep -q '^too late: matching handoff H is committed' "$dir/abort.out" || { echo "the refusal is not the documented 'too late'" >&2; return 1; }
  echo "PASS: Abort after H refused: $(grep '^too late' "$dir/abort.out")"
  m2_install_epoch "$epoch" "$roots" || { echo "the handoff did not install after the refused Abort" >&2; return 1; }
  echo "PASS: the handoff still installed after the refused Abort; a paid transaction certified in root epoch $epoch"
}
