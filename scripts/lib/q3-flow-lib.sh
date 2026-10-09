# The Q3-flow handoff library (the one handoff flow of the fresh-B1 layout): trust base, candidate, readiness receipts, propose, the root install barrier and
# the committed activation record. Sourced by the Q3 weight-activation steps and by the lanes ported to the B1 layout (M2, F8 ...). Definitions only.
#
# Caller state: Q3_DIR (evidence), H3_ROOTS, Q3_WEIGHTS (the mirrored weights, one per entity in entity order), Q3_TOTAL_WEIGHT / Q3_ROOT_QUORUM /
# Q3_EVM_QUORUM (the arithmetic of those weights; q3-lib.sh holds the 6,1,1,1 values). Per handoff: Q3_NEXT_EPOCH, Q3_ASSIGN_TAG, Q3_SUFFIX, Q3_INCUMBENT.
# Q3_ENTITIES (default "1 2 3 4") are the successor entities; Q3_NO_ASSIGNMENT=1 is a handoff that leaves the EVM assignment alone (same entities, no EVM
# change): no assignment is built or named, only the root committee and its weights change hands.

q3_x() { printf '%s\n' "$*" >>"$Q3_DIR/commands.log"; "$@"; }          # every lane command is recorded, then run
# The candidate root trust base: same members and keys, the mirrored weights (--root-weights follows the --node-info order; the V3 protocol tuple is
# the root's own configured one, carried by the V3 body, not by the trust base).
q3_trust_base_v3() { # epoch
  local epoch=$1 i infos=() w=${Q3_WEIGHTS// /,}
  for i in $H3_ROOTS; do infos+=(--node-info "test-nodes/root$i/node-info.json"); done
  q3_x build/ubft trust-base generate --home test-nodes --network-id 3 --epoch "$epoch" --epoch-start "$((epoch * 100000))" \
    --previous-trust-base "test-nodes/trust-base-epoch$((epoch-1)).json" --root-weights "$w" \
    --output-file-name "trust-base-epoch${epoch}.json" "${infos[@]}" >/dev/null || return 1
  for i in $H3_ROOTS; do build/ubft trust-base sign --home "test-nodes/root$i" --trust-base "test-nodes/trust-base-epoch${epoch}.json" >/dev/null || return 1; done
}

# The operator's own pins for the readiness check: never read from the execution client under test. The registry code comes from the chain spec the
# clients were started with; the genesis block hash is the one entity 1's client reported at the start of the lane (recorded in pins.txt).
q3_execution_pins() {
  Q3_EXEC_GENESIS=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["0x0",false]' | pyget "['result']['hash']") || return 1
  Q3_EXEC_CODE_HASH=$(python3 - "$chainSpec" "$H3_REGISTRY" <<'PY'
import hashlib, json, sys
alloc = json.load(open(sys.argv[1]))["alloc"]
want = sys.argv[2].lower().removeprefix("0x")
for k, v in alloc.items():
    if k.lower().removeprefix("0x") == want:
        print(hashlib.sha256(bytes.fromhex(v["code"].removeprefix("0x"))).hexdigest()); break
else:
    sys.exit("registry not in the chain spec")
PY
  ) || return 1
  printf 'execution genesis hash: %s\nregistry code sha256: %s\n' "$Q3_EXEC_GENESIS" "$Q3_EXEC_CODE_HASH" >>"$Q3_DIR/pins.txt"
}

# ---- the root's verified Q3 endpoints (local operator API) --------------------------------------------------------------------------------------
q3_signers_of() { curl -fsS -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url "$1")/api/v1/q3/signers"; }   # {epoch,round,scheme,signers,signedTotal,threshold,quorum}

q3_weight_of() { echo "$Q3_WEIGHTS" | awk -v n="$1" '{print $n}'; }

# ---- readiness: one receipt per entity, from its root key, after checking its BFT node, its shard service and its paired Ureth --------------------
q3_readiness() { # entity out: a receipt for the staged candidate, or the typed refusal on stderr
  local i=$1 out=$2
  q3_x build/ubft root handoff q3-readiness --candidate "$Q3_DIR/candidate${Q3_SUFFIX:-}.cbor" --key-conf "test-nodes/root$i/keys.json" \
    --root-rpc "$(h3_rpc_url "$i")" --shard-rpc "http://$(evm_validator_rpc_addr "$i")" --eth-url "http://127.0.0.1:$((rethEthBase + i - 1))" \
    --engine-url "http://127.0.0.1:$((rethEngineBase + i - 1))" --jwt-secret "test-nodes/evm$i/jwt.hex" \
    --execution-genesis-hash "$Q3_EXEC_GENESIS" --execution-code-hash "$Q3_EXEC_CODE_HASH" --out "$out"
}

q3_engine_url() { echo "http://127.0.0.1:$((rethEngineBase + $1 - 1))"; }

q3_eth_url() { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }

q3_derive_candidate() { # the root's derivation of the V3 candidate for the current attempt (Q3_NEXT_EPOCH, Q3_ASSIGN_TAG, Q3_SUFFIX name the handoff; the first by default)
  local e=${Q3_NEXT_EPOCH:-2} tag=${Q3_ASSIGN_TAG:-cand} suf=${Q3_SUFFIX:-}
  local -a assign=(); [ -n "${Q3_NO_ASSIGNMENT:-}" ] || assign=(--next-evm-assignment "$Q3_DIR/$tag-assignment.json")
  rm -rf "$Q3_DIR/candidate${suf}.d"
  q3_x build/ubft root handoff q3-candidate --next-trust-base "test-nodes/trust-base-epoch${e}.json" \
    ${assign[@]+"${assign[@]}"} --root-rpc "$(h3_root_rpcs)" --out-dir "$Q3_DIR/candidate${suf}.d" || return 1
  cp "$Q3_DIR/candidate${suf}.d/candidate.cbor" "$Q3_DIR/candidate${suf}.cbor"
  cp "$Q3_DIR/candidate${suf}.d/config.json" "$Q3_DIR/candidate-config${suf}.json"
  cp "$Q3_DIR/candidate${suf}.d/v3-body-id.txt" "$Q3_DIR/v3-body-id${suf}.txt"
  cp "$Q3_DIR/candidate${suf}.d/root-weights.json" "$Q3_DIR/root-weights${suf}.json"
  cp "$Q3_DIR/candidate${suf}.d/evm-weights.json" "$Q3_DIR/evm-weights${suf}.json"
}

q3_receipts() { # exactly one receipt per successor entity, from its root key
  local i suf=${Q3_SUFFIX:-} n=0
  for i in ${Q3_ENTITIES:-1 2 3 4}; do
    # a lane hook runs before an entity's turn (H3: a joiner that is behind restores from the archive once the incumbents before it have staged)
    [ -z "${Q3_BEFORE_READINESS:-}" ] || "$Q3_BEFORE_READINESS" "$i" || return 1
    q3_readiness "$i" "$Q3_DIR/receipt${suf}-$i.json" || return 1; n=$((n + 1))
  done
  [ "$(ls "$Q3_DIR"/receipt${suf}-*.json | wc -l | tr -d ' ')" = "$n" ]
}

q3_attempt() { # a retry rebuilds the proofs of possession, the candidate and the receipts for the new attempt number
  local e=${Q3_NEXT_EPOCH:-2} tag=${Q3_ASSIGN_TAG:-cand} suf=${Q3_SUFFIX:-} i receipts=
  local -a assign=()
  if [ -z "${Q3_NO_ASSIGNMENT:-}" ]; then
    q3_build_assignment "$tag" ${Q3_ENTITIES:-1 2 3 4} || return 1
    assign=(--next-evm-assignment "$Q3_DIR/$tag-assignment.json")
  fi
  q3_derive_candidate || return 1
  # an exact recovery (Q3_RECOVERY=1) carries no receipts (the product refuses a recovery that has them) and asks for the V3 plan with --q3
  if [ -z "${Q3_RECOVERY:-}" ]; then
    q3_receipts || return 1
    for i in ${Q3_ENTITIES:-1 2 3 4}; do receipts+="${receipts:+,}$Q3_DIR/receipt${suf}-$i.json"; done
    assign+=(--readiness-receipts "$receipts")
  fi
  # a lane hook sees the complete plan inputs (the receipts exist) before the real proposal: the P85 proof controls mutate it here
  [ -z "${Q3_BEFORE_PROPOSE:-}" ] || "$Q3_BEFORE_PROPOSE" "$tag" "$receipts" || return 1
  q3_x build/ubft root handoff propose --next-trust-base "test-nodes/trust-base-epoch${e}.json" ${assign[@]+"${assign[@]}"} \
    --root-rpc "$(h3_root_rpcs)" ${Q3_RECOVERY:+--q3}
}

q3_history_ids() { # out: the verified history identities retained by the first root
  q3_x build/ubft q3 history --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$1" && [ -s "$1" ]
}

q3_handoff_n() { # n epoch weights supersede(0|1) incumbent: plans, endorses and commits the handoff at old epoch (epoch-1)
  local n=$1 epoch=$2
  Q3_WEIGHTS=$3 Q3_SUFFIX=-$n Q3_NEXT_EPOCH=$epoch Q3_ASSIGN_TAG=cand$n Q3_INCUMBENT=$5
  if [ "$4" = 1 ]; then Q3_SUPERSEDE=1; else unset Q3_SUPERSEDE; fi
  q3_trust_base_v3 "$epoch" || return 1
  h3_retry_handoff $((epoch - 1)) q3_attempt || return 1
  [ "$(jq -r .signingScheme "$Q3_DIR/candidate-config-$n.json")" = 2 ] || { echo "handoff $n does not select scheme 2" >&2; return 1; }
  q3_check_weights set "$Q3_DIR/root-weights-$n.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM" >/dev/null || return 1
  q3_check_weights set-evm "$Q3_DIR/evm-weights-$n.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM" >/dev/null || return 1
  Q3_WEIGHTS=$Q3_WEIGHTS_1; unset Q3_SUFFIX Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_INCUMBENT Q3_SUPERSEDE
  echo "handoff $n committed at root epoch $((epoch - 1))"
}

q3_install_n() { # epoch: the installation barrier of epoch N; no certificate of N may exist before the roots restart into it
  local epoch=$1 prev=$(($1 - 1)) r before
  for r in $H3_ROOTS; do
    before=$(q3_signers_of "$r" | jq -r .epoch) || return 1
    [ "$before" = "$prev" ] || { echo "root $r reports a certificate of epoch $before before its install restart into $epoch" >&2; return 1; }
  done
  h3_restart_roots "$epoch" || { echo "root restart into epoch $epoch failed" >&2; return 1; }
  for r in $(seq 1 120); do
    [ "$(q3_signers_of "$(h3_first_root)" 2>/dev/null | jq -r .epoch 2>/dev/null)" = "$epoch" ] && break
    sleep 1
  done
  q3_signers_of "$(h3_first_root)" | jq -c . >"$Q3_DIR/first-epoch${epoch}-certificate.json"
  [ "$(jq -r .epoch "$Q3_DIR/first-epoch${epoch}-certificate.json")" = "$epoch" ] || { echo "no epoch-$epoch certificate after the install restart" >&2; return 1; }
  q3_history_ids "$Q3_DIR/history-ids-epoch${epoch}.txt"
}

q3_activation_n() { # n epoch: the committed activation record of epoch N; its Commit is the previous (weighted, scheme 2) committee's proof
  local n=$1 epoch=$2 rec="$Q3_DIR/activation-record-$2.json" astar amin first total
  q3_x build/ubft root handoff q3-activation --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --epoch "$epoch" --out "$rec" || return 1
  [ "$(jq -r .epoch "$rec")" = "$epoch" ] || { echo "activation epoch is not $epoch" >&2; return 1; }
  [ "$(jq -r .signingScheme "$rec")" = 2 ] || { echo "activated scheme is not 2" >&2; return 1; }
  [ "$(jq -r .v3BodyId "$rec")" = "$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id-$n.txt")" ] || { echo "activation record names a different V3BodyID than candidate $n" >&2; return 1; }
  astar=$(jq -r .activationRound "$rec"); amin=$(jq -r .minActivationRound "$rec")
  [ "$astar" -ge "$amin" ] || { echo "A*=$astar is below A_min=$amin" >&2; return 1; }
  first=$(jq -r .round "$Q3_DIR/first-epoch${epoch}-certificate.json")
  [ "$first" -ge "$astar" ] || { echo "first epoch-$epoch certificate round $first is below A*=$astar" >&2; return 1; }
  # the Commit is verified under the PREVIOUS epoch: its weighted committee (W=9, Q=7) under scheme 2
  [ "$(jq -r '.commit.scheme' "$rec")" = 2 ] || { echo "the Commit of epoch $epoch is not a scheme-2 proof" >&2; return 1; }
  [ "$(jq -r '.commit.epoch' "$rec")" = "$((epoch - 1))" ] || { echo "the Commit of epoch $epoch is not the previous committee's" >&2; return 1; }
  jq '.commit.signers' "$rec" >"$Q3_DIR/old-commit-signers-$epoch.json"
  total=$(q3_check_weights cert "$Q3_DIR/old-commit-signers-$epoch.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM") || return 1
  printf 'E=%s\nA_min=%s\nA*=%s\nactivationCommitId=%s\nv3BodyId=%s\nfirst epoch-%s certificate round=%s\nCommit signed by weight %s of %s (quorum %s) under scheme 2\n' \
    "$epoch" "$amin" "$astar" "$(jq -r .activationCommitId "$rec")" "$(jq -r .v3BodyId "$rec")" "$epoch" "$first" "$total" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM" >"$Q3_DIR/activation-coordinates-$epoch.txt"
}
