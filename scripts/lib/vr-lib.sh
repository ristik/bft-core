#!/usr/bin/env bash
# The validator-registry (VR) generation lane's helpers (VT-14, ristik/bft-core#1158). Sourced by the paired devnet script under VR_LANE=1
# (with Q3_B1=1 and M2_PROFILE2=1): the same genesis plan as deploy/testnet/vr_genesis.py, on the devnet's topology, so a VR generation's roots,
# shard nodes and ureth start from the plan's outputs, verified by `ubft vr-genesis verify` before anything runs.
#
#   vr_lane_conf            the EVM shard configuration pins VR (validator_registry, validator_registry_code_hash) from the measurement
#   vr_profile_args         the b1-profile flags of a VR generation (both hooks on VR, priced from the measurement)
#   vr_utb_args             the vr-genesis flags of the UTB genesis entry (VR_UTB=1)
#   vr_prepare_genesis      dev keys -> vr-genesis plan -> contracts genesis (test-nodes/vr/*)
#   vr_merge_alloc <src>    adds the VR accounts and the dev premine to a genesis source's alloc
#   vr_verify <genesis> <full-conf>   vr-genesis verify of the finished set; writes the roots' --vr-deployment
#   vr_root_flags <i> <rpc> the flags a root of the lane runs with
#   vr_readback <rpc>       VR's views through ureth: the genesis committee, the PoA module, GENESIS_RESULT, Healthy
#
# VR_POS=1 (VT-04): the PoS-prototype generation. The module is the PosElectionAdapter and the P85 stack (custody = liability holder 0) is in the
# genesis; the plan carries a `pos` object whose genesis assignment id is the FULL shard configuration's, so the contracts genesis is built after a
# reconciling genesis pass (vr_pos_reconcile, called by reth-paired-devnet.sh before the alloc merge). VR_MEASUREMENT and VR_FRESH_MEASUREMENT must
# be the PoS-capable build's complete-path measurements (hook-pin ticket #1217).
#
# Inputs (environment):
#   VR_CONTRACTS            a PRIVATE unicity-pos-contracts checkout with script/vr-genesis.sh (forge and cast on PATH): forge writes into it
#                           (script/genesis-out/, out/, cache/), so never point it at a checkout another lane or a staging network uses
#   VR_MEASUREMENT          the recorded complete-path measurement the profile is pinned from (default deploy/testnet/vr-hook-measurement.json)
#   VR_FRESH_MEASUREMENT    a fresh complete-path measurement (ureth tests/vr_hook.rs vr_hook_measurement) taken for this run; required
#   VR_FORGE_HOME           optional HOME for forge (a host whose solc cache lives elsewhere)
#   VR_GENERATION           the development generation's name (default paired-devnet): its network word is sha256("unicity.dev.vr." + name)
#
# The premine is dev-only: each identity owner and governor signer gets a generated key (test-nodes/vr/dev-keys/keys.json, 0600, created with
# O_EXCL by deploy/testnet/vr_dev_keys.py, the generator vr_genesis.py --dev-fund shares; never copy dev-keys/ into evidence) and 1000 UCT, so the
# lane can send an owner's proposeBinding or a multisig execute; the devnet's own test sender stays funded. verify checks every one of them as
# an expected premine of a dev generation.

VR_DIR=${VR_DIR:-test-nodes/vr}
case "$VR_DIR" in /* | *..*) echo "vr: VR_DIR must be a relative path inside the checkout, got $VR_DIR" >&2; return 2 2>/dev/null || exit 2 ;; esac
# the fee collector exactly as the lane hands it to the shard nodes (reth-paired-devnet.sh EVM_ENGINE_FEE_COLLECTOR) and to ureth
vr_fee_collector() { echo "${POST_M2A_FEE_COLLECTOR:-$URETH_PIN_FEE_COLLECTOR}"; }
VR_MEASUREMENT=${VR_MEASUREMENT:-deploy/testnet/vr-hook-measurement.json}
VR_GENERATION=${VR_GENERATION:-paired-devnet}
VR_DEV_FUND_WEI=0x3635c9adc5dea00000   # 1000 UCT

vr_die() { echo "vr: $*" >&2; return 1; }

vr_check_inputs() {
  [ -n "${VR_CONTRACTS:-}" ] && [ -x "$VR_CONTRACTS/script/vr-genesis.sh" ] || vr_die "VR_CONTRACTS must name a unicity-pos-contracts checkout with script/vr-genesis.sh" || return 1
  [ -s "$VR_MEASUREMENT" ] || vr_die "no recorded measurement at $VR_MEASUREMENT" || return 1
  [ -s "${VR_FRESH_MEASUREMENT:-}" ] || vr_die "VR_FRESH_MEASUREMENT must name a fresh complete-path measurement (ureth vr_hook_measurement)" || return 1
  [ "$(realpath "$VR_FRESH_MEASUREMENT")" != "$(realpath "$VR_MEASUREMENT")" ] || vr_die "the fresh measurement is the recorded file" || return 1
  command -v cast >/dev/null && command -v forge >/dev/null || vr_die "forge and cast must be on PATH" || return 1
}

vr_lane_conf() { # pins VR in the base EVM shard configuration (before the profile and the genesis are derived from it)
  vr_check_inputs || return 1
  mkdir -p "$VR_DIR"
  python3 - "test-nodes/shard-conf-${partitionID:-8}_0.json" "$VR_MEASUREMENT" <<'PY' || return 1
import json, sys
conf, m = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
p = conf["partitionParams"]
if "validator_registry" in p or "validator_registry_code_hash" in p:
    sys.exit("the shard configuration already pins a VR")
p["validator_registry"], p["validator_registry_code_hash"] = m["registry"], m["registryCodeHash"]
p.setdefault("continuity_max_distance", "1/2")
json.dump(conf, open(sys.argv[1], "w"), indent=2)
PY
  echo "vr: the EVM shard configuration pins VR $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["registryCodeHash"])' "$VR_MEASUREMENT")"
}

# VR_UTB=1 (the default, reth-paired-devnet.sh): plan emits the UTB genesis entry and its pin where the roots, shard nodes and aggregator read them
# (test-nodes/utb-genesis.cbor, utb-genesis.id: the files scripts/lib/utb-lib.sh uses), and verify checks them against the epoch-1 trust base.
vr_utb_args() { [ "${VR_UTB:-0}" != 1 ] || echo --utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id test-nodes/utb-genesis.id; }

vr_profile_args() { echo --vr-hook-measurement "$VR_MEASUREMENT"; }

vr_network_word() { printf '0x%s\n' "$(printf 'unicity.dev.vr.%s' "$VR_GENERATION" | shasum -a 256 | cut -d' ' -f1)"; }

vr_prepare_genesis() { # after the profile: dev keys, the plan, the contracts genesis
  local i n=${validators:-4} items=() keys
  mkdir -p "$VR_DIR"
  for i in $(seq 1 "$n"); do
    local rid eid
    rid=$(build/ubft node-id --home "test-nodes/root$i" | tail -n1) && [ -n "$rid" ] || vr_die "no node id for test-nodes/root$i" || return 1
    eid=$(build/ubft node-id --home "test-nodes/evm$i" | tail -n1) && [ -n "$eid" ] || vr_die "no node id for test-nodes/evm$i" || return 1
    items+=("{\"rootNodeId\":\"$rid\",\"evmNodeId\":\"$eid\"}")
  done
  printf '[%s]\n' "$(IFS=,; echo "${items[*]}")" >"$VR_DIR/genesis-bindings.json"
  [ -s "$VR_DIR/dev-keys/keys.json" ] || python3 deploy/testnet/vr_dev_keys.py "$VR_DIR/dev-keys" "$n" || vr_die "generating the dev keys failed" || return 1
  vr_plan 0x1111111111111111111111111111111111111111111111111111111111111111 || return 1
  # a PoS generation builds its contracts genesis after the reconciling pass (the genesis assignment id comes from the full configuration)
  [ "${VR_POS:-0}" = 1 ] && return 0
  vr_contracts_genesis || return 1
}

vr_plan() { # <genesis assignment id: only a PoS plan carries it>
  local pos=()
  if [ "${VR_POS:-0}" = 1 ]; then
    local g; g=$(build/ubft trust-base utb-manifest --trust-base test-nodes/trust-base.json --out-dir "$VR_DIR/root-identity" | sed -n 's/^root genesis id *\(0x[0-9a-f]\{64\}\)$/\1/p')
    [ -n "$g" ] || vr_die "the manifest tool printed no root genesis id" || return 1
    pos=(--pos --limits "${VR_POS_LIMITS:-4,5,5}" --pos-bond-unit 100000000000000000000 --pos-treasury 0x00000000000000000000000000000000000000ee
         --pos-root-genesis "$g" --pos-assignment-id "$1" --pos-cadence-rounds "${VR_POS_CADENCE_ROUNDS:-400}" --pos-cadence-seconds "${VR_POS_CADENCE_SECONDS:-300}")
  fi
  build/ubft vr-genesis plan --trust-base test-nodes/trust-base.json --shard-conf "test-nodes/shard-conf-${partitionID:-8}_0.json" \
    --bindings "$VR_DIR/genesis-bindings.json" --owners "$VR_DIR/dev-keys/owners.json" --b1-profile test-nodes/b1-profile.json \
    --network-word "$(vr_network_word)" --governor-signers "$(tr -d '\n' <"$VR_DIR/dev-keys/signers.txt")" --fee-collector "$(vr_fee_collector)" \
    --out-input "$VR_DIR/input.json" --out-identities "$VR_DIR/genesis-identities.json" "${pos[@]}" $(vr_utb_args) || return 1
}

vr_contracts_genesis() {
  local script=vr-genesis.sh; [ "${VR_POS:-0}" != 1 ] || script=vr-pos-genesis.sh
  ( cd "$VR_CONTRACTS" && HOME=${VR_FORGE_HOME:-$HOME} script/$script "$OLDPWD/$VR_DIR/input.json" "$OLDPWD/$VR_DIR/contracts" ) ||
    vr_die "the contracts genesis failed" || return 1
}

vr_pos_reconcile() { # <funded genesis source, before the alloc merge>: the PoS plan's genesis assignment id from the full configuration
  [ "${VR_POS:-0}" = 1 ] || return 0
  local d=$VR_DIR/reconcile id; mkdir -p "$d"
  build/ubft engine-api genesis --shard-conf "test-nodes/shard-conf-${partitionID:-8}_0.json" --trust-base test-nodes/trust-base.json \
    --b1-profile test-nodes/b1-profile.json --alloc-source "$1" --out "$d/genesis.json" --full-shard-conf "$d/full-shard-conf.json" \
    --identities-out "$d/b1-identities.json" >/dev/null || vr_die "the reconciling genesis failed" || return 1
  id=$(build/ubft vr-genesis assignment --shard-conf "$d/full-shard-conf.json" --genesis-identities "$VR_DIR/genesis-identities.json" | sed -n 's/^genesis assignment id \(0x[0-9a-f]\{64\}\)$/\1/p')
  [ -n "$id" ] || vr_die "vr-genesis assignment printed no id" || return 1
  echo "vr: the PoS genesis assignment id is $id (the full shard configuration's)"
  vr_plan "$id" || return 1
  vr_contracts_genesis || return 1
}

vr_merge_alloc() { # <genesis source>: the VR accounts and the dev premine; every balance-only account of the source is part of the premine list
  python3 - "$1" "$VR_DIR" "$VR_DEV_FUND_WEI" <<'PY' || return 1
import json, sys
src, d, fund = sys.argv[1], sys.argv[2], sys.argv[3]
g = json.load(open(src))
have = {k.lower().removeprefix("0x") for k in g["alloc"]}
premine = {}
for k, v in g["alloc"].items():   # the devnet's own test sender(s): balance only
    if set(v) - {"balance", "nonce"} or int(v.get("nonce", "0x0"), 16):
        sys.exit(f"the genesis source allocates {k} with code, storage or a nonce")
    premine["0x" + k.lower().removeprefix("0x")] = v["balance"]
for k, v in json.load(open(f"{d}/contracts/alloc.json")).items():
    if k.lower().removeprefix("0x") in have:
        sys.exit(f"the genesis source already has {k}")
    g["alloc"][k] = v
keys = json.load(open(f"{d}/dev-keys/keys.json"))
for k in keys["owners"] + keys["signers"]:
    if k["address"].removeprefix("0x") in have:
        sys.exit(f"the genesis source already has {k['address']}")
    g["alloc"][k["address"]] = {"balance": fund}
    premine[k["address"]] = fund
json.dump(g, open(src, "w"), indent=2)
json.dump(premine, open(f"{d}/funded-accounts.json", "w"), indent=1)
print(f"vr: merged {len(g['alloc'])} accounts (premine of {len(premine)} balance-only accounts)")
PY
}

vr_ureth_vector() { # the paired ureth's certified argument vector, exactly as the lane passes it (urethPinUnicityFlags)
  urethPinUnicityFlags | tr '\n' ' ' | sed 's/  */ /g'
}

vr_verify() { # <finalized genesis> <full shard conf>
  build/ubft vr-genesis verify --input "$VR_DIR/input.json" --deployment "$VR_DIR/contracts/deployment.json" --genesis "$1" --shard-conf "$2" \
    --trust-base test-nodes/trust-base.json --b1-profile test-nodes/b1-profile.json --genesis-identities "$VR_DIR/genesis-identities.json" \
    --vr-hook-measurement "$VR_FRESH_MEASUREMENT" --ureth-flags "$(URETH_GENESIS_SPEC=$1 vr_ureth_vector)" \
    --fee-collector "$(vr_fee_collector)" --funded-accounts "$VR_DIR/funded-accounts.json" --dev-generation "$VR_GENERATION" \
    --out-root-deployment "$VR_DIR/vr-deployment.json" $(vr_utb_args) || vr_die "vr-genesis verify refused the generation" || return 1
}

# the name m2_start_root calls a restarted VR root's flags through (scripts/lib/m2-handoff-lib.sh)
export VR_ROOT_FLAGS_FN=vr_root_flags

vr_root_flags() { # <i> <ureth rpc>: the VR-mode roots: the genesis committee, the VR deployment, and the execution client VT-05b's root side reads
  # VT-09: the node does its member steps itself; its EVM key (the possession proof) is its paired EVM shard node's, as the validator configuration names it
  local evmHolder="--vr-evm-keys test-nodes/evm$1/keys.json"
  [ "${SIGNING:-local}" != authority ] || evmHolder="--vr-evm-authority-socket test-nodes/auth$1/pop.sock --vr-evm-authority-credential test-nodes/auth$1/pop.cred"
  echo --genesis-identities "$VR_DIR/genesis-identities.json" --vr-deployment "$VR_DIR/vr-deployment.json" --pos-evm-rpc "$2" $evmHolder --vr-shard-rpc "http://$(evm_validator_rpc_addr "$1")"
}

# #1216: pin the P85 election in authority <i> (its identity's id and the generation's election, network word and chain). The election is in the
# genesis, so every authority is pinned once its enrollment is complete; the pin cannot change afterwards.
vr_pos_pin_authority() { # <i> [<identity id>]
  [ "${VR_POS:-0}" = 1 ] && [ "${SIGNING:-local}" = authority ] || return 0
  local home=test-nodes/auth$1
  python3 scripts/vr-pos-authority-policy.py "$home/pos-policy.json" "$@" || return 1
  build/ubft signing-authority pos-policy --operator-socket "$home/operator.sock" --operator-credential "$home/operator.cred" --policy "$home/pos-policy.json" ||
    vr_die "pinning the P85 election in authority $1 failed" || return 1
}

vr_readback() { # <ureth rpc>: VR's views at the latest block read back what the plan put there
  local rpc=$1 vr=0xff00000000000000000000000000000000000003 ids want raw module acked health
  ids=$(cast call --rpc-url "$rpc" "$vr" 'committeeIds()(uint64[])') || vr_die "committeeIds() failed" || return 1
  want=$(python3 -c 'import sys;print("[" + ", ".join(str(i) for i in range(1, int(sys.argv[1]) + 1)) + "]")' "${validators:-4}")
  [ "$ids" = "$want" ] || vr_die "VR's committee is $ids, the plan's $want" || return 1
  raw=$(cast call --rpc-url "$rpc" "$vr" 'activeModule()') || vr_die "activeModule() failed" || return 1
  module=$(python3 -c "import sys;h=sys.argv[1][2:];w=[h[i:i+64] for i in range(0,len(h),64)];k=1 if int(w[0],16)==32 else 0;print('0x'+w[k][24:])" "$raw")
  [ "$module" = 0xff00000000000000000000000000000000000007 ] || vr_die "VR's active module is $module" || return 1
  acked=$(cast call --rpc-url "$rpc" "$vr" 'lastAcked()(bytes32)')
  [ "$acked" = "$(cast keccak unicity.vr.genesis-result.v1)" ] || vr_die "VR's lastAcked is $acked" || return 1
  health=$(cast call --rpc-url "$rpc" "$vr" 'health()(uint8)')
  [ "$health" = 0 ] || vr_die "VR's health is $health" || return 1
  echo "vr: committee $ids, module $module, lastAcked GENESIS_RESULT, health $health (block $(cast block-number --rpc-url "$rpc"))"
}
