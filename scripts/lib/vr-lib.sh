#!/usr/bin/env bash
# The validator-registry (VR) generation lane's helpers (VT-14, ristik/bft-core#1158). Sourced by the paired devnet script under VR_LANE=1
# (with Q3_B1=1 and M2_PROFILE2=1): the same genesis plan as deploy/testnet/vr_genesis.py, on the devnet's topology, so a VR generation's roots,
# shard nodes and ureth start from the plan's outputs, verified by `ubft vr-genesis verify` before anything runs.
#
#   vr_lane_conf            the EVM shard configuration pins VR (validator_registry, validator_registry_code_hash) from the measurement
#   vr_profile_args         the b1-profile flags of a VR generation (both hooks on VR, priced from the measurement)
#   vr_prepare_genesis      dev keys -> vr-genesis plan -> contracts genesis (test-nodes/vr/*)
#   vr_merge_alloc <src>    adds the VR accounts and the dev premine to a genesis source's alloc
#   vr_verify <genesis> <full-conf>   vr-genesis verify of the finished set; writes the roots' --vr-deployment
#   vr_root_flags <i> <rpc> the flags a root of the lane runs with
#   vr_readback <rpc>       VR's views through ureth: the genesis committee, the PoA module, GENESIS_RESULT, Healthy
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
  python3 deploy/testnet/vr_dev_keys.py "$VR_DIR/dev-keys" "$n" || vr_die "generating the dev keys failed" || return 1
  build/ubft vr-genesis plan --trust-base test-nodes/trust-base.json --shard-conf "test-nodes/shard-conf-${partitionID:-8}_0.json" \
    --bindings "$VR_DIR/genesis-bindings.json" --owners "$VR_DIR/dev-keys/owners.json" --b1-profile test-nodes/b1-profile.json \
    --network-word "$(vr_network_word)" --governor-signers "$(tr -d '\n' <"$VR_DIR/dev-keys/signers.txt")" --fee-collector "$(vr_fee_collector)" \
    --out-input "$VR_DIR/input.json" --out-identities "$VR_DIR/genesis-identities.json" || return 1
  ( cd "$VR_CONTRACTS" && HOME=${VR_FORGE_HOME:-$HOME} script/vr-genesis.sh "$OLDPWD/$VR_DIR/input.json" "$OLDPWD/$VR_DIR/contracts" ) ||
    vr_die "the contracts genesis failed" || return 1
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
    --out-root-deployment "$VR_DIR/vr-deployment.json" || vr_die "vr-genesis verify refused the generation" || return 1
}

vr_root_flags() { # <i> <ureth rpc>: the VR-mode roots: the genesis committee, the VR deployment, and the execution client VT-05b's root side reads
  echo --genesis-identities "$VR_DIR/genesis-identities.json" --vr-deployment "$VR_DIR/vr-deployment.json" --pos-evm-rpc "$2"
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
