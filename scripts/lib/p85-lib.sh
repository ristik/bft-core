#!/usr/bin/env bash
# The proof-of-stake recovery lane's helpers (briefs/p85-recovery-lane.md). Sourced by scripts/p85-recovery-steps.sh and, under P85_LANE=1, by
# the paired devnet script. Everything in p85_prepare_genesis is offline: it needs the topology `setup-evm-nodes.sh` wrote and a checkout of
# unicity-pos-contracts (P85_CONTRACTS) with forge on PATH, and it takes no lock.
#
#   p85_prepare_genesis     plan -> relayer genesis -> contracts genesis -> election measurement   (test-nodes/p85/*)
#   p85_profile_args        the b1-profile flags that pin the records hook and the election (price derived from the measurement)
#   p85_write_pos_deployment  the roots' --pos-deployment file, after the profile exists (it pins the registry's code hash)
#   p85_merge_alloc <genesis-source.json>  adds the P85 accounts (custody, election, evidence, ...) to a genesis source's alloc
#   p85_root_flags <node>   the flags a root of the lane runs with
#   p85_selftest            offline checks of the above that need no node and no forge

P85_DIR=${P85_DIR:-test-nodes/p85}
P85_CAPS=${P85_CAPS:-16,2,8}                       # manifest limits.vMax, limits.lMax, election nMax: the measurement is taken at exactly these
P85_BOND_UNIT=${P85_BOND_UNIT:-100000000000000000000}   # 100 UCT in base units: one weight unit
P85_GENESIS_UNITS=${P85_GENESIS_UNITS:-1}          # bond units per genesis identity (unit weights, like the PoA lanes)
P85_H_RECORDS=${P85_H_RECORDS:-2}
P85_HOOK_RECORD_GAS=${P85_HOOK_RECORD_GAS:-3000000}
P85_CADENCE_ROUNDS=${P85_CADENCE_ROUNDS:-60}       # the election is due this many ordinary rounds after the last acknowledged rotation...
P85_CADENCE_SECONDS=${P85_CADENCE_SECONDS:-30}     # ...and this many UC seconds
P85_REGISTRY=0xff00000000000000000000000000000000000002
P85_TREASURY=0x00000000000000000000000000000000000000ee

p85_die() { echo "p85: $*" >&2; return 1; }

p85_prepare_genesis() {
  [ -s test-nodes/trust-base.json ] && [ -s "test-nodes/shard-conf-${partitionID:-8}_0.json" ] || p85_die "run setup-evm-nodes.sh first" || return 1
  [ -n "${P85_CONTRACTS:-}" ] && [ -x "$P85_CONTRACTS/script/p85-genesis.sh" ] || p85_die "P85_CONTRACTS must name a unicity-pos-contracts checkout" || return 1
  command -v forge >/dev/null || p85_die "forge is not on PATH" || return 1
  local conf=test-nodes/shard-conf-${partitionID:-8}_0.json chain
  chain=$(python3 -c "import json;print(json.load(open('$conf'))['partitionParams']['chain_id'])" 2>/dev/null) || chain=${chainID:-31337}
  mkdir -p "$P85_DIR"
  python3 scripts/p85-genesis-plan.py test-nodes/trust-base.json "$conf" "$P85_BOND_UNIT" "$P85_GENESIS_UNITS" >"$P85_DIR/plan.json" || return 1
  build/ubft pos-relayer genesis --plan "$P85_DIR/plan.json" --trust-base test-nodes/trust-base.json --shard-conf "$conf" \
    --out-identities "$P85_DIR/genesis-identities.json" --out-contracts "$P85_DIR/contracts-genesis.json" 2>"$P85_DIR/genesis-assignment.txt" || return 1
  local IFS=, caps
  read -r -a caps <<<"$P85_CAPS"
  local word="0x$(printf 'unicity.p85.lane.network' | shasum -a 256 | cut -d' ' -f1)"
  ( cd "$P85_CONTRACTS" && P85_NETWORK_WORD=$word P85_CHAIN_ID=$chain P85_ROOTS=$P85_REGISTRY P85_TREASURY=$P85_TREASURY \
      P85_V_MAX=${caps[0]} P85_L_MAX=${caps[1]} P85_N_MAX=${caps[2]} P85_CADENCE_ROUNDS=$P85_CADENCE_ROUNDS P85_CADENCE_SECONDS=$P85_CADENCE_SECONDS \
      script/p85-genesis.sh "$OLDPWD/$P85_DIR/contracts-genesis.json" "$OLDPWD/$P85_DIR/genesis" ) || return 1
  ( cd "$P85_CONTRACTS" && script/measure-elect.sh "${caps[0]}" "${caps[1]}" "${caps[2]}" ) >"$P85_DIR/elect-measurement.json" || p85_die "the election measurement failed" || return 1
  echo "p85: genesis prepared in $P85_DIR (assignment $(cat "$P85_DIR/genesis-assignment.txt"), measurement $(cat "$P85_DIR/elect-measurement.json"))"
}

p85_json() { python3 -c "import json,sys;print(json.load(open('$1'))$2)"; }

p85_profile_args() {
  local d=$P85_DIR/genesis/deployment.json
  [ -s "$d" ] || p85_die "no deployment: run p85_prepare_genesis" || return 1
  echo --records-custody "$(p85_json "$d" "['custody']")" --h-records "$P85_H_RECORDS" --hook-record-gas "$P85_HOOK_RECORD_GAS" \
    --election "$(p85_json "$d" "['election']")" --elect-measurement "$P85_DIR/elect-measurement.json" --elect-caps "$P85_CAPS"
}

p85_write_pos_deployment() {
  local d=$P85_DIR/genesis/deployment.json profile=${1:-test-nodes/b1-profile.json}
  python3 - "$d" "$profile" >"$P85_DIR/pos-deployment.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); p = json.load(open(sys.argv[2]))
print(json.dumps({
    "networkWord": d["networkWord"], "chainId": str(d["chainId"]),
    "custody": d["custody"], "custodyCodeHash": d["custodyCodeHash"],
    "registry": "0xff00000000000000000000000000000000000002", "registryCodeHash": p["runtimeHash"],
    "election": d["election"], "electionCodeHash": d["electionCodeHash"],
}, indent=1))
PY
}

p85_merge_alloc() {
  local src=$1
  [ -s "$P85_DIR/genesis/alloc.json" ] || return 0
  python3 - "$src" "$P85_DIR/genesis/alloc.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); extra = json.load(open(sys.argv[2]))
for addr, acct in extra.items():
    if addr in g["alloc"] or addr.lower() in {k.lower() for k in g["alloc"]}:
        sys.exit(f"alloc already has {addr}")
    g["alloc"][addr] = acct
json.dump(g, open(sys.argv[1], "w"), indent=2)
print(f"p85: {len(extra)} P85 accounts added to the genesis alloc")
PY
}

# p85_root_flags <node> <eth rpc url>: the flags of a root of the lane. The P85
# control executor with the election pinned (--q3-lane is added by the caller), and the genesis committee's records as K. --pos-evm-rpc is required by an election-pinned chain.
p85_root_flags() {
  echo --pos-deployment "$P85_DIR/pos-deployment.json" --pos-genesis-identities "$P85_DIR/genesis-identities.json" --pos-evm-rpc "$2"
}

p85_selftest() {
  local ok=0 bad
  bad() { echo "p85 selftest FAIL: $*" >&2; ok=1; }
  bash -n scripts/lib/p85-lib.sh || bad "bash -n"
  python3 -c "import ast;ast.parse(open('scripts/p85-genesis-plan.py').read())" || bad "plan generator does not parse"
  # the plan generator refuses a topology that is not coupled one to one
  local t; t=$(mktemp -d)
  echo '{"rootNodes":[{"nodeId":"a","sigKey":"0x02"}]}' >"$t/tb.json"; echo '{"validators":[]}' >"$t/c.json"
  python3 scripts/p85-genesis-plan.py "$t/tb.json" "$t/c.json" 1 1 >/dev/null 2>&1 && bad "an uncoupled topology was accepted"
  rm -rf "$t"
  return $ok
}
