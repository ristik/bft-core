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
# manifest limits.vMax, limits.lMax, election nMax: the election price AND the records hook's per-record reservation are measured at exactly these. 16,1,6 is what
# the 3,000,000 per record (P85_HOOK_RECORD_GAS) covers with the 1.25 margin: the RecoveryAck that applies a pending closure costs 2,281,165 cold for 6 members of
# one lot, but 3,629,888 for 8 members of 2 lots (contracts docs/p85/HOOK_GAS.md). Until the owner decides between raising the limit and keeping lower caps (Q12),
# the lane declares caps its limit covers; `b1-profile --hook-measurement` refuses any pair it does not.
P85_CAPS=${P85_CAPS:-16,1,6}
P85_BOND_UNIT=${P85_BOND_UNIT:-100000000000000000000}   # 100 UCT in base units: one weight unit
P85_GENESIS_UNITS=${P85_GENESIS_UNITS:-1}          # bond units per genesis identity (unit weights, like the PoA lanes)
P85_H_RECORDS=${P85_H_RECORDS:-2}
P85_HOOK_RECORD_GAS=${P85_HOOK_RECORD_GAS:-3000000}
P85_CADENCE_ROUNDS=${P85_CADENCE_ROUNDS:-400}      # the election is due this many ordinary rounds after the last acknowledged rotation (the joiner is onboarded first)...
P85_DIST_NUM=${P85_DIST_NUM:-1}; P85_DIST_DEN=${P85_DIST_DEN:-2}   # the election's weight-distance bound D <= 1/2: adding one unit-weight joiner to four unit-weight members is D = 2/5, over the default 1/4 (WeightChurn, a NoCandidate)
P85_CADENCE_SECONDS=${P85_CADENCE_SECONDS:-300}    # ...and this many UC seconds
P85_REGISTRY=0xff00000000000000000000000000000000000002
P85_TREASURY=0x00000000000000000000000000000000000000ee
# T8: the fixed development authority of policy governance, and the reward pool's genesis allocation and rate (explicit; the contracts have no default authority)
P85_GOVERNANCE_AUTHORITY=${P85_GOVERNANCE_AUTHORITY:-0x00000000000000000000000000000000000000ef}
P85_REWARD_FUNDING=${P85_REWARD_FUNDING:-10000000000000000000000}
P85_REWARD_RATE=${P85_REWARD_RATE:-1000000000000000000}

p85_die() { echo "p85: $*" >&2; return 1; }

# The identity of the root consensus the contracts bind (contracts#46: the evidence digests are rebuilt from the root network N and genesis identity G, and both are part
# of the manifest the genesis hashes): N is the trust base's network id, G its root genesis id, both read from the manifest tool and never typed. Prints
# "P85_ROOT_NETWORK=<n> P85_ROOT_GENESIS=0x<64 hex>".
p85_root_identity() { # [trust-base.json]
  local tb=${1:-test-nodes/trust-base.json} d out n g
  d=$(mktemp -d) || return 1
  out=$(build/ubft trust-base utb-manifest --trust-base "$tb" --out-dir "$d" 2>&1); local rc=$?
  rm -rf "$d"
  [ "$rc" -eq 0 ] || { echo "p85_root_identity: the manifest tool failed: $out" >&2; return 1; }
  n=$(sed -n 's/^root network id *//p' <<<"$out"); g=$(sed -n 's/^root genesis id *//p' <<<"$out")
  [[ $n =~ ^[0-9]+$ ]] && [ "$n" -gt 0 ] && [[ $g =~ ^0x[0-9a-f]{64}$ ]] || { echo "p85_root_identity: no network id / genesis id in the tool's output: $out" >&2; return 1; }
  echo "P85_ROOT_NETWORK=$n P85_ROOT_GENESIS=$g"
}
# p85_root_identity_args [trust-base.json]: fills the array P85_ROOT_ARGS with the two assignments, one element each, whatever IFS the caller has set
# (p85_prepare_genesis runs with IFS=, for its caps: an unquoted expansion of the identity would not split there). Use: env "${P85_ROOT_ARGS[@]}" ...
p85_root_identity_args() {
  local IFS=' ' line
  line=$(p85_root_identity "$@") || return 1
  read -r -a P85_ROOT_ARGS <<<"$line"
  [ "${#P85_ROOT_ARGS[@]}" -eq 2 ] || { echo "p85_root_identity_args: expected two assignments, got: $line" >&2; return 1; }
}

p85_prepare_genesis() {
  [ -s test-nodes/trust-base.json ] && [ -s "test-nodes/shard-conf-${partitionID:-8}_0.json" ] || p85_die "run setup-evm-nodes.sh first" || return 1
  [ -n "${P85_CONTRACTS:-}" ] && [ -x "$P85_CONTRACTS/script/p85-genesis.sh" ] || p85_die "P85_CONTRACTS must name a unicity-pos-contracts checkout" || return 1
  command -v forge >/dev/null || p85_die "forge is not on PATH" || return 1
  local conf=${P85_GENESIS_CONF:-test-nodes/shard-conf-${partitionID:-8}_0.json} chain
  chain=$(python3 -c "import json;print(json.load(open('$conf'))['partitionParams']['chain_id'])" 2>/dev/null) || chain=${chainID:-31337}
  mkdir -p "$P85_DIR"
  # REWARD_LANE=1 (T8): the genesis payees hold keys, so the reward step can claim for real
  # X4_HELD_KEYS=1 (the PoS campaign): the genesis owners and withdrawal addresses hold keys the lane keeps, so an incumbent can request retirement and claim
  P85_PLAN_OWNER_KEYS=$([ "${X4_HELD_KEYS:-0}" = 1 ] && echo "$P85_DIR/owner-keys") \
  P85_PLAN_PAYEE_KEYS=$([ "${REWARD_LANE:-0}" = 1 ] && echo "$P85_DIR/payee-keys") P85_CAST=$P85_CAST \
    python3 scripts/p85-genesis-plan.py test-nodes/trust-base.json "$conf" "$P85_BOND_UNIT" "$P85_GENESIS_UNITS" >"$P85_DIR/plan.json" || return 1
  # the first pass runs on the base configuration (the full one does not exist yet): provisional, its id is replaced by p85_reconcile_genesis_assignment
  build/ubft pos-relayer genesis ${P85_GENESIS_CONF:---provisional} --plan "$P85_DIR/plan.json" --trust-base test-nodes/trust-base.json --shard-conf "$conf" \
    --out-identities "$P85_DIR/genesis-identities.json" --out-contracts "$P85_DIR/contracts-genesis.json" 2>"$P85_DIR/genesis-assignment.txt" || return 1
  local IFS=, caps
  read -r -a caps <<<"$P85_CAPS"
  local word="0x$(printf 'unicity.p85.lane.network' | shasum -a 256 | cut -d' ' -f1)"
  p85_root_identity_args test-nodes/trust-base.json || return 1
  ( cd "$P85_CONTRACTS" && env "${P85_ROOT_ARGS[@]}" P85_NETWORK_WORD=$word P85_CHAIN_ID=$chain P85_ROOTS=$P85_REGISTRY P85_TREASURY=$P85_TREASURY \
      P85_GOVERNANCE_AUTHORITY=$P85_GOVERNANCE_AUTHORITY P85_REWARD_FUNDING=$P85_REWARD_FUNDING P85_REWARD_RATE=$P85_REWARD_RATE \
      P85_V_MAX=${caps[0]} P85_L_MAX=${caps[1]} P85_N_MAX=${caps[2]} P85_CADENCE_ROUNDS=$P85_CADENCE_ROUNDS P85_CADENCE_SECONDS=$P85_CADENCE_SECONDS P85_DIST_NUM=$P85_DIST_NUM P85_DIST_DEN=$P85_DIST_DEN \
      script/p85-genesis.sh "$OLDPWD/$P85_DIR/contracts-genesis.json" "$OLDPWD/$P85_DIR/genesis" ) || return 1
  ( cd "$P85_CONTRACTS" && script/measure-elect.sh "${caps[0]}" "${caps[1]}" "${caps[2]}" ) >"$P85_DIR/elect-measurement.json" || p85_die "the election measurement failed" || return 1
  ( cd "$P85_CONTRACTS" && script/measure-hook-gas.sh "${caps[0]}" "${caps[1]}" "${caps[2]}" ack stage closure recovery ) >"$P85_DIR/hook-measurement.jsonl" || p85_die "the records hook measurement failed" || return 1
  echo "p85: genesis prepared in $P85_DIR (assignment $(cat "$P85_DIR/genesis-assignment.txt"), measurement $(cat "$P85_DIR/elect-measurement.json"))"
}

# The custody genesis names the assignment hash of the genesis shard configuration over the genesis identity records. The roots derive the same hash
# from the configuration they install: the FULL one (the base plus seal_registry_genesis), which `engine-api genesis` writes only after the funded
# genesis exists. A hash taken from the base configuration is another assignment, and custody then does not know the one the root closes (P85
# runs 25 and 26: the closure of epoch 1 reverted AssignmentNotActive in every block). So: finalize once without the P85 accounts, take the id
# from that full configuration, prepare the contracts genesis with it, and (p85_assert_full_conf) check that the real genesis wrote the same file.
p85_assignment_of() { # shard-conf -> the genesis assignment id of that configuration over the lane's identities
  local d=$P85_DIR/reconcile; mkdir -p "$d"
  build/ubft pos-relayer genesis --plan "$P85_DIR/plan.json" --trust-base test-nodes/trust-base.json --shard-conf "$1" \
    --out-identities "$d/identities.json" --out-contracts "$d/contracts.json" 2>&1 | sed -n 's/^genesis assignment id //p'
}
p85_reconcile_genesis_assignment() { # the funded genesis source (without the P85 accounts)
  local d=$P85_DIR/reconcile have want; mkdir -p "$d"
  build/ubft engine-api genesis --shard-conf "test-nodes/shard-conf-${partitionID:-8}_0.json" --trust-base test-nodes/trust-base.json \
    --b1-profile test-nodes/b1-profile.json --alloc-source "$1" --out "$d/genesis.json" --full-shard-conf "$d/full-shard-conf.json" \
    --identities-out "$d/b1-identities.json" >/dev/null || p85_die "the reconciling finalization failed" || return 1
  have=$(grep -o '0x[0-9a-fA-F]\{64\}' "$P85_DIR/genesis-assignment.txt" | head -1)
  want=$(p85_assignment_of "$d/full-shard-conf.json")
  [[ "$want" =~ ^0x[0-9a-f]{64}$ ]] || p85_die "no assignment id for the full configuration" || return 1
  if [ "$have" = "$want" ]; then echo "p85: the genesis assignment $have is the full configuration's"; return 0; fi
  echo "p85: the genesis assignment of the base configuration ($have) is not the installed full configuration's ($want): preparing the genesis again from the full configuration"
  P85_GENESIS_CONF=$d/full-shard-conf.json p85_prepare_genesis || return 1
  [ "$(grep -o '0x[0-9a-fA-F]\{64\}' "$P85_DIR/genesis-assignment.txt" | head -1)" = "$want" ] || p85_die "the prepared genesis does not carry $want" || return 1
}
p85_assert_full_conf() { # the full configuration the real genesis wrote must be the one the id was taken from
  build/ubft pos-relayer verify-genesis --plan "$P85_DIR/plan.json" --trust-base test-nodes/trust-base.json --shard-conf "$1" \
    --contracts-genesis "$P85_DIR/contracts-genesis.json" 2>&1 | tail -n 1 || return 1
  cmp -s "$1" "$P85_DIR/reconcile/full-shard-conf.json" || p85_die "the full shard configuration changed after the genesis assignment was fixed (the P85 accounts moved seal_registry_genesis?)" || return 1
}

# The profile's per-record reservation against a FRESH cold measurement of the worst record at the deployed caps (contracts script/measure-hook-gas.sh):
# refused when the contracts grew past the margin. The same rule `b1-profile --hook-measurement` applies at generation.
p85_check_hook_gas() { # profile
  local caps; IFS=, read -r -a caps <<<"$P85_CAPS"
  ( cd "$P85_CONTRACTS" && script/measure-hook-gas.sh "${caps[0]}" "${caps[1]}" "${caps[2]}" ack stage closure recovery ) >"$P85_DIR/hook-measurement-fresh.jsonl" || p85_die "the fresh hook measurement failed" || return 1
  build/ubft engine-api check-hook-gas --b1-profile "$1" --measurement "$P85_DIR/hook-measurement-fresh.jsonl" || p85_die "the hook reservation does not cover the fresh measurement" || return 1
}

p85_json() { python3 -c "import json,sys;print(json.load(open('$1'))$2)"; }

# P85_SHADOW=1 (X4 #58, briefs/x4-shadow-campaign-design.md): the staking modules are in the genesis and the records hook runs, but the chain has NO authoritative
# election: the profile carries no --election/--elect-measurement and the roots run without --pos-deployment/--pos-evm-rpc/--pos-genesis-identities. The shadow
# adapter (scripts/shadow) then runs the real election on forks of certified state. The genesis tool takes the election optional (b1state validHook).
p85_shadow() { [ "${P85_SHADOW:-0}" = 1 ]; }

p85_profile_args() {
  local d=$P85_DIR/genesis/deployment.json
  [ -s "$d" ] || p85_die "no deployment: run p85_prepare_genesis" || return 1
  if p85_shadow; then
    echo --records-custody "$(p85_json "$d" "['custody']")" --h-records "$P85_H_RECORDS" --hook-record-gas "$P85_HOOK_RECORD_GAS" --hook-measurement "$P85_DIR/hook-measurement.jsonl" --elect-caps "$P85_CAPS"
    return
  fi
  echo --records-custody "$(p85_json "$d" "['custody']")" --h-records "$P85_H_RECORDS" --hook-record-gas "$P85_HOOK_RECORD_GAS" \
    --election "$(p85_json "$d" "['election']")" --elect-measurement "$P85_DIR/elect-measurement.json" --hook-measurement "$P85_DIR/hook-measurement.jsonl" --elect-caps "$P85_CAPS"
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
    "rewardPool": d["rewardPool"], "rewardPoolCodeHash": d["rewardPoolCodeHash"],
}, indent=1))
PY
}

P85_CAST=${P85_CAST:-$HOME/.foundry/bin/cast}
# the joiner bonds P85_JOINER_UNITS units (3 in the over-bound mode, which refuses a candidate that heavy), and is funded with those plus two more units for the
# gas of its transactions (the default mode: 1 + 2 = 3 units, as before). Decided here, before the genesis alloc, from the mode.
P85_JOINER_UNITS=${P85_JOINER_UNITS:-$([ "${P85_MODE:-}" = overbound ] && echo 3 || echo 1)}
# the shadow chain's joiner account also funds the scripted spare identities (scripts/x4-shadow-steps.sh): ten more units
P85_JOINER_FUND_WEI=${P85_JOINER_FUND_WEI:-$(python3 -c "print($P85_BOND_UNIT * ($P85_JOINER_UNITS + 2 + (10 if '${P85_SHADOW:-0}' == '1' else 0)))")}

# The joiner entity's EVM-side account (owner of its custody identity; it also pays the relayer transactions of the lane). It is funded in the
# genesis alloc, so the lane needs no faucet. Its root/EVM keys are the nodes' own (written by the lane when the joiner's nodes exist).
p85_joiner_prepare() {
  local d=$P85_DIR/joiner
  mkdir -p "$d"
  [ -s "$d/owner.key" ] || { printf '0x%s\n' "$(openssl rand -hex 32)" >"$d/owner.key"; chmod 600 "$d/owner.key"; }
  "$P85_CAST" wallet address --private-key "$(cat "$d/owner.key")" >"$d/owner.addr" || p85_die "cast is not available (P85_CAST)" || return 1
  printf '0x%s\n' "$(printf 'p85-lane/withdrawal/joiner' | shasum -a 256 | cut -c1-40)" >"$d/withdrawal.addr"
  if [ "${X4_EXIT_LANE:-0}" = 1 ]; then   # X4 B3b: the joiner's identity (custody id 5) exits, so its owner and withdrawal addresses are keys the lane holds (random, lane-only)
    [ -s "$d/withdrawal.key" ] || { printf '0x%s\n' "$(openssl rand -hex 32)" >"$d/withdrawal.key"; chmod 600 "$d/withdrawal.key"; }
    "$P85_CAST" wallet address --private-key "$(cat "$d/withdrawal.key")" >"$d/withdrawal.addr" || p85_die "cast is not available (P85_CAST)" || return 1
    mkdir -p "$P85_DIR/owner-keys"
    cp "$d/owner.key" "$P85_DIR/owner-keys/owner-5.key"; cp "$d/withdrawal.key" "$P85_DIR/owner-keys/withdrawal-5.key"; chmod 600 "$P85_DIR"/owner-keys/*-5.key
  fi
  printf '0x%s\n' "$(printf 'p85-lane/payee/joiner' | shasum -a 256 | cut -c1-40)" >"$d/payee.addr"
}

p85_merge_alloc() {
  local src=$1
  [ -s "$P85_DIR/genesis/alloc.json" ] || return 0
  p85_joiner_prepare || return 1
  python3 - "$src" "$P85_DIR/genesis/alloc.json" "$(cat "$P85_DIR/joiner/owner.addr")" "$P85_JOINER_FUND_WEI" "$P85_DIR/genesis/deployment.json" "$P85_CAST" <<'PY'
import json, subprocess, sys
g = json.load(open(sys.argv[1])); extra = json.load(open(sys.argv[2])); dep = json.load(open(sys.argv[5]))
# T8: the contracts' genesis state carries the deployed code of every module the deployment records, and the reward pool holds exactly its recorded
# funding from block 0 (allocated, not promised). Checked before anything is merged.
def acct(addr):
    hits = [v for k, v in extra.items() if k.lower().removeprefix("0x") == addr.lower().removeprefix("0x")]
    if len(hits) != 1: sys.exit(f"no account {addr} in the contracts genesis state")
    return hits[0]
for module in ("custody", "election", "policy", "rewardPool"):
    code = acct(dep[module]).get("code", "0x")
    if len(code) <= 2: sys.exit(f"no code at the {module} ({dep[module]}) in the contracts genesis state")
    have = subprocess.run([sys.argv[6], "keccak", code], text=True, capture_output=True, check=True).stdout.strip().lower()
    if have != dep[module + "CodeHash"].lower(): sys.exit(f"{module} code in the genesis state hashes to {have}, the deployment records {dep[module + 'CodeHash']}")
if int(acct(dep["rewardPool"]).get("balance", "0x0"), 16) != int(dep["rewardFunding"]):
    sys.exit(f"the reward pool does not hold its recorded funding {dep['rewardFunding']} in the genesis state")
extra[sys.argv[3]] = {"balance": hex(int(sys.argv[4]))}
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
  # no election is pinned: a root given --pos-deployment would require the election-pinned chain. It still records the genesis committee (the same file, the
  # non-PoS flag: --pos-genesis-identities needs --pos-deployment), so the assignment the records hook delivers is the one custody holds.
  if p85_shadow; then echo --genesis-identities "$P85_DIR/genesis-identities.json"; return 0; fi
  echo --pos-deployment "$P85_DIR/pos-deployment.json" --pos-genesis-identities "$P85_DIR/genesis-identities.json" --pos-evm-rpc "$2"
  # S4: every root keeps an observer journal (S3, docs/root-evidence.md)
  [ "${S4_LANE:-0}" != 1 ] || echo --evidence-journal "test-nodes/root$1/evidence.db"
}

# The shadow chain has the records hook and NO election, and its roots run without the PoS flags. Two checks, both run by the shadow lane after the genesis and
# after the roots started (and by the selftest on fixtures): a profile with an election, or a root with --pos-*, would make the shadow comparison meaningless.
p85_assert_shadow_profile() { # b1-profile.json
  python3 - "$1" <<'PY' || return 1
import json, sys
p = json.load(open(sys.argv[1]))
zero = "0x" + "00" * 20
if p.get("recordsCustody", zero) == zero: sys.exit("shadow: the profile has no records hook (recordsCustody)")
if p.get("electionContract", zero) != zero or p.get("electGas", 0) != 0 or p.get("electMeasurement"):
    sys.exit("shadow: the profile carries an authoritative election (electionContract/electGas/electMeasurement)")
PY
}
p85_assert_shadow_roots() { # the command lines of the running roots
  local f pid args n=0
  for f in test-nodes/root*/pid; do
    [ -s "$f" ] || continue
    pid=$(cat "$f"); args=$(ps -o args= -p "$pid" 2>/dev/null) || continue
    [ -n "$args" ] || continue
    n=$((n + 1))
    case "$args" in *--pos-deployment*|*--pos-evm-rpc*|*--pos-genesis-identities*) p85_die "shadow: root $f runs with PoS flags: $args" || return 1;; esac
  done
  [ "$n" -gt 0 ] || p85_die "shadow: no running root to check" || return 1
}

# A node answers an estimateGas/send that raced a block being built with "bound parent hash mismatch" / "Failed to estimate gas" (ci-lane run 39495201581: the
# shadow campaign's 27th minute). Both are refusals BEFORE anything is sent, so the same transaction can be tried again; nothing else is retried, and every retry
# is logged (X4_RETRY_LOG) so the evidence shows how often the node did it. x4_retry CMD...: stdout of the successful attempt; the last stderr on failure.
x4_retry() {
  local i n=${X4_RETRIES:-8} out rc err; err=$(mktemp) || return 1
  for i in $(seq 1 "$n"); do
    out=$("$@" 2>"$err"); rc=$?
    if [ "$rc" -eq 0 ]; then rm -f "$err"; printf '%s\n' "$out"; return 0; fi
    if grep -qE 'Failed to estimate gas|bound parent hash mismatch' "$err" && [ "$i" -lt "$n" ]; then
      echo "$(date -u +%FT%TZ) retry $i/$n: $1 $2 $3: $(head -c 200 "$err" | tr '\n' ' ')" >>"${X4_RETRY_LOG:-/dev/null}"
      sleep "${X4_RETRY_SLEEP:-5}"; continue
    fi
    printf '%s\n' "$out"; cat "$err" >&2; rm -f "$err"; return "$rc"
  done
}

p85_selftest() {
  local ok=0 bad got
  bad() { echo "p85 selftest FAIL: $*" >&2; ok=1; }
  bash -n scripts/lib/p85-lib.sh || bad "bash -n"
  python3 -c "import ast;ast.parse(open('scripts/p85-genesis-plan.py').read())" || bad "plan generator does not parse"
  # the plan generator refuses a topology that is not coupled one to one
  local t; t=$(mktemp -d)
  echo '{"rootNodes":[{"nodeId":"a","sigKey":"0x02"}]}' >"$t/tb.json"; echo '{"validators":[]}' >"$t/c.json"
  python3 scripts/p85-genesis-plan.py "$t/tb.json" "$t/c.json" 1 1 >/dev/null 2>&1 && bad "an uncoupled topology was accepted"
  # a dry run of p85_prepare_genesis itself (fake ubft, forge and contracts scripts): both root-identity variables, the comma-split caps and the rest reach p85-genesis.sh
  # as separate variables, under the function's own IFS=,
  local d="$t/dry" want
  mkdir -p "$d/scripts" "$d/build" "$d/test-nodes"; cp scripts/p85-genesis-plan.py "$d/scripts/"
  mkdir -p "$d/contracts/script" "$d/bin"
  echo '{"rootNodes":[{"nodeId":"a","sigKey":"0x02"}]}' >"$d/test-nodes/trust-base.json"
  echo '{"validators":[{"nodeId":"e","sigKey":"0x03"}],"partitionParams":{"chain_id":31337}}' >"$d/test-nodes/shard-conf-8_0.json"
  printf '#!/bin/sh\nif [ "$1" = trust-base ]; then printf "x\\nroot genesis id  0x%s\\nroot network id  7\\n" "%s"; fi\nexit 0\n' "$(printf 'ab%.0s' $(seq 32))" "$(printf 'ab%.0s' $(seq 32))" >"$d/build/ubft"
  printf '#!/bin/sh\nexit 0\n' >"$d/bin/forge"
  printf '#!/bin/sh\nenv | grep "^P85_" | sort >"$1.env"\n' >"$d/contracts/script/p85-genesis.sh"
  printf '#!/bin/sh\necho "{}"\n' >"$d/contracts/script/measure-elect.sh"; cp "$d/contracts/script/measure-elect.sh" "$d/contracts/script/measure-hook-gas.sh"
  chmod +x "$d/build/ubft" "$d/bin/forge" "$d/contracts/script/"*.sh
  ( cd "$d" && PATH="$d/bin:$PATH" P85_CONTRACTS="$d/contracts" p85_prepare_genesis ) >"$t/dry.out" 2>&1 || bad "the dry run of p85_prepare_genesis failed: $(tail -3 "$t/dry.out")"
  want="P85_ROOT_GENESIS=0x$(printf 'ab%.0s' $(seq 32))"
  grep -qx "$want" "$d/test-nodes/p85/contracts-genesis.json.env" 2>/dev/null || grep -qx "$want" "$d"/test-nodes/p85/*.env 2>/dev/null || bad "P85_ROOT_GENESIS did not reach p85-genesis.sh: $(cat "$d"/test-nodes/p85/*.env 2>/dev/null | tr '\n' ' ')"
  grep -qx "P85_ROOT_NETWORK=7" "$d"/test-nodes/p85/*.env 2>/dev/null || bad "P85_ROOT_NETWORK did not reach p85-genesis.sh as its own variable"
  grep -qx "P85_V_MAX=16" "$d"/test-nodes/p85/*.env 2>/dev/null || bad "the caps were not split for p85-genesis.sh"
  # the shadow variant: no election flags, no PoS root flags; the unshadowed variant keeps both (regression)
  mkdir -p "$t/sh/genesis" "$t/sh/n/root1"
  echo '{"custody":"0x00000000000000000000000000000000000000c1","election":"0x00000000000000000000000000000000000000e1"}' >"$t/sh/genesis/deployment.json"
  got=$(P85_DIR="$t/sh" P85_SHADOW=1 p85_profile_args); case "$got" in *--election*|*--elect-measurement*) bad "the shadow profile arguments carry the election: $got";; esac
  case "$got" in *--records-custody*--hook-measurement*--elect-caps*) ;; *) bad "the shadow profile arguments lost the records hook: $got";; esac
  got=$(P85_DIR="$t/sh" P85_SHADOW=0 p85_profile_args); case "$got" in *--election*--elect-measurement*) ;; *) bad "the PoS profile arguments lost the election: $got";; esac
  got=$(P85_DIR="$t/sh" P85_SHADOW=1 p85_root_flags 1 http://x); case "$got" in *--pos-*) bad "a shadow root is given PoS flags: $got";; esac
  case "$got" in *--genesis-identities*) ;; *) bad "a shadow root does not record the genesis committee: $got";; esac
  got=$(P85_DIR="$t/sh" P85_SHADOW=0 p85_root_flags 1 http://x); case "$got" in *--pos-deployment*--pos-evm-rpc*) ;; *) bad "a PoS root lost its PoS flags: $got";; esac
  echo '{"recordsCustody":"0x00000000000000000000000000000000000000c1","electionContract":"0x0000000000000000000000000000000000000000","electGas":0}' >"$t/sh/ok.json"
  p85_assert_shadow_profile "$t/sh/ok.json" 2>/dev/null || bad "a hook-only profile was refused as a shadow profile"
  echo '{"recordsCustody":"0x00000000000000000000000000000000000000c1","electionContract":"0x00000000000000000000000000000000000000e1","electGas":5}' >"$t/sh/bad.json"
  p85_assert_shadow_profile "$t/sh/bad.json" 2>/dev/null && bad "a profile with an election was accepted as a shadow profile"
  echo '{"electionContract":"0x0000000000000000000000000000000000000000","electGas":0}' >"$t/sh/nohook.json"
  p85_assert_shadow_profile "$t/sh/nohook.json" 2>/dev/null && bad "a profile without the records hook was accepted as a shadow profile"
  sleep 30 & local sp=$!; echo "$sp" >"$t/sh/n/root1/pid"
  ( cd "$t/sh/n" && mkdir -p test-nodes && rm -rf test-nodes/root1 && cp -R root1 test-nodes/root1 && p85_assert_shadow_roots ) 2>/dev/null || bad "a root without PoS flags was refused"
  kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
  # a process whose command line carries a PoS flag is refused
  local pf="$t/sh/n/test-nodes/root1/pid"
  bash -c 'exec -a "ubft root-node run --pos-deployment x" sleep 30' & local sp2=$!; echo "$sp2" >"$pf"
  ( cd "$t/sh/n" && p85_assert_shadow_roots ) 2>/dev/null && bad "a root with --pos-deployment was accepted as a shadow root"
  kill "$sp2" 2>/dev/null; wait "$sp2" 2>/dev/null
  # x4_retry: a transient pre-send refusal is retried and logged, anything else fails at once, a persistent refusal fails after the bound
  local c="$t/retry-count"; echo 0 >"$c"
  flaky() { local n; n=$(cat "$c"); echo $((n + 1)) >"$c"; if [ "$n" -lt 2 ]; then echo "Error: Failed to estimate gas: bound parent hash mismatch" >&2; return 1; fi; echo "ok-out"; }
  got=$(X4_RETRY_SLEEP=0 X4_RETRY_LOG="$t/retry.log" x4_retry flaky 2>/dev/null); [ "$got" = ok-out ] && [ "$(cat "$c")" = 3 ] && [ "$(wc -l <"$t/retry.log" | tr -d ' ')" = 2 ] || bad "x4_retry did not retry a transient estimate refusal twice and log it: '$got' $(cat "$c")"
  echo 0 >"$c"; hard() { local n; n=$(cat "$c"); echo $((n + 1)) >"$c"; echo "Error: execution reverted" >&2; return 7; }
  X4_RETRY_SLEEP=0 x4_retry hard >/dev/null 2>&1; [ "$?" = 7 ] && [ "$(cat "$c")" = 1 ] || bad "x4_retry retried (or masked the status of) a real failure"
  echo 0 >"$c"; always() { local n; n=$(cat "$c"); echo $((n + 1)) >"$c"; echo "bound parent hash mismatch" >&2; return 1; }
  X4_RETRIES=4 X4_RETRY_SLEEP=0 x4_retry always >/dev/null 2>&1; [ "$?" = 1 ] && [ "$(cat "$c")" = 4 ] || bad "x4_retry did not stop at its bound"
  rm -rf "$t"
  return $ok
}

# p85_progress <label> [seconds before the second look] [window]: the lane has no aggregator shards (h3_progress needs them), so progress is the
# root round and the EVM shard's certified IR round (partition 8) both advancing, polled for up to the window.
p85_progress() {
  local label=$1 pause=${2:-10} limit=${3:-35} q='[.roundNumber, (.partitionShards[] | select(.partitionId==8) | .roundNumber)] | @tsv'
  local r0 e0 r1 e1 waited=0
  read -r r0 e0 < <(h3_root_info | jq -r "$q") || return 1
  sleep "$pause"
  while :; do
    read -r r1 e1 < <(h3_root_info | jq -r "$q") || return 1
    if [ "$r1" -gt "$r0" ] && [ "$e1" -gt "$e0" ]; then
      echo "  progress $label: root round $r0 -> $r1, EVM certified IR round $e0 -> $e1"; return 0
    fi
    waited=$((waited + 2)); [ "$waited" -lt "$limit" ] || break
    sleep 2
  done
  echo "  no progress $label: root round $r0 -> $r1, EVM certified IR round $e0 -> $e1" >&2; return 1
}
