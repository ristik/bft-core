#!/usr/bin/env python3
"""The registration policy (`signing-authority run --registration-policy`) of one authority of the VR lane under SIGNING=authority.

  vr-authority-policy.py <out> binding <i> <validators>   authority i (the EVM key of identity rank(root i)) may sign ONE binding: its identity's owner
                                                          stages the payee recorded in <vr dir>/rotate-payees.json (the lane's `validator rotate`)
  vr-authority-policy.py <out> register <i>               the joiner's authority i may sign ONE registration: the first dev signer registers root i with
                                                          itself as payee (the lane's `validator apply`)

The dev keys exist before the authorities start (they are generated here when absent, into the directory vr-lib.sh's vr_prepare_genesis then reuses).
Environment: VR_DIR (default test-nodes/vr), VR_GENERATION (default paired-devnet), M2_CHAIN_ID (default 31337).
"""
import hashlib, json, os, secrets, subprocess, sys

out, mode, i = sys.argv[1], sys.argv[2], int(sys.argv[3])
vr = os.environ.get("VR_DIR", "test-nodes/vr")
gen = os.environ.get("VR_GENERATION", "paired-devnet")
chain = int(os.environ.get("M2_CHAIN_ID", "31337"))
keys_dir = f"{vr}/dev-keys"
if not os.path.exists(f"{keys_dir}/keys.json"):
    os.makedirs(vr, exist_ok=True)
    n = int(sys.argv[4]) if mode == "binding" else 4
    subprocess.run([sys.executable, "deploy/testnet/vr_dev_keys.py", keys_dir, str(n)], check=True)
keys = json.load(open(f"{keys_dir}/keys.json"))
root = json.load(open(f"test-nodes/root{i}/node-info.json"))
policy = {"network": "0x" + hashlib.sha256(("unicity.dev.vr." + gen).encode()).hexdigest(), "chainId": chain,
          "registry": "0xff00000000000000000000000000000000000003", "authorized": []}
if mode == "binding":
    n = int(sys.argv[4])
    ids = sorted(json.load(open(f"test-nodes/root{j}/node-info.json"))["nodeId"] for j in range(1, n + 1))
    ident = ids.index(root["nodeId"]) + 1
    payees = {}
    pf = f"{vr}/rotate-payees.json"
    if os.path.exists(pf):
        payees = json.load(open(pf))
    payees[str(i)] = "0x" + secrets.token_hex(20)
    json.dump(payees, open(pf, "w"))
    policy["authorized"].append({"action": "binding", "owner": keys["owners"][ident - 1]["address"], "id": ident,
                                 "rootNodeId": root["nodeId"], "rootKey": root["sigKey"], "payee": payees[str(i)]})
elif mode == "register":
    s = keys["signers"][0]["address"]
    policy["authorized"].append({"action": "register", "owner": s, "rootNodeId": root["nodeId"], "rootKey": root["sigKey"], "payee": s})
json.dump(policy, open(out, "w"), indent=1)
