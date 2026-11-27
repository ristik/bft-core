#!/usr/bin/env python3
"""The registration policy (`signing-authority run --registration-policy`) of one authority of the VR lane under SIGNING=authority.

  vr-authority-policy.py <out> binding <i> <validators>   authority i (the EVM key of identity rank(root i)) may sign ONE binding: its identity's owner
                                                          stages a payee recorded in <vr dir>/rotate-payees.json (the first; the lane's `validator rotate`) or rotate-payees-all.json (VR_ROTATIONS of them)
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
    # VR_ROTATIONS (default 1) payees: the authority may sign that many bindings of its identity, one per payee (a lane that rotates once per handoff
    # needs one for each); rotate-payees.json keeps the first (what the Boundary step's `validator rotate` uses), rotate-payees-all.json all of them
    n_rot = int(os.environ.get("VR_ROTATIONS", "1"))
    all_payees = [ "0x" + secrets.token_hex(20) for _ in range(n_rot) ]
    payees[str(i)] = all_payees[0]
    json.dump(payees, open(pf, "w"))
    allf = f"{vr}/rotate-payees-all.json"
    every = json.load(open(allf)) if os.path.exists(allf) else {}
    every[str(i)] = all_payees
    json.dump(every, open(allf, "w"))
    for pay in all_payees:
        policy["authorized"].append({"action": "binding", "owner": keys["owners"][ident - 1]["address"], "id": ident,
                                     "rootNodeId": root["nodeId"], "rootKey": root["sigKey"], "payee": pay})
elif mode == "register":
    s = keys["signers"][0]["address"]
    policy["authorized"].append({"action": "register", "owner": s, "rootNodeId": root["nodeId"], "rootKey": root["sigKey"], "payee": s})
json.dump(policy, open(out, "w"), indent=1)
