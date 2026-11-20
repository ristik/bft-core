#!/usr/bin/env python3
"""The P85 election pin (`signing-authority pos-policy`) of one authority of the PoS VR lane under SIGNING=authority (#1216).

  vr-pos-authority-policy.py <out> <i> [<id>]   authority i may sign the P85 possession proofs of identity <id> (default: the identity of its EVM
                                                node in the genesis identities; the joiner, not among them, is the next id) for the generation's
                                                election, on the generation's network word and chain

Environment: VR_DIR (default test-nodes/vr), VR_GENERATION (default paired-devnet), M2_CHAIN_ID (default 31337).
"""
import hashlib, json, os, sys

out, i = sys.argv[1], int(sys.argv[2])
vr = os.environ.get("VR_DIR", "test-nodes/vr")
gen = os.environ.get("VR_GENERATION", "paired-devnet")
chain = int(os.environ.get("M2_CHAIN_ID", "31337"))
dep = json.load(open(f"{vr}/contracts/deployment.json"))
idents = json.load(open(f"{vr}/genesis-identities.json"))
node = json.load(open(f"test-nodes/auth{i}/node-info.json"))["nodeId"]
if len(sys.argv) > 3:
    ident = int(sys.argv[3])
else:
    ids = [n for n, x in enumerate(idents, 1) if x["evmNodeId"] == node]
    ident = ids[0] if ids else len(idents) + 1
pin = {"network": "0x" + hashlib.sha256(("unicity.dev.vr." + gen).encode()).hexdigest(), "chainId": chain,
       "election": dep["election"], "ids": [ident]}
json.dump(pin, open(out, "w"), indent=1)
print(f"authority {i}: identity {ident}, election {dep['election']}")
