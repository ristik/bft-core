"""Capture of the complete bounded eligibility inputs at ONE pinned block (design section 2). Every read is an eth_call/eth_getStorageAt/eth_getCode at
the block hash's number; the block number, hash and state root are recorded so a verifier can re-derive the same reads against any node. An untrusted RPC is a
hint, not an authority: nothing here is trusted beyond being recorded. A failed read raises CaptureGap (a recorded coverage gap, never equality)."""
import abi
from abi import calldata, words, dyn_array
from chain import RpcError
from keccak import keccak256

ORIGIN_SLOT = keccak256(b"unicity.seal-registry/origin.identity")
ZERO32 = b"\0" * 32


class CaptureGap(Exception):
    pass


class Reader:
    def __init__(self, rpc, block):
        self.rpc, self.block = rpc, block

    def w(self, to, sig, *args):
        try:
            return words(self.rpc.call(to, calldata(sig, *args), self.block))
        except (RpcError, AssertionError, ValueError) as e:
            raise CaptureGap(f"{to} {sig}{args}: {e}") from e

    def raw(self, to, sig, *args):
        try:
            return self.rpc.call(to, calldata(sig, *args), self.block)
        except RpcError as e:
            raise CaptureGap(f"{to} {sig}{args}: {e}") from e

    def one(self, to, sig, *args):
        return self.w(to, sig, *args)[0]

    def b32(self, to, sig, *args):
        return self.one(to, sig, *args).to_bytes(32, "big")


def _delegation(raw: bytes):
    """election.delegation(id, generation) -> (Delegation binding, bytes32 bindingHash, uint64 nextNonce); the binding tuple is dynamic."""
    w = words(raw[:96])
    tup = w[0]
    binding_hash = w[1].to_bytes(32, "big")
    head = [int.from_bytes(raw[tup + 32 * i:tup + 32 * (i + 1)], "big") for i in range(5)]
    root_key = abi.dyn_bytes(raw, tup + head[1])
    evm_key = abi.dyn_bytes(raw, tup + head[3])
    return {"bindingHash": binding_hash, "rootKeyHash": keccak256(root_key), "evmKeyHash": keccak256(evm_key), "payee": abi.addr(head[4])}


def capture(rpc, block_tag, modules, registry, evm_version="", ):
    """modules: dict of 0x addresses: election, custody, evidence (the deployment file's fields). Returns the inputs dict (bytes for hash words)."""
    blk = rpc.block(block_tag)
    number = int(blk["number"], 16)
    tag = hex(number)
    r = Reader(rpc, tag)
    el, cu, ev = modules["election"], modules["custody"], modules["evidence"]
    inp = {"format": "UNICITY_X4_SHADOW_INPUTS/v1", "chainId": rpc.chain_id(),
           "block": {"number": number, "hash": blk["hash"], "stateRoot": blk["stateRoot"], "timestamp": int(blk["timestamp"], 16)},
           "modules": dict(modules, registry=registry)}
    inp["origin"] = rpc.storage(registry, ORIGIN_SLOT, tag)
    selection = abi.addr(r.one(el, "selection()"))
    policy_src = abi.addr(r.one(el, "policySource()"))
    roots = abi.addr(r.one(el, "roots()"))
    inp["modules"].update(selection=selection, policySource=policy_src, roots=roots)
    p = r.w(el, "params()")
    inp["election"] = {
        "address": el, "initialized": bool(r.one(el, "initialized()")), "network": r.b32(el, "network()"),
        "params": dict(zip(("nMin", "nTarget", "nMax", "maxM", "distNum", "distDen", "cadenceRounds", "cadenceSeconds"), p)),
        "anchorProgress": r.one(el, "anchorProgress()"), "anchorTime": r.one(el, "anchorTime()"), "attemptProgress": r.one(el, "attemptProgress()"),
        "attemptTime": r.one(el, "attemptTime()"), "attemptCursor": r.one(el, "attemptCursor()"), "openResult": r.b32(el, "openResult()")}
    inp["clock"] = {"recordCount": r.one(roots, "recordCount()"), "custodyCursor": r.one(cu, "recordCursor()"), "progress": r.one(roots, "progress()"),
                    "ucTime": r.one(roots, "ucTime()")}
    lim = r.w(cu, "limits()")
    last = r.b32(cu, "lastAckedAssignment()")
    inp["custody"] = {"bondUnit": r.one(cu, "bondUnit()"), "minBond": r.one(cu, "minBond()"), "nextStakingID": r.one(cu, "nextStakingID()"),
                      "lastAckedAssignment": last, "limits": dict(zip(("vMax", "lMax", "rMax", "maxBatch"), lim))}
    inp["policy"] = {"currentPolicyID": r.one(policy_src, "currentPolicyID()")}
    lot_table = {}

    def lot(lot_id):
        if lot_id not in lot_table:
            lw = r.w(cu, "lots(uint256)", lot_id)
            lot_table[lot_id] = {"id": lw[0], "generation": lw[1], "remaining": lw[3], "category": lw[5], "refCount": lw[7]}
        return lot_table[lot_id]

    identities = []
    for ident in range(1, inp["custody"]["nextStakingID"] + 1):
        row = {"id": ident, "indexed": bool(r.one(el, "isIndexed(uint64)", ident))}
        pw = r.w(cu, "positions(uint64)", ident)
        row["position"] = {"owner": pw[0], "withdrawal": pw[1], "rootKeyHash": pw[2].to_bytes(32, "big"), "stagedRootKeyHash": pw[3].to_bytes(32, "big"),
                           "generation": pw[4], "roleNonce": pw[5], "openLots": pw[6], "lotCount": pw[7], "retirementRequested": bool(pw[8])}
        row["excluded"] = bool(r.one(ev, "excluded(uint64)", ident))
        row["staged"], row["keyOwner"], row["lots"] = None, None, []
        if row["indexed"] and pw[0] != 0:
            gen = pw[4]
            st = _delegation(r.raw(el, "delegation(uint64,uint64)", ident, gen))
            if st["bindingHash"] != ZERO32:
                row["staged"] = st
                ko = r.w(cu, "keyOwner(bytes32)", st["evmKeyHash"])
                row["keyOwner"] = (ko[0], ko[1])
            lot_ids = dyn_array(r.w(cu, "generationLots(uint64,uint64)", ident, gen), 0)
            row["lots"] = [lot(x) for x in lot_ids]
        identities.append(row)
    inp["identities"] = identities
    # the incumbent: the last acknowledged assignment, its committed members, the digests custody committed, the policy terms it captured
    a = r.w(cu, "assignments(bytes32)", last)
    ex_ids = dyn_array(r.w(cu, "assignmentExposures(bytes32)", last), 0)
    exps = []
    for eid in ex_ids:
        e = r.w(cu, "exposures(bytes32)", eid.to_bytes(32, "big"))
        lots = dyn_array(r.w(cu, "exposureLots(bytes32)", eid.to_bytes(32, "big")), 0)
        for x in lots:
            lot(x)
        exps.append({"id": e[1], "generation": e[2], "weight": e[3], "rawWeight": e[4], "rootKeyHash": e[5].to_bytes(32, "big"), "evmKeyHash": e[6].to_bytes(32, "big"),
                     "payee": abi.addr(e[7]), "lots": lots})
    inp["incumbent"] = {"assignmentID": last, "lineage": a[1].to_bytes(32, "big"), "rootEpoch": a[2], "evmEpoch": a[3], "exposureDigest": a[13].to_bytes(32, "big"),
                        "keyDigest": a[14].to_bytes(32, "big"), "policyID": a[15], "exposures": exps,
                        "policyTerms": r.w(cu, "policyTerms(bytes32)", last)}
    inp["lotTable"] = lot_table
    # the module digest inputs of K's commitment, in the contracts' order: custody, its code hash, election, ..., evidence, selection, policy source, roots
    digest_inputs = []
    for addr_ in (cu, el, ev, selection, policy_src):
        code = rpc.code(addr_, tag)
        if not code:
            raise CaptureGap(f"no code at {addr_}")
        digest_inputs += [addr_, keccak256(code)]
    digest_inputs.append(roots)
    inp["moduleDigestInputs"] = digest_inputs
    return inp
