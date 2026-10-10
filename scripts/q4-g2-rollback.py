#!/usr/bin/env python3
"""Q4 #51 row G2: rollback of an executed, uncertified EVM block on live pairs.

A pair never un-commits: a block becomes canonical and final only with its certificate. A block that was built and executed but not certified is never
made canonical, and a different block is certified on the same parent. This tool reads what the pairs themselves report and logged:

  heads <eth-url>...                         one JSON line: every pair's latest and finalized block (number, hash)
  children --parent <hash> <log>:<mark>...   the blocks sealed on that parent since the marks, who sealed them and which pairs verified them VALID
  judge --dir <dir> --parent <hash> --height <n> --tx <hash> --sender <addr> --nonce <n> --url <eth-url>... --log <log>:<mark>...
                                             the verdict over the samples in <dir>/samples.jsonl, the pairs' final state and the logs

The logs are the shard nodes' debug logs (test-nodes/evm<i>/debug.log); a mark is the line count before the fault, so only the step's own lines count.
"""
import argparse
import json
import re
import sys
import urllib.request

SEALED = re.compile(r'msg="sealed execution payload" blockHash=(\w+) parentHash=(\w+) userTransactions=(\d+)')
VERIFIED = re.compile(r'msg="verified execution payload" .*?blockHash=(\w+) status=(\w+)')
ADMITTED = re.compile(r'msg="certificate admitted" block=(\w+) height=(\d+) round=(\d+)')


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        out = json.load(resp)
    if out.get("error"):
        raise RuntimeError(f"{method} at {url}: {out['error']}")
    return out.get("result")


def strip(h):
    return h[2:].lower() if h and h.startswith("0x") else (h or "").lower()


def block_ref(url, tag):
    b = rpc(url, "eth_getBlockByNumber", [tag, False])
    if b is None:
        return None
    return {"number": int(b["number"], 16), "hash": strip(b["hash"]), "parent": strip(b["parentHash"])}


def heads(urls):
    return [{"pair": i + 1, "latest": block_ref(u, "latest"), "finalized": block_ref(u, "finalized")} for i, u in enumerate(urls)]


def read_logs(specs):
    """specs: path:mark. Returns (sealed by parent, verified VALID by block, admitted by block); names are the log's directory (evm<i>)."""
    sealed, verified, admitted = {}, {}, {}
    for spec in specs:
        path, _, mark = spec.rpartition(":")
        name = path.split("/")[-2]
        with open(path, errors="replace") as f:
            for n, line in enumerate(f):
                if n < int(mark):
                    continue
                m = SEALED.search(line)
                if m:
                    sealed.setdefault(m.group(2), {})[m.group(1)] = {"hash": m.group(1), "sealedBy": name, "time": line[5:29], "userTransactions": int(m.group(3))}
                    continue
                m = VERIFIED.search(line)
                if m:
                    if m.group(2) == "VALID":
                        verified.setdefault(m.group(1), set()).add(name)
                    continue
                m = ADMITTED.search(line)
                if m:
                    admitted.setdefault(m.group(1), set()).add(name)
    return sealed, verified, admitted


def children(parent, specs):
    sealed, verified, admitted = read_logs(specs)
    out = []
    for c in sorted(sealed.get(strip(parent), {}).values(), key=lambda c: c["time"]):
        c["verifiedValidBy"] = sorted(verified.get(c["hash"], ()))
        c["admittedBy"] = sorted(admitted.get(c["hash"], ()))
        out.append(c)
    return out


def judge(a):
    parent, height = strip(a.parent), a.height
    pairs = len(a.url)
    names = sorted({spec.rpartition(":")[0].split("/")[-2] for spec in a.log})
    problems, notes = [], []

    # 1. while the certification requests were held, no pair moved: latest and finalized stay the parent
    samples = [json.loads(line) for line in open(f"{a.dir}/samples.jsonl") if line.strip()]
    held = [s for s in samples if s["phase"] == "held"]
    if len(held) < 3:
        problems.append(f"only {len(held)} samples while held")
    for s in held:
        for p in s["pairs"]:
            for tag in ("latest", "finalized"):
                ref = p[tag]
                if ref is None or ref["hash"] != parent or ref["number"] != height - 1:
                    problems.append(f"pair {p['pair']} {tag} was {ref} at {s['elapsed_s']}s while held; the parent is {height - 1} {parent}")
    # finalized never decreases on any pair, over every sample of the step
    last = {}
    for s in samples:
        for p in s["pairs"]:
            n = p["finalized"]["number"] if p["finalized"] else -1
            if n < last.get(p["pair"], -1):
                problems.append(f"pair {p['pair']} finalized went back {last[p['pair']]} -> {n} at {s['elapsed_s']}s ({s['phase']})")
            last[p["pair"]] = n

    # 2. after the release every pair holds the same certified block at the height, on the parent, finalized
    certified = set()
    for i, u in enumerate(a.url):
        b = block_ref(u, hex(height))
        fin = block_ref(u, "finalized")
        if b is None:
            problems.append(f"pair {i + 1} has no block {height}")
            continue
        certified.add(b["hash"])
        if b["parent"] != parent:
            problems.append(f"pair {i + 1} block {height} has parent {b['parent']}, not {parent}")
        if fin is None or fin["number"] < height:
            problems.append(f"pair {i + 1} finalized is {fin}, below {height}")
    if len(certified) != 1:
        problems.append(f"the pairs disagree on block {height}: {sorted(certified)}")
        certified_hash = None
    else:
        certified_hash = certified.pop()

    # 3. the abandoned blocks: sealed on the parent, not the certified one; at least one executed (verified VALID) by every pair and carrying the transaction
    kids = children(parent, a.log)
    abandoned = [c for c in kids if c["hash"] != certified_hash]
    executed = [c for c in abandoned if c["verifiedValidBy"] == names]
    with_tx = [c for c in executed if c["userTransactions"] >= 1]
    if not abandoned:
        problems.append("no block was sealed on the parent other than the certified one: nothing was rolled back")
    elif not executed:
        problems.append("no abandoned block was verified VALID by every pair")
    elif not with_tx:
        problems.append("no abandoned block that every pair executed carried a user transaction")
    for c in abandoned:
        if c["admittedBy"]:
            problems.append(f"abandoned block {c['hash']} has a certificate admitted by {c['admittedBy']}")
    if certified_hash and not any(c["hash"] == certified_hash for c in kids):
        notes.append(f"the certified block {certified_hash} was sealed outside the marked logs")
    # what each pair answers for an abandoned block by hash (recorded; a client may or may not expose a non-canonical block) and that none has it canonical
    by_hash = {}
    for c in abandoned:
        answers = []
        for i, u in enumerate(a.url):
            b = rpc(u, "eth_getBlockByHash", ["0x" + c["hash"], False])
            answers.append(None if b is None else int(b["number"], 16))
            canon = block_ref(u, hex(height))
            if canon and canon["hash"] == c["hash"]:
                problems.append(f"pair {i + 1} has the abandoned block {c['hash']} canonical at {height}")
        by_hash[c["hash"]] = answers

    # 4. the transaction is included once, in a certified canonical block at or above the height, and the sender's nonce advanced by exactly one
    receipts = set()
    for i, u in enumerate(a.url):
        r = rpc(u, "eth_getTransactionReceipt", [a.tx])
        if r is None:
            problems.append(f"pair {i + 1} has no receipt for {a.tx}")
            continue
        n = int(r["blockNumber"], 16)
        receipts.add((n, strip(r["blockHash"]), r["status"]))
        canon = block_ref(u, hex(n))
        if canon is None or canon["hash"] != strip(r["blockHash"]):
            problems.append(f"pair {i + 1}: the receipt's block {r['blockHash']} is not canonical at {n}")
        if n < height:
            problems.append(f"pair {i + 1}: the transaction is in block {n}, below the height {height}")
        if r["status"] != "0x1":
            problems.append(f"pair {i + 1}: receipt status {r['status']}")
        nonce = int(rpc(u, "eth_getTransactionCount", [a.sender, "latest"]), 16)
        if nonce != a.nonce + 1:
            problems.append(f"pair {i + 1}: sender nonce {nonce}, want {a.nonce + 1} (the transaction applied exactly once)")
    if len(receipts) > 1:
        problems.append(f"the pairs disagree on the receipt: {sorted(receipts)}")
    _, _, admitted = read_logs(a.log)
    for n, h, _ in receipts:
        if sorted(admitted.get(h, ())) != names:
            problems.append(f"the transaction's block {h} has no certificate admitted by every shard node (admitted by {sorted(admitted.get(h, ()))})")

    report = {
        "parent": {"number": height - 1, "hash": parent},
        "certified": {"number": height, "hash": certified_hash},
        "abandoned": abandoned,
        "abandonedByHashAnswers": by_hash,
        "heldSamples": len(held),
        "samples": len(samples),
        "transaction": {"hash": a.tx, "sender": a.sender, "nonce": a.nonce, "receipts": sorted(receipts)},
        "notes": notes,
        "problems": problems,
    }
    json.dump(report, open(f"{a.dir}/verdict.json", "w"), indent=1)
    print(f"parent {height - 1} {parent}; certified at {height}: {certified_hash}")
    for c in abandoned:
        cert = f"ADMITTED by {c['admittedBy']}" if c["admittedBy"] else "certificate admitted by none"
        print(f"abandoned {c['hash']}: sealed by {c['sealedBy']} at {c['time']}, {c['userTransactions']} user transaction(s), "
              f"verified VALID by {len(c['verifiedValidBy'])} of {len(names)} pairs, {cert}")
    print(f"while held ({len(held)} samples) every pair's latest and finalized stayed {height - 1}; finalized never decreased over {len(samples)} samples")
    if receipts:
        n, h, st = sorted(receipts)[0]
        print(f"transaction {a.tx}: one receipt, block {n} {h}, status {st}; sender nonce {a.nonce} -> {a.nonce + 1} on every pair")
    for p in problems:
        print("PROBLEM: " + p, file=sys.stderr)
    if not problems:
        print(f"rollback to the finalized head: {len(abandoned)} executed block(s) abandoned uncertified, {pairs} pairs agree on the certified block, nothing below the finalized head changed")
    return 1 if problems else 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("heads")
    h.add_argument("url", nargs="+")
    c = sub.add_parser("children")
    c.add_argument("--parent", required=True)
    c.add_argument("log", nargs="+")
    j = sub.add_parser("judge")
    j.add_argument("--dir", required=True)
    j.add_argument("--parent", required=True)
    j.add_argument("--height", type=int, required=True)
    j.add_argument("--tx", required=True)
    j.add_argument("--sender", required=True)
    j.add_argument("--nonce", type=int, required=True)
    j.add_argument("--url", action="append", required=True)
    j.add_argument("--log", action="append", required=True)
    a = ap.parse_args()
    if a.cmd == "heads":
        print(json.dumps(heads(a.url)))
        return 0
    if a.cmd == "children":
        print(json.dumps(children(a.parent, a.log)))
        return 0
    return judge(a)


if __name__ == "__main__":
    sys.exit(main())
