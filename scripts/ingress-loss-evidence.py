#!/usr/bin/env python3
"""Check the #998 lane's gate traces and root, shard and load logs."""

from datetime import datetime
from pathlib import Path
import json
import re
import sys


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def traces(evidence):
    for root in range(1, 6):
        path = evidence / f"root{root}" / "shard-trace.jsonl"
        with path.open() as log:
            # A concurrent writer may be appending the final line.
            yield [json.loads(line) for line in log if line.endswith("\n")]


def request(event):
    return event.get("direction") == "in" and event.get("type") == "request"


def audit_drops(roots, round_number, block_hash, rules):
    counts, drops = [], []
    quorum = False
    for root, events in enumerate(roots, 1):
        arrivals = [e for e in events if e.get("kind") == "in" and request(e)
                    and (e.get("partition"), e.get("round"), e.get("blockHash")) == (8, round_number, block_hash)]
        by_seq = {e["seq"]: e for e in events}
        for arrival in arrivals:
            # The gate emits the decision immediately after its arrival under the same lock.
            decision = by_seq.get(arrival["seq"] + 1, {})
            if (decision.get("kind") != "drop" or decision.get("rule") not in rules
                    or any(decision.get(k) != arrival[k] for k in
                           ("direction", "type", "partition", "round", "blockHash", "node"))):
                raise ValueError(f"root{root} arrival seq={arrival['seq']} round={round_number} lacks a matching drop")
            drops.append(decision["time"])
        counts.append(len(arrivals))
        quorum |= len({e["node"] for e in arrivals}) >= 3
    if not quorum:
        raise ValueError("no ingress root received a quorum of the selected request")
    return counts, min(drops, key=instant)


def select_drop(roots):
    candidates = {(e["round"], e["blockHash"]) for events in roots for e in events
                  if e.get("rule") == "evm-loss" and e.get("kind") == "drop"
                  and e.get("partition") == 8 and request(e) and e.get("blockHash")}
    for round_number, block_hash in sorted(candidates):
        try:
            _, first_drop = audit_drops(roots, round_number, block_hash, {"evm-loss"})
        except ValueError:
            continue
        print(round_number, block_hash, first_drop, sep="\t")
        return
    raise ValueError("no fully dropped request quorum")


def log_records(paths, message):
    for path in sorted(paths):
        with path.open() as log:
            for line in log:
                if message in line:
                    yield dict(re.findall(r'([\w.]+)=("[^"]*"|\S+)', line))


def timeout_proposals(nodes, after):
    for record in log_records(nodes.glob("root*/debug.log"), 'msg="broadcast proposal"'):
        if re.search(r"\b00000008->timeout\b", record.get("data", "")) and instant(record["time"]) > after:
            yield record


def first(records, describe):
    record = min(records, key=lambda line: instant(line["time"]), default=None)
    if record is None:
        raise ValueError(f"missing {describe}")
    return record


def verify_recovery(evidence, roots, nodes, lost_round, lost_hash, parent, fresh_hash, tx, repeat_root):
    counts, first_drop = audit_drops(roots, lost_round, lost_hash, {"evm-loss", "lost-round"})
    first_drop = instant(first_drop)
    proposal = first((r for r in timeout_proposals(nodes, first_drop) if r["round"] == repeat_root), "EVM T2 proposal")
    commits = [r for r in log_records(nodes.glob("root*/debug.log"), 'msg="shard certificate committed"')
               if r.get("shard.partition") == "8"]
    retained = [r for r in log_records(nodes.glob("root*/debug.log"), 'msg="shard request retained"')
                if r.get("shard.partition") == "8"]
    if any(r.get("blockHash") == lost_hash for r in commits + retained) or lost_hash == fresh_hash:
        raise ValueError("the dropped candidate appeared in retention or certification")

    repeat = first((r for r in commits if r.get("sealRound") == repeat_root and r.get("blockHash") == parent
                    and r.get("nextRound") == str(lost_round + 1)), "committed repeat authorizing the next shard round")
    fresh = first((r for r in commits if r.get("blockHash") == fresh_hash
                   and r.get("nextRound") == str(lost_round + 2)), "fresh EVM certificate")
    quorum = first((r for r in retained if r.get("blockHash") == fresh_hash
                    and r.get("requestRound") == str(lost_round + 1)), "fresh EVM request quorum")
    shard_logs = list(nodes.glob("evm*/debug.log"))
    sealed = first((r for r in log_records(shard_logs, 'msg="sealed execution transaction"')
                    if r.get("blockHash") == lost_hash and r.get("transactionHash") == tx),
                   "seeded transaction in the dropped execution candidate")
    signed = first((r for r in log_records(shard_logs, 'msg="certification request signed"')
                    if r.get("round") == str(lost_round + 1) and r.get("rootRound") == repeat_root
                    and r.get("parentHash") == parent and r.get("childHash") == fresh_hash),
                   "fresh EVM request signed under the committed repeat")
    proposal_time = instant(proposal["time"])
    repeat_time = instant(repeat["time"])
    fresh_time = instant(fresh["time"])
    if not instant(sealed["time"]) <= first_drop < proposal_time < repeat_time < instant(signed["time"]) < instant(quorum["time"]) < fresh_time:
        raise ValueError("dropped candidate, repeat, fresh authorization, retention and certification are out of order")

    recovery_count = 0
    for i, partition in enumerate((9, 9, 10)):
        sent = set(re.findall(r"batch sent .* state=([0-9a-f]{64})", (evidence / f"load{i}.log").read_text()))
        arrivals = {instant(e["time"]) for events in roots for e in events if e.get("kind") == "in"
                    and request(e) and e.get("partition") == partition and e.get("blockHash") in sent}
        before_proposal = [t for t in arrivals if first_drop <= t < proposal_time]
        if not before_proposal:
            raise ValueError(f"load{i} supplied no f8batch requests to ingress during the loss before the T2 proposal")
        during_recovery = sum(repeat_time <= t < fresh_time for t in arrivals)
        recovery_count += during_recovery
        print(f"load{i} batch ingress during loss before T2={len(before_proposal)} during repeat recovery={during_recovery}")
    if not recovery_count:
        raise ValueError("no f8batch request reached ingress between the repeat commit and fresh EVM certificate")
    print(f"all selected arrivals dropped per root={counts} firstDrop={first_drop.isoformat()}")
    print(f"T2={proposal['time']} repeatRoot={repeat_root} repeat={repeat['time']} "
          f"authorized={signed['time']} retained={quorum['time']} freshRoot={fresh['sealRound']} certified={fresh['time']}")


def main(action, path, *args):
    path = Path(path)
    if action == "proposal":
        print(first(timeout_proposals(path, instant(args[0])), "EVM T2 proposal")["round"])
        return
    roots = list(traces(path))
    if action == "select":
        select_drop(roots)
    elif action == "audit-drops":
        counts, _ = audit_drops(roots, int(args[0]), args[1], {"evm-loss", "lost-round"})
        print(f"all selected arrivals dropped per root={counts}")
    elif action == "verify":
        verify_recovery(path, roots, Path(args[0]), int(args[1]), *args[2:])
    else:
        raise ValueError(f"unknown assertion {action}")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (ValueError, OSError) as err:
        sys.exit(f"ingress-loss evidence: {err}")
