#!/usr/bin/env python3
"""Cross-repository fixture check between bft-core and unicity-pos-contracts.

Every file in xrepo/fixtures.json exists in both repositories and must be byte-identical. One side produces it (its own tests fail
when the committed file is not what it produces now); the other consumes a copy. Each repository's CI runs this script against a
checkout of the other at the commit it pins, so a change on either side fails until the copy is replaced and the pin moved.

  python3 xrepo/check.py --bft-core <bft-core checkout> --contracts <unicity-pos-contracts checkout> [--sync]

--sync copies each file from its producer's checkout over the consumer's copy instead of failing (a local helper; CI never passes it).
Exit status: 0 identical, 1 a difference or a missing file, 2 usage.
"""
import argparse
import json
import pathlib
import shutil
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bft-core", required=True)
    ap.add_argument("--contracts", required=True)
    ap.add_argument("--sync", action="store_true")
    a = ap.parse_args()
    bft, con = pathlib.Path(a.bft_core), pathlib.Path(a.contracts)
    manifest = json.loads((bft / "xrepo" / "fixtures.json").read_text())
    if manifest.get("format") != "UNICITY_XREPO_FIXTURES/v1":
        sys.exit("xrepo/fixtures.json: unknown format")
    problems, checked = [], 0
    for f in manifest["fixtures"]:
        producer = f["producer"]
        if producer not in ("contracts", "bft-core"):
            sys.exit(f"unknown producer {producer!r}")
        cpath = con / f["contracts"]
        for rel in f["bftCore"]:
            bpath = bft / rel
            src, dst = (cpath, bpath) if producer == "contracts" else (bpath, cpath)
            checked += 1
            if not src.is_file():
                problems.append(f"missing at its producer ({producer}): {src}")
                continue
            if dst.is_file() and dst.read_bytes() == src.read_bytes():
                continue
            if a.sync:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
                print(f"synced {dst} from {src}")
                continue
            state = "missing" if not dst.is_file() else "differs"
            problems.append(f"{state}: {dst}\n    is a copy of {src} (produced by {producer}; pair: {f['pair']})")
    if problems:
        print(f"cross-repository fixtures: {len(problems)} of {checked} copies are not in step:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        print("Regenerate at the producer, replace the copy, and move the pin of the repository that consumes it.", file=sys.stderr)
        sys.exit(1)
    print(f"cross-repository fixtures: {checked} copies identical")


if __name__ == "__main__":
    main()
