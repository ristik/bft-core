#!/usr/bin/env python3
"""X4 #58 step A: the certified-snapshot shadow adapter (briefs/x4-shadow-campaign-design.md section 2).

    adapter.py run --rpc URL --deployment genesis/deployment.json --out DIR [--cadence 60] [--samples N] [--registry 0xff..02] [--anvil anvil]
    adapter.py replay --recorded DIR          recompute the reference over the recorded inputs and compare with the recorded contract outputs (offline)
    adapter.py report --out DIR               rebuild report.json / REPORT.md from observations.jsonl

At each scheduled sample it captures the complete bounded eligibility inputs at ONE finalized (certified) block, runs the real election on a disposable anvil fork
of exactly that state (impersonating the system caller only inside the fork), derives the expected output independently, and writes one observation row. It never
writes to the authoritative node. See fork.py for the safety checks, reference.py for the reference, report.py for the PASS / INCOMPLETE / FAIL rule."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as cap  # noqa: E402
import compare  # noqa: E402
import fork  # noqa: E402
import reference  # noqa: E402
import report  # noqa: E402
from chain import ReadOnlyRpc, RpcError  # noqa: E402

REGISTRY = "0xff00000000000000000000000000000000000002"


def freeze(o):
    """JSON-ready form of inputs: bytes become {"$b": hex}, tuples lists."""
    if isinstance(o, bytes):
        return {"$b": "0x" + o.hex()}
    if isinstance(o, dict):
        return {str(k) if not isinstance(k, int) else str(k): freeze(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [freeze(v) for v in o]
    return o


def thaw(o, int_keys=False):
    if isinstance(o, dict):
        if set(o) == {"$b"}:
            return bytes.fromhex(o["$b"][2:])
        return {(int(k) if int_keys and k.isdigit() else k): thaw(v, int_keys) for k, v in o.items()}
    if isinstance(o, list):
        return [thaw(v, int_keys) for v in o]
    return o


def load_inputs(path):
    inp = thaw(json.load(open(path)))
    inp["lotTable"] = {int(k): v for k, v in inp["lotTable"].items()}
    for ident in inp["identities"]:
        if ident["keyOwner"] is not None:
            ident["keyOwner"] = tuple(ident["keyOwner"])
    return inp


def input_digest(inp):
    return hashlib.sha256(json.dumps(freeze(inp), sort_keys=True).encode()).hexdigest()


def tool_versions(anvil, cast="cast"):
    def ver(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip().splitlines()[0]
        except (OSError, IndexError, subprocess.SubprocessError):
            return "unavailable"
    return {"python": platform.python_version(), "anvil": ver([anvil, "--version"]), "cast": ver([cast, "--version"])}


def observe(k, rpc, rpc_url, modules, registry, anvil, out_dir, fork_factory=fork.Fork):
    """One sample: capture, simulate, derive, compare. Returns the observation row. Raises on a gap (the caller records it)."""
    inp = cap.capture(rpc, "finalized", modules, registry)
    pin = {"number": inp["block"]["number"], "hash": inp["block"]["hash"], "chainId": inp["chainId"]}
    contract, evidence = fork.simulate(rpc_url, pin, modules, inp["origin"], inp["election"]["attemptCursor"], anvil=anvil, fork_factory=fork_factory)
    return build_row(k, inp, contract, evidence, out_dir)


def build_row(k, inp, contract, evidence, out_dir):
    try:
        expected = reference.expected(inp)
        ref_error = None
    except Exception as e:  # a reference that cannot derive the answer is a divergence to investigate, never a pass
        expected, ref_error = {"outcome": "ReferenceError"}, f"{type(e).__name__}: {e}"
    mism = compare.compare(contract, expected)
    if ref_error:
        mism.append({"field": "reference", "contract": None, "reference": ref_error})
    case = compare.case_of(contract, inp["incumbent"]["exposures"]) if contract.get("outcome") in ("NotDue", "Disabled", "NoCandidateRecorded", "Reserved") else "error"
    row = {"sample": k, "utc": datetime.now(timezone.utc).isoformat(), "chainId": inp["chainId"], "block": inp["block"], "origin": "0x" + inp["origin"].hex(),
           "inputDigest": input_digest(inp), "case": case, "contract": contract, "reference": expected, "verdict": "MISMATCH" if mism else "MATCH", "mismatches": mism,
           "fork": evidence}
    base = Path(out_dir) / "raw" / f"{k:05d}"
    if mism or case not in ("NotDue", "Disabled"):
        base.mkdir(parents=True, exist_ok=True)
        json.dump(freeze(inp), open(base / "inputs.json", "w"), indent=1, sort_keys=True)
        json.dump(contract, open(base / "contract.json", "w"), indent=1, sort_keys=True)
        json.dump(expected, open(base / "reference.json", "w"), indent=1, sort_keys=True)
        row["artifacts"] = str(base.relative_to(out_dir))
    return row


def write_report(out_dir, manifest, rows, scheduled, rules=None):
    cov = report.coverage(rows, scheduled, rules)
    first = next(({"sample": r["sample"], "mismatches": r["mismatches"][:5], "artifacts": r.get("artifacts")} for r in rows if r["verdict"] == "MISMATCH"), None)
    manifest = dict(manifest, firstBlock=min((r["block"]["number"] for r in rows if "block" in r), default=None),
                    lastBlock=max((r["block"]["number"] for r in rows if "block" in r), default=None))
    json.dump(dict(cov, firstFailure=first, manifest=manifest), open(Path(out_dir) / "report.json", "w"), indent=1, sort_keys=True)
    report.write_markdown(Path(out_dir) / "REPORT.md", manifest, cov, first)
    return cov


def seal(out_dir):
    lines = []
    for p in sorted(Path(out_dir).rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out_dir)}")
    (Path(out_dir) / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def cmd_run(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    dep = json.load(open(a.deployment))
    modules = {"election": dep["election"], "custody": dep["custody"], "evidence": dep["evidence"]}
    rpc = ReadOnlyRpc(a.rpc)
    manifest = {"format": "UNICITY_X4_SHADOW_MANIFEST/v1", "rpc": a.rpc, "chainId": rpc.chain_id(), "cadenceSeconds": a.cadence, "samples": a.samples,
                "modules": modules, "registry": a.registry, "startedUtc": datetime.now(timezone.utc).isoformat(), "tools": tool_versions(a.anvil),
                "fork": "anvil fork of the pinned finalized block; the election runs with the system caller impersonated inside the fork only (not ureth: no enshrined hook "
                        "or precompiles); a comparison, not consensus evidence"}
    json.dump(manifest, open(out / "manifest.json", "w"), indent=1, sort_keys=True)
    events = open(out / "events.jsonl", "a")
    rows = []
    t0 = time.monotonic()
    obs = open(out / "observations.jsonl", "w")
    taken = 0
    for k in range(a.samples):
        wait = t0 + k * a.cadence - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        if a.stop_file and Path(a.stop_file).exists():   # the driver ends the interval: the scheduled samples are those begun before the stop
            events.write(json.dumps({"utc": datetime.now(timezone.utc).isoformat(), "event": "stop-file", "sample": k}) + "\n")
            break
        taken += 1
        try:
            row = observe(k, rpc, a.rpc, modules, a.registry, a.anvil, out)
        except Exception as e:  # any failure of one sample is a recorded coverage gap with its cause, never a crash and never equality
            row = {"sample": k, "utc": datetime.now(timezone.utc).isoformat(), "verdict": "GAP", "case": "gap", "inputDigest": "", "gap": f"{type(e).__name__}: {e}"}
            events.write(json.dumps({"utc": row["utc"], "event": "gap", "sample": k, "detail": row["gap"]}) + "\n")
            events.flush()
        rows.append(row)
        obs.write(json.dumps(row, sort_keys=True) + "\n")
        obs.flush()
        print(f"sample {k}: {row['verdict']} {row['case']}", flush=True)
    manifest["finishedUtc"] = datetime.now(timezone.utc).isoformat()
    obs.close()      # everything the pack seals is on disk before it is hashed
    events.close()
    manifest["samplesScheduled"] = taken
    cov = write_report(out, manifest, rows, taken)
    seal(out)
    print(json.dumps({k: cov[k] for k in ("status", "scheduled", "accounted", "dueComparisons", "cases", "reasons")}, indent=1))
    return 0 if cov["status"] != report.STATUS_FAIL else 1


def cmd_replay(a):
    """Offline: recompute the reference from every recorded inputs.json and compare with the recorded contract output."""
    bad = 0
    for d in sorted(Path(a.recorded).glob("raw/*")):
        inp = load_inputs(d / "inputs.json")
        contract = json.load(open(d / "contract.json"))
        contract = thaw(contract) if False else contract
        mism = compare.compare(contract, reference.expected(inp))
        print(d.name, "MATCH" if not mism else f"MISMATCH {mism[:3]}")
        bad += bool(mism)
    return 1 if bad else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--rpc", required=True)
    r.add_argument("--deployment", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--cadence", type=float, default=60.0)
    r.add_argument("--samples", type=int, default=5, help="at most this many samples")
    r.add_argument("--stop-file", help="end the interval when this file exists (a scenario driver's end marker)")
    r.add_argument("--registry", default=REGISTRY)
    r.add_argument("--anvil", default="anvil")
    rp = sub.add_parser("replay")
    rp.add_argument("--recorded", required=True)
    a = p.parse_args(argv)
    return {"run": cmd_run, "replay": cmd_replay}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
