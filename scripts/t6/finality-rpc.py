#!/usr/bin/env python3
"""Watch JSON-RPC finality and take wallet-style reads only at the finalized tag."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

CERT = re.compile(r'msg="certificate admitted".*?\bblock=(?:0x)?([0-9a-fA-F]{64})\s+height=(\d+)')
RESTORED = re.compile(r'msg="execution journal restored".*?\bblock=(?:0x)?([0-9a-fA-F]{64})\s+height=(\d+)')


class CheckError(Exception):
    pass


def request_json(url: str, body: dict | None = None):
    payload = None if body is None else json.dumps(body).encode()
    request = Request(url, data=payload, headers={"Content-Type": "application/json"} if payload else {})
    try:
        with urlopen(request, timeout=3) as response:
            return json.loads(response.read())
    except (OSError, URLError, json.JSONDecodeError) as exc:
        raise CheckError(f"request {url} failed: {exc}") from exc


def rpc(url: str, method: str, params: list):
    result = request_json(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if result.get("error"):
        raise CheckError(f"{method} returned JSON-RPC error: {result['error']}")
    if "result" not in result:
        raise CheckError(f"{method} returned no result")
    return result["result"]


def parse_int(text: str, field: str) -> int:
    try:
        return int(text, 16)
    except (ValueError, TypeError) as exc:
        raise CheckError(f"{field} is not an Ethereum hex quantity: {text!r}") from exc


def certified_from_log(path: Path) -> dict[int, set[str]]:
    found: dict[int, set[str]] = {}
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return found
    for line in lines:
        match = CERT.search(line) or RESTORED.search(line)
        if match:
            found.setdefault(int(match.group(2)), set()).add("0x" + match.group(1).lower())
    return found


def read_tip(status_url: str):
    status = request_json(status_url.rstrip("/") + "/api/v1/operator/status")
    tip = status.get("certifiedTip")
    if not isinstance(tip, dict) or not tip.get("hash"):
        raise CheckError(f"{status_url}: operator status has no certifiedTip")
    return int(tip["height"]), tip["hash"].lower()


def check_finalized(rpc_url: str, status_url: str, log_path: Path):
    final = rpc(rpc_url, "eth_getBlockByNumber", ["finalized", False])
    latest = rpc(rpc_url, "eth_getBlockByNumber", ["latest", False])
    if not isinstance(final, dict) or not isinstance(latest, dict):
        raise CheckError(f"{rpc_url}: finalized/latest RPC returned no block")
    final_height = parse_int(final.get("number"), "finalized.number")
    latest_height = parse_int(latest.get("number"), "latest.number")
    final_hash = str(final.get("hash", "")).lower()
    latest_hash = str(latest.get("hash", "")).lower()
    tip_height, tip_hash = read_tip(status_url)

    certs = certified_from_log(log_path)
    if final_height:
        known = certs.get(final_height, set())
        # Certificate logging follows the durable certification operation. Give a just-committed
        # certificate a short chance to reach the log before classifying the finalized RPC value.
        if final_hash not in known:
            time.sleep(0.15)
            certs = certified_from_log(log_path)
            known = certs.get(final_height, set())
        if final_hash not in known:
            raise CheckError(
                f"{rpc_url}: RPC finalized candidate {final_hash} at height {final_height} has no certificate-admitted log record"
            )
    if final_height > tip_height:
        raise CheckError(
            f"{rpc_url}: RPC finalized height {final_height} is ahead of certified parent {tip_height}/{tip_hash}"
        )
    if final_height == tip_height and final_hash != tip_hash:
        raise CheckError(
            f"{rpc_url}: finalized hash {final_hash} differs from current certified parent {tip_hash} at {tip_height}"
        )
    pending = None
    try:
        pending = rpc(rpc_url, "eth_getBlockByNumber", ["pending", False])
    except CheckError:
        # The pending tag is diagnostic only. The finalized tag and certified-tip checks above
        # are mandatory and fail closed.
        pass
    pending_hash = pending.get("hash", "").lower() if isinstance(pending, dict) else None
    candidate_ahead = latest_height > tip_height or (
        latest_height > 0 and latest_hash not in certs.get(latest_height, set())
    )
    if candidate_ahead and final_hash == latest_hash and latest_hash not in certs.get(latest_height, set()):
        raise CheckError(
            f"{rpc_url}: uncertified latest candidate {latest_hash} at height {latest_height} is exposed as finalized"
        )
    if pending_hash and pending_hash == final_hash and pending_hash not in certs.get(final_height, set()):
        raise CheckError(f"{rpc_url}: uncertified pending candidate {pending_hash} is exposed as finalized")
    return {
        "rpc": rpc_url,
        "finalizedHeight": final_height,
        "finalizedHash": final_hash,
        "latestHeight": latest_height,
        "latestHash": latest_hash,
        "certifiedTipHeight": tip_height,
        "certifiedTipHash": tip_hash,
        "pendingHash": pending_hash,
        "candidateAhead": candidate_ahead,
    }


def restore_certified(path: Path) -> bool:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return False
    epoch3 = any("handoff activated" in line and re.search(r"rootEpoch=3(?:\s|$)", line) for line in lines)
    cert3 = any(
        'msg="certificate admitted"' in line and re.search(r"rootEpoch=3(?:\s|$)", line)
        for line in lines
    )
    return epoch3 and cert3


def watch(args) -> int:
    urls = args.rpc_urls.split(",")
    status_urls = args.status_urls.split(",")
    logs = [Path(item) for item in args.log_paths.split(",")]
    if not (len(urls) == len(status_urls) == len(logs) == args.validators):
        raise CheckError("watch requires one RPC URL, status URL, and log path per validator")
    out = Path(args.out)
    ready = Path(args.ready_file)
    stop = Path(args.stop_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    ready.parent.mkdir(parents=True, exist_ok=True)
    counts = [0] * args.validators
    started = time.monotonic()
    restored_at = None
    with out.open("a", encoding="utf-8") as stream:
        print(json.dumps({"event": "watch-start", "validators": args.validators}), file=stream, flush=True)
        while not stop.exists():
            for index, (rpc_url, status_url, log_path) in enumerate(zip(urls, status_urls, logs), start=1):
                try:
                    sample = check_finalized(rpc_url, status_url, log_path)
                    sample.update({"event": "finality-sample", "validator": index, "unixTime": time.time()})
                    counts[index - 1] += 1
                    print(json.dumps(sample, separators=(",", ":")), file=stream, flush=True)
                except CheckError as exc:
                    restore_log = Path(args.restore_log)
                    restored = restore_certified(restore_log) if index == args.allow_offline_validator else False
                    if restored and restored_at is None:
                        restored_at = time.monotonic()
                    expected_offline = (
                        index == args.allow_offline_validator
                        and Path(args.offline_marker).exists()
                        and not restored
                    )
                    if expected_offline:
                        print(
                            json.dumps({"event": "expected-restore-outage", "validator": index, "error": str(exc), "unixTime": time.time()}),
                            file=stream,
                            flush=True,
                        )
                    elif restored_at is not None and index == args.allow_offline_validator and time.monotonic() - restored_at < 15:
                        print(
                            json.dumps({"event": "restore-rpc-starting", "validator": index, "error": str(exc), "unixTime": time.time()}),
                            file=stream,
                            flush=True,
                        )
                    else:
                        raise
            if not ready.exists() and all(count > 0 for count in counts):
                ready.write_text("ready\n", encoding="utf-8")
            time.sleep(args.interval)
        if time.monotonic() - started < args.minimum_runtime:
            raise CheckError(f"finality monitor ran only {time.monotonic() - started:.1f}s; need {args.minimum_runtime}s")
        if not restore_certified(Path(args.restore_log)):
            raise CheckError("H4 restore log lacks epoch-3 activation and a certified epoch-3 block")
        if any(count < args.minimum_samples for count in counts):
            raise CheckError(f"finality sample counts {counts} are below required {args.minimum_samples} per validator")
        print(json.dumps({"event": "watch-pass", "sampleCounts": counts, "unixTime": time.time()}), file=stream, flush=True)
    print(f"PASS: finalized-tag RPC never exposed an uncertified candidate as finalized; samples={counts}", flush=True)
    return 0


def call_uint(rpc_url: str, target: str, data: str) -> int:
    result = rpc(rpc_url, "eth_call", [{"to": target, "data": data}, "finalized"])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise CheckError(f"eth_call at finalized returned malformed result {result!r}")
    return int(result, 16)


def wallet(args) -> int:
    out = check_finalized(args.rpc_url, args.status_url, Path(args.log_path))
    tag = "finalized"
    wallet_balance = parse_int(rpc(args.rpc_url, "eth_getBalance", [args.wallet, tag]), "wallet balance")
    beneficiary_balance = parse_int(rpc(args.rpc_url, "eth_getBalance", [args.beneficiary, tag]), "beneficiary balance")
    treasury_balance = parse_int(rpc(args.rpc_url, "eth_getBalance", [args.treasury, tag]), "treasury balance")
    wuct_balance = call_uint(args.rpc_url, args.wuct, args.balance_of_data)
    wuct_supply = call_uint(args.rpc_url, args.wuct, args.total_supply_data)
    treasury_credit = call_uint(args.rpc_url, args.fee_collector, args.treasury_credit_data)
    if wuct_balance != args.expected_wuct:
        raise CheckError(f"finalized wallet WUCT balance is {wuct_balance}, expected {args.expected_wuct}")
    if wuct_supply != args.expected_supply:
        raise CheckError(f"finalized WUCT total supply is {wuct_supply}, expected {args.expected_supply}")
    if treasury_credit != args.expected_treasury_credit:
        raise CheckError(
            f"finalized treasury credit is {treasury_credit}, expected {args.expected_treasury_credit}"
        )
    if beneficiary_balance < args.minimum_beneficiary_balance:
        raise CheckError(
            f"finalized beneficiary balance {beneficiary_balance} is below claimed principal {args.minimum_beneficiary_balance}"
        )
    out.update(
        {
            "readTag": tag,
            "wallet": args.wallet,
            "walletNativeBalanceWei": str(wallet_balance),
            "beneficiary": args.beneficiary,
            "beneficiaryNativeBalanceWei": str(beneficiary_balance),
            "treasury": args.treasury,
            "treasuryNativeBalanceWei": str(treasury_balance),
            "wuct": args.wuct,
            "wuctBalance": str(wuct_balance),
            "wuctTotalSupply": str(wuct_supply),
            "feeCollector": args.fee_collector,
            "treasuryCredit": str(treasury_credit),
        }
    )
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(
        f"PASS: wallet, beneficiary, WUCT, and treasury reads used certified finalized block "
        f"{out['finalizedHeight']}/{out['finalizedHash']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--rpc-urls", required=True)
    w.add_argument("--status-urls", required=True)
    w.add_argument("--log-paths", required=True)
    w.add_argument("--validators", type=int, default=4)
    w.add_argument("--out", required=True)
    w.add_argument("--ready-file", required=True)
    w.add_argument("--stop-file", required=True)
    w.add_argument("--offline-marker", required=True)
    w.add_argument("--restore-log", required=True)
    w.add_argument("--allow-offline-validator", type=int, default=1)
    w.add_argument("--interval", type=float, default=0.5)
    w.add_argument("--minimum-runtime", type=float, default=10)
    w.add_argument("--minimum-samples", type=int, default=3)
    w.set_defaults(run=watch)

    s = sub.add_parser("wallet")
    for name in (
        "rpc-url",
        "status-url",
        "log-path",
        "wallet",
        "beneficiary",
        "treasury",
        "wuct",
        "balance-of-data",
        "total-supply-data",
        "fee-collector",
        "treasury-credit-data",
    ):
        s.add_argument("--" + name, required=True)
    s.add_argument("--expected-wuct", required=True, type=int)
    s.add_argument("--expected-supply", required=True, type=int)
    s.add_argument("--expected-treasury-credit", required=True, type=int)
    s.add_argument("--minimum-beneficiary-balance", required=True, type=int)
    s.add_argument("--out")
    s.set_defaults(run=wallet)
    args = parser.parse_args()
    try:
        return args.run(args)
    except CheckError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
