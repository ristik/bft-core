#!/usr/bin/env python3
"""Inject one D2-C process fault after B5 and relaunch from retained homes."""

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path.cwd()
ETH_BASE = 18545
ENGINE_BASE = 18551
P2P_BASE = 30401
SCENARIO, CERTIFIED, LAST_ROUND = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])


def rpc(port, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=2) as response:
        answer = json.load(response)
    if "error" in answer:
        raise RuntimeError(f"{method} on {port}: {answer['error']}")
    return answer["result"]


def head(i):
    return int(rpc(ETH_BASE + i - 1, "eth_blockNumber", []), 16)


def stop(kind, i, sig):
    pidfile = f"test-nodes/{kind}{i}/pid"
    pattern = "ubft shard-node run" if kind == "evm" else "reth.* node"
    pid = int(Path(pidfile).read_text().strip())
    subprocess.run(["bash", "-c", "source helper.sh; stop_pidfile \"$1\" \"$2\" \"$3\"",
                    "d2c-stop", pidfile, pattern, sig], check=True)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        stat = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        if not stat or stat.startswith("Z"):
            return
        time.sleep(0.1)
    raise RuntimeError(f"{kind}{i} process {pid} did not exit after SIG{sig}")


def start_reth(i):
    home = Path(f"test-nodes/reth{i}")
    jwt = f"test-nodes/evm{i}/jwt.hex"
    threshold = os.environ.get("D2C_PERSISTENCE_THRESHOLD", "64")
    fee_collector = os.environ["URETH_PIN_FEE_COLLECTOR"]
    args = [os.environ["URETH_BIN"], "node", "--chain", "test-nodes/evm-genesis-finalized-funded.json",
            "--datadir", str(home / "dd"), "--authrpc.jwtsecret", jwt,
            "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(ENGINE_BASE + i - 1),
            "--http", "--http.addr", "127.0.0.1", "--http.port", str(ETH_BASE + i - 1),
            "--http.api", "eth,net,web3,admin,debug", "--rpc.eth-proof-window", "64",
            "--port", str(P2P_BASE + i - 1), "--disable-discovery", "--ipcdisable",
            "--engine.persistence-threshold", threshold, "--builder.gaslimit", "30000000",
            "--unicity.fee-collector", fee_collector]
    with open(home / "reth.log", "a") as log:
        process = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    (home / "pid").write_text(f"{process.pid}\n")
    for _ in range(120):
        if process.poll() is not None:
            raise RuntimeError(f"reth{i} exited {process.returncode}; see {home / 'reth.log'}")
        try:
            rpc(ETH_BASE + i - 1, "eth_chainId", [])
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"reth{i} did not reopen its HTTP RPC")


def start_shard(i):
    command = ("source helper.sh; rootBoot=$(boot_node test-nodes/root1 26662); "
               f"start_one_evm_validator {i} 4 8 \"$rootBoot\" engine-api")
    subprocess.run(["bash", "-c", command], cwd=ROOT, check=True, env=os.environ.copy())


def restore_reth_mesh():
    for i in range(1, 5):
        for j in range(1, 5):
            if i == j:
                continue
            enode = rpc(ETH_BASE + j - 1, "admin_nodeInfo", [])["enode"]
            added = rpc(ETH_BASE + i - 1, "admin_addPeer", [enode])
            print(f"reth{i} admin_addPeer reth{j}: {added}", flush=True)
    for i in range(1, 5):
        for _ in range(40):
            peers = rpc(ETH_BASE + i - 1, "admin_peers", [])
            if peers:
                break
            time.sleep(0.25)
        if not peers:
            raise RuntimeError(f"reth{i} has no connected static peers after restart")
        print(f"reth{i} connected peers after relaunch: {len(peers)}", flush=True)


def wait_down(i):
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", ETH_BASE + i - 1), timeout=0.1):
                pass
        except OSError:
            return
        time.sleep(0.1)
    raise RuntimeError(f"reth{i} HTTP port did not close after signal")


def proof_fault():
    control = Path("test-nodes/proof-proxy/control.json")
    proxy_log = Path("test-nodes/proof-proxy/proxy.log")
    validator_log = Path("test-nodes/evm1/debug.log")

    def set_mode(mode, seconds=0):
        temp = control.with_suffix(".tmp")
        temp.write_text(json.dumps({"mode": mode, "until": time.time() + seconds}))
        temp.replace(control)

    if not control.exists() or not Path("test-nodes/proof-proxy/pid").exists():
        raise RuntimeError("proof scenario selected but the local proof proxy is not running")
    with validator_log.open("a") as stream:
        stream.write(f"D2C_PROOF_BOUNDARY scenario={SCENARIO} certified=B{CERTIFIED}\n")
    if SCENARIO == "proof-outage":
        seconds = int(os.environ.get("D2C_PROOF_OUTAGE_SECONDS", "10"))
        set_mode("outage", seconds)
        print(f"D2C[proof-outage] dropped proof RPC methods for {seconds}s", flush=True)
        time.sleep(seconds)
        set_mode("pass")
        drops = sum("drop method=" in line for line in proxy_log.read_text(errors="replace").splitlines())
        if drops == 0:
            raise RuntimeError("proof outage expired without dropping either requested method")
        print(f"D2C[proof-outage] restored forwarding after {drops} dropped proof calls", flush=True)
        return

    seconds = int(os.environ.get("D2C_PROOF_CORRUPT_SECONDS", "10"))
    before_head = head(1)
    set_mode("corrupt", seconds)
    print(f"D2C[proof-corrupt] corrupted proof RPC bytes for {seconds}s", flush=True)
    time.sleep(seconds)
    set_mode("pass")
    proxy_lines = proxy_log.read_text(errors="replace").splitlines()
    corrupted = [line for line in proxy_lines if "corrupt method=" in line]
    if not corrupted:
        raise RuntimeError("proof-corrupt window ended without mutating proof bytes")
    lines = validator_log.read_text(errors="replace").splitlines()
    marker_line = max(i for i, line in enumerate(lines) if "D2C_PROOF_BOUNDARY" in line)
    after = lines[marker_line + 1:]
    requests = [line for line in after if 'msg="submitting block certification request"' in line]
    named = [line for line in after if re.search(r"parent witness|proof|invalid|mismatch", line, re.I)
             and re.search(r"level=(ERROR|WARN)", line)]
    after_head = head(1)
    if requests:
        raise RuntimeError(f"validator 1 submitted {len(requests)} certification request(s) during corrupt evidence window")
    if after_head != before_head:
        raise RuntimeError(f"validator 1 reth head advanced during corrupt evidence window: {before_head} -> {after_head}")
    if not named:
        raise RuntimeError("corrupt proof bytes produced no named validator diagnostic")
    print(f"D2C[proof-corrupt] named failure observed; no certification request or reth head advance; "
          f"corrupted RPC calls={len(corrupted)}", flush=True)


def leader():
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        for i in range(1, 5):
            lines = Path(f"test-nodes/evm{i}/debug.log").read_text(errors="replace").splitlines()
            for line in reversed(lines[-100:]):
                round_match = re.search(r"(?:^|\s)round=(\d+)(?:\s|$)", line)
                if ('msg="submitting block certification request"' in line and "leader=true" in line
                        and round_match and int(round_match.group(1)) > LAST_ROUND):
                    print(f"D2C leader detected from logs: validator={i}; {line}", flush=True)
                    return i
        time.sleep(0.1)
    raise RuntimeError("no active leader proposal observed in shard logs within 40 seconds")


if SCENARIO == "leader-kill":
    targets, sig, kill_reth = [leader()], "KILL", True
elif SCENARIO == "pair-term":
    targets, sig, kill_reth = [1], "TERM", True
elif SCENARIO == "pair-kill":
    targets, sig, kill_reth = [1], "KILL", True
elif SCENARIO == "ureth-kill":
    targets, sig, kill_reth = [1], "KILL", True
elif SCENARIO == "all-kill":
    targets, sig, kill_reth = [1, 2, 3, 4], "KILL", True
elif SCENARIO in {"proof-outage", "proof-corrupt"}:
    proof_fault()
    raise SystemExit(0)
elif SCENARIO == "missing-body":
    import hashlib
    import struct
    import tempfile
    import subprocess
    # A tiny Go helper removes the certified B5 candidate record from validator 1's journal.
    output = subprocess.check_output(["go", "run", "scripts/d2c-journal-edit.go",
        "delete-certified-height", "test-nodes/execution-journals/evm1.db", "5"],
        text=True, stderr=subprocess.STDOUT)
    print(output, end="", flush=True)
    stop("evm", 1, "TERM")
    with open("test-nodes/evm1/debug.log", "a") as log:
        log.write(f"D2C_RESTART_BOUNDARY scenario={SCENARIO} certified=B{CERTIFIED}\n")
    try:
        start_shard(1)
        time.sleep(5)
        lines = Path("test-nodes/evm1/debug.log").read_text(errors="replace").splitlines()
        marker = max(i for i, line in enumerate(lines) if "D2C_RESTART_BOUNDARY" in line)
        restart = lines[marker + 1:]
        failures = [line for line in restart if "execution journal" in line.lower() and
                    ("error" in line.lower() or "failed" in line.lower() or "missing" in line.lower())]
        if failures:
            print(f"D2C[missing-body] journal rejected restart after certified B{CERTIFIED}: {failures[-1]}", flush=True)
            raise SystemExit(0)
        raise RuntimeError("restarted validator did not report missing certified candidate journal entry")
    except subprocess.CalledProcessError as exc:
        print(f"D2C[missing-body] restart refused after certified candidate body deletion: {exc}", flush=True)
        raise SystemExit(0)
    raise SystemExit(0)
elif SCENARIO == "wrong-genesis":
    stop("evm", 1, "TERM")
    stop("reth", 1, "TERM")
    wait_down(1)
    spec = json.loads(Path("test-nodes/evm-genesis-finalized-funded.json").read_text())
    spec["config"]["chainId"] = 31338
    wrong = Path("test-nodes/wrong-restart-genesis.json")
    wrong.write_text(json.dumps(spec))
    args = [os.environ["URETH_BIN"], "node", "--chain", str(wrong), "--datadir", "test-nodes/reth1/dd",
            "--authrpc.jwtsecret", "test-nodes/evm1/jwt.hex", "--authrpc.addr", "127.0.0.1",
            "--authrpc.port", str(ENGINE_BASE), "--http", "--http.addr", "127.0.0.1", "--http.port", str(ETH_BASE),
            "--http.api", "eth,net,web3,admin,debug", "--port", str(P2P_BASE), "--disable-discovery", "--ipcdisable",
            "--engine.persistence-threshold", os.environ.get("D2C_PERSISTENCE_THRESHOLD", "64"),
            "--builder.gaslimit", "30000000", "--unicity.fee-collector", os.environ["URETH_PIN_FEE_COLLECTOR"]]
    with open("test-nodes/reth1/reth.log", "a") as log:
        proc = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    (Path("test-nodes/reth1/pid")).write_text(f"{proc.pid}\n")
    try:
        for _ in range(20):
            if proc.poll() is not None:
                print(f"D2C[wrong-genesis] retained-state reth restart refused alternate genesis (exit {proc.returncode})", flush=True)
                raise SystemExit(0)
            time.sleep(0.5)
        raise RuntimeError("reth accepted alternate genesis on retained datadir")
    except SystemExit:
        raise
else:
    raise RuntimeError(f"no process fault hook for {SCENARIO}")

before = {i: head(i) for i in range(1, 5)}
print(f"D2C[{SCENARIO}] injection at certified B{CERTIFIED}; reth heads before={before}", flush=True)
for i in targets:
    if SCENARIO != "ureth-kill":
        stop("evm", i, sig)
    if kill_reth:
        stop("reth", i, sig)
        wait_down(i)

for i in targets:
    with open(f"test-nodes/evm{i}/debug.log", "a") as log:
        log.write(f"D2C_RESTART_BOUNDARY scenario={SCENARIO} certified=B{CERTIFIED}\n")
for i in range(1, 4):
    with open(f"test-nodes/root{i}/debug.log", "a") as log:
        log.write(f"D2C_RESTART_BOUNDARY scenario={SCENARIO} validator={','.join(map(str, targets))}\n")

immediate_after = {}
if kill_reth:
    for i in targets:
        start_reth(i)
    for i in range(1, 5):
        try:
            immediate_after[i] = head(i)
        except Exception:
            immediate_after[i] = "unavailable"
    restore_reth_mesh()
if SCENARIO != "ureth-kill":
    for i in targets:
        start_shard(i)

after = {}
for i in range(1, 5):
    try:
        after[i] = head(i)
    except Exception:
        after[i] = "unavailable"
lag = {i: max(0, CERTIFIED - h) if isinstance(h, int) else "unavailable" for i, h in after.items()}
if immediate_after:
    immediate_lag = {i: max(0, CERTIFIED - h) if isinstance(h, int) else "unavailable"
                     for i, h in immediate_after.items()}
    print(f"D2C[{SCENARIO}] reth heads immediately after relaunch={immediate_after}; "
          f"certified=B{CERTIFIED}; lag={immediate_lag}", flush=True)
print(f"D2C[{SCENARIO}] reth heads after peer restoration={after}; certified=B{CERTIFIED}; lag={lag}", flush=True)
