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
    # M1 ureth P2P is intentionally a no-op (ureth#33/#34). Transactions are
    # seeded into each local mempool directly, so peer connectivity is not a
    # relaunch premise and must not gate the fault scenario.
    print("D2C reth relaunch: skipping peer-connectivity check (M1 P2P is a no-op)", flush=True)


def record_expected_refusal(scenario, detail):
    Path("test-nodes/d2c-expected-refusal").write_text(f"{scenario}: {detail}\n")


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

    def set_mode(mode, seconds=0, **extra):
        temp = control.with_suffix(".tmp")
        temp.write_text(json.dumps({"mode": mode, "until": time.time() + seconds, **extra}))
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
        drops = sum(" drop " in line for line in proxy_log.read_text(errors="replace").splitlines())
        if drops == 0:
            raise RuntimeError("proof outage expired without dropping either requested method")
        print(f"D2C[proof-outage] restored forwarding after {drops} dropped proof calls", flush=True)
        deadline = time.monotonic() + int(os.environ.get("D2C_PROOF_RECOVERY_TIMEOUT", "120"))
        association = None
        agreement = None
        admission_re = re.compile(
            r'msg="certificate admitted" source=peer_recovery block=([0-9a-f]{64}) '
            r'height=([1-9][0-9]*) round=([0-9]+) rootRound=([0-9]+)(?:\s|$)'
        )
        while time.monotonic() < deadline:
            validator_lines = validator_log.read_text(errors="replace").splitlines()
            for line in reversed(validator_lines):
                match = admission_re.search(line)
                if match:
                    block, height, shard_round, root_round = match.groups()
                    association = {"block": block, "height": int(height),
                                   "round": shard_round, "rootRound": root_round}
                    break
            if association:
                try:
                    tags = {tag: rpc(ETH_BASE, "eth_getBlockByNumber", [tag, False])
                            for tag in ("latest", "safe", "finalized")}
                    canonical = [tags[tag]["hash"].removeprefix("0x").lower() for tag in tags]
                    numbers = [int(tags[tag]["number"], 16) for tag in tags]
                    at_height = rpc(ETH_BASE, "eth_getBlockByNumber", [hex(association["height"]), False])
                    association_block = rpc(ETH_BASE, "eth_getBlockByHash",
                                             ["0x" + association["block"], False])
                    if (len(set(canonical)) == 1 and min(numbers) >= association["height"]
                            and at_height is not None and association_block is not None
                            and at_height["hash"].removeprefix("0x").lower() == association["block"]
                            and association_block["hash"].removeprefix("0x").lower() == association["block"]):
                        agreement = {"hash": canonical[0], "height": numbers[0]}
                        break
                except (OSError, RuntimeError, KeyError, TypeError, ValueError):
                    pass
            time.sleep(0.5)
        if not association:
            raise RuntimeError("timed out waiting for positive-height peer_recovery certificate association")
        if not agreement:
            raise RuntimeError(f"timed out waiting for latest/safe/finalized agreement on associated block "
                                f"B{association['height']} {association['block']}")
        print(f"D2C[proof-outage] peer-recovery association confirmed: block={association['block']} "
              f"height={association['height']} round={association['round']} "
              f"rootRound={association['rootRound']}; latest/safe/finalized agree at "
              f"B{agreement['height']} {agreement['hash']}", flush=True)
        return

    timeout = int(os.environ.get("D2C_PROOF_CORRUPT_TIMEOUT", "60"))
    lines = validator_log.read_text(errors="replace").splitlines()
    known_parents = set()
    known_numbers = set()
    for line in lines:
        match = re.search(r'msg="parent witness snapshot" cache=(?:miss|hit).*?parentNumber=(\d+) parentHash=([0-9a-f]{64})', line)
        if match:
            known_numbers.add(int(match.group(1)))
            known_parents.add(match.group(2))
        match = re.search(r'msg="acquired certified parent registry witness".*?parentNumber=(\d+) parentHash=([0-9a-f]{64})', line)
        if match:
            known_numbers.add(int(match.group(1)))
            known_parents.add(match.group(2))

    def selector(line):
        match = re.search(r'parent=([^ ]+)', line)
        if not match:
            return None
        value = match.group(1).lower()
        hash_value = value.removeprefix("0x")
        if re.fullmatch(r"[0-9a-f]{64}", hash_value):
            return {"hash": hash_value, "number": None}
        if value.startswith("0x"):
            try:
                return {"hash": None, "number": int(value, 16)}
            except ValueError:
                pass
        return None

    proxy_activation = time.time()
    prior_refs = set()
    for line in proxy_log.read_text(errors="replace").splitlines():
        try:
            log_epoch = float(line.split(" ", 1)[0])
        except (ValueError, IndexError):
            continue
        ref_match = re.search(r"\bparent=([^ ]+)", line)
        if log_epoch <= proxy_activation and " fetch " in line and ref_match:
            prior = ref_match.group(1).lower().removeprefix("0x")
            if re.fullmatch(r"[0-9a-f]{64}", prior):
                prior_refs.add(prior)
            else:
                try:
                    prior_refs.add(f"height:{int(prior, 16)}")
                except ValueError:
                    prior_refs.add(prior)
    set_mode("hold", 120, hold=True, release=[], pass_release=[])
    print(f"D2C[proof-corrupt] holding proof fetches until an uncached parent request is selected; "
          f"cached parents={len(known_parents)}", flush=True)
    deadline = time.monotonic() + timeout
    target = None
    released_cached = []
    while time.monotonic() < deadline:
        for line in proxy_log.read_text(errors="replace").splitlines():
            if " fetch " not in line or " mode=hold" not in line:
                continue
            trace_match = re.search(r"\btrace=([0-9]+)", line)
            ref = selector(line)
            if not trace_match or not ref:
                continue
            ref_key = ref["hash"] or f"height:{ref['number']}"
            is_known = (ref["hash"] in known_parents if ref["hash"] is not None
                        else ref["number"] in known_numbers)
            if ref_key in prior_refs:
                is_known = True
            if not is_known:
                target = {"trace": trace_match.group(1), "ref": ref, "line": line}
                break
            # Let already-verified cached parents continue normally while keeping future
            # requests behind the barrier.
            if trace_match.group(1) not in released_cached:
                released_cached.append(trace_match.group(1))
                set_mode("hold", 120, hold=True, release=released_cached,
                         pass_release=released_cached)
        if target:
            break
        time.sleep(0.05)
    if not target:
        set_mode("pass")
        raise RuntimeError(f"no held proof request for an uncached parent appeared within {timeout}s")

    ref_text = target["ref"]["hash"] or f"height:{target['ref']['number']}"
    corrupt_refs = [ref_text]
    with validator_log.open("a") as stream:
        stream.write(f"D2C_PROOF_CORRUPT_RELEASE parent={ref_text} trace={target['trace']}\n")
    set_mode("corrupt", 120, hold=True, release=released_cached + [target["trace"]],
             pass_release=released_cached, corrupt_refs=corrupt_refs)
    print(f"D2C[proof-corrupt] corrupting and promptly releasing all proof RPCs for uncached parent={ref_text}; "
          f"trace={target['trace']}; fetch={target['line']}", flush=True)

    mutation_deadline = time.monotonic() + 20
    mutations = []
    while time.monotonic() < mutation_deadline:
        mutations = [line for line in proxy_log.read_text(errors="replace").splitlines()
                     if " mutate " in line and "response_sha256=" in line
                     and (candidate := selector(line)) == target["ref"]]
        if (any(f"trace={target['trace']} " in line for line in mutations)
                and any("method=eth_getProof " in line for line in mutations)):
            break
        time.sleep(0.05)
    target_mutation = next((line for line in mutations if f"trace={target['trace']} " in line), None)
    proof_mutation = next((line for line in mutations if "method=eth_getProof " in line), None)
    if not target_mutation or not proof_mutation:
        set_mode("pass")
        raise RuntimeError(f"uncached parent {ref_text} did not promptly return both a mutated selected response "
                           f"and a mutated matching eth_getProof response: {mutations[-4:]}")
    mutated_hash = re.search(r"response_sha256=([0-9a-f]{64})", target_mutation)
    if not mutated_hash:
        set_mode("pass")
        raise RuntimeError("proxy mutation log lacks the corrupted response digest")
    print(f"D2C[proof-corrupt] mutated responses confirmed promptly: {target_mutation}; {proof_mutation}", flush=True)

    # Require a validation-class failure tied to this exact parent. An unavailable or
    # deadline diagnostic means another proof call was held too long and does not prove
    # that the mutated response reached verification.
    reject_deadline = time.monotonic() + 30
    rejected = None
    while time.monotonic() < reject_deadline:
        lines = validator_log.read_text(errors="replace").splitlines()
        marker = f"D2C_PROOF_CORRUPT_RELEASE parent={ref_text} trace={target['trace']}"
        release_index = max((i for i, line in enumerate(lines) if marker in line), default=-1)
        for line in reversed(lines[release_index + 1:]):
            # Peer catch-up can wrap a concrete invalid-proof error in an outer
            # `certified input unavailable` message. Accept only the specific
            # validation diagnostic, and only when it names this requested
            # parent; generic unavailable/deadline errors still do not qualify.
            specific_invalid = re.search(
                r"header hash mismatch|registryproof:.*invalid|parent registry witness invalid|"
                r"invalid peer candidate: fetched block binding",
                line, re.I,
            )
            expected_parent = target["ref"].get("hash")
            tied_to_parent = expected_parent and expected_parent.lower() in line.lower()
            if (("level=ERROR" in line or "level=WARN" in line) and specific_invalid
                    and tied_to_parent):
                rejected = line
                break
        if rejected:
            break
        time.sleep(0.1)
    lines = validator_log.read_text(errors="replace").splitlines()
    marker = f"D2C_PROOF_CORRUPT_RELEASE parent={ref_text} trace={target['trace']}"
    release_index = max((i for i, line in enumerate(lines) if marker in line), default=-1)
    post_release = lines[release_index + 1:]
    if not rejected:
        set_mode("pass")
        raise RuntimeError(f"mutated uncached proof parent={ref_text} had no rejection diagnostic")
    parent_hash = target["ref"]["hash"]
    if parent_hash is None:
        # If the request used a block number selector, resolve its canonical hash for
        # exact downstream correlation.
        block = rpc(ETH_BASE, "eth_getBlockByNumber", [hex(target["ref"]["number"]), False])
        parent_hash = block["hash"].removeprefix("0x").lower() if block else None
    if not parent_hash:
        set_mode("pass")
        raise RuntimeError(f"cannot resolve held proof parent {ref_text} to a canonical block hash")
    # Error strings can identify the parent as `parent is 0x<hash>` rather than
    # a structured `parentHash=<hash>` field. A word boundary before the first
    # hex digit does not match there because the preceding `0` is also a word
    # character, so correlate by the normalized hash substring itself.
    pattern = re.compile(re.escape(parent_hash), re.I)
    if not pattern.search(rejected):
        set_mode("pass")
        raise RuntimeError(
            "invalid-proof diagnostic lacks the selected parent hash and cannot be correlated: "
            f"{rejected}; needed parentHash, proof request trace, rejection class, and event time"
        )
    parent_snapshots = {}
    for line in post_release:
        if 'msg="parent witness snapshot"' in line and pattern.search(line):
            snapshot_id = re.search(r"\bsnapshotID=([0-9a-f]{64})\b", line)
            if snapshot_id:
                parent_snapshots[snapshot_id.group(1)] = line
    dependent_signatures = [line for line in post_release
                            if 'msg="certification request signed"' in line
                            and (pattern.search(line) or any(
                                re.search(rf"\bsnapshotID={re.escape(snapshot_id)}\b", line)
                                for snapshot_id in parent_snapshots))]
    derivations = [line for line in post_release
                   if 'msg="derived root input from parent witness"' in line and pattern.search(line)]
    if parent_snapshots or dependent_signatures or derivations:
        set_mode("pass")
        raise RuntimeError(f"mutated uncached parent {parent_hash} reached a verified derivation or signature: "
                            f"snapshotIDs={sorted(parent_snapshots)} dependent={dependent_signatures[-1:]}; "
                            f"derivation={derivations[-1:]}")
    cached_progress = [line for line in post_release if 'msg="parent witness snapshot" cache=hit' in line]
    pass_marker = f"D2C_PROOF_CORRUPT_PASS parent={parent_hash} trace={target['trace']}\n"
    with validator_log.open("a") as stream:
        stream.write(pass_marker)
    set_mode("pass")
    result = {"parentHash": parent_hash, "trace": target["trace"],
              "responseSHA256": mutated_hash.group(1), "invalidDiagnostic": rejected,
              "snapshotIDs": sorted(parent_snapshots), "cachedProgress": len(cached_progress)}
    Path("test-nodes/d2c-proof-corrupt-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"D2C[proof-corrupt] invalid-proof rejection confirmed for parent={parent_hash}; "
          f"trace={target['trace']}; response_sha256={mutated_hash.group(1)}; diagnostic={rejected}; "
          f"snapshotIDs={sorted(parent_snapshots)}; dependentSignedRequests=0", flush=True)
    if cached_progress:
        print(f"D2C[proof-corrupt] legitimate cached-parent progress remained allowed; "
              f"cache-hit snapshots={len(cached_progress)}", flush=True)


def leader():
    # D2A-2 was reproduced with validator 2 holding the uncertified local proposal.
    # Keep this fault deterministic so the acceptance run proves that exact restarted
    # leader rejoins instead of killing whichever validator happens to lead first.
    candidates = [2] if SCENARIO == "leader-kill" else range(1, 5)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        for i in candidates:
            lines = Path(f"test-nodes/evm{i}/debug.log").read_text(errors="replace").splitlines()
            for line in reversed(lines[-100:]):
                round_match = re.search(r"(?:^|\s)round=(\d+)(?:\s|$)", line)
                if ('msg="submitting block certification request"' in line and "leader=true" in line
                        and round_match and int(round_match.group(1)) > LAST_ROUND):
                    print(f"D2C leader detected from logs: validator={i}; {line}", flush=True)
                    return i
        time.sleep(0.1)
    if SCENARIO == "leader-kill":
        raise RuntimeError("validator 2 did not become active leader within 40 seconds")
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
    import subprocess
    # Close the journal owner before editing its Bolt file offline.
    stop("evm", 1, "TERM")
    result = subprocess.run(["go", "run", "scripts/d2c-journal-edit.go",
        "delete-certified-height", "test-nodes/evm1/execution-journal.db", "5"],
        text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError("journal edit helper failed:\n"
                           f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    output = result.stdout
    print(output, end="", flush=True)
    print(f"D2C[missing-body] deleted certified candidate at B5; restarting validator 1", flush=True)
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
            record_expected_refusal(SCENARIO, failures[-1])
            raise SystemExit(0)
        syncing = [line for line in restart if "status syncing" in line.lower()]
        if syncing:
            print(f"D2C[missing-body] restarted validator remains SYNCING: {syncing[-1]}", flush=True)
            record_expected_refusal(SCENARIO, syncing[-1])
        else:
            raise RuntimeError("restarted validator neither rejected the journal nor reported SYNCING")
    except subprocess.CalledProcessError as exc:
        print(f"D2C[missing-body] restart refused after certified candidate body deletion: {exc}", flush=True)
        record_expected_refusal(SCENARIO, f"restart exited {exc.returncode} after deleting B{CERTIFIED} candidate")
        raise SystemExit(0)
    raise SystemExit(0)
elif SCENARIO == "wrong-genesis":
    print(f"D2C[wrong-genesis] testing alternate genesis against retained validator 1 datadir at B{CERTIFIED}", flush=True)
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
                record_expected_refusal(SCENARIO, f"reth exited {proc.returncode} on alternate genesis")
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
print(f"D2C[{SCENARIO}] reth heads after relaunch={after}; certified=B{CERTIFIED}; lag={lag}", flush=True)
