"""The real election on a DISPOSABLE fork of the pinned state (design section 2). One anvil per sample, spawned by this process on a free loopback port,
forking the authoritative node at the pinned block; the system caller is impersonated ONLY inside that fork; the fork is killed afterwards. Nothing is sent
to the authoritative node (it is only ever read through ReadOnlyRpc), `electNow` is never called, no clock is moved, and the simulated assignment is
discarded with the fork. Before any write the fork endpoint is VERIFIED: loopback host, the port this process chose, its own live child process, the
pinned chain id and the pinned block hash. A misconfigured URL can therefore never receive a transaction."""
import socket
import subprocess
import time
from urllib.parse import urlparse

import abi
from abi import calldata, dyn_array, dyn_struct_array, words
from chain import ForkRpc, RpcError

SYSTEM_CALLER = "0xff00000000000000000000000000000000000001"
OUTCOMES = ("Disabled", "NotDue", "Reserved", "NoCandidateRecorded")
REASONS = ("None", "InvalidProfile", "Cardinality", "MembershipChurn", "WeightChurn", "ReferenceCapacity", "ReservationRefused", "InternalFailure")


class ForkRefused(Exception):
    pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Fork:
    def __init__(self, source_url, pin, anvil="anvil", ready_timeout=60, port=None, command=None):
        self.source_url, self.pin, self.anvil = source_url, pin, anvil
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.rpc = ForkRpc(self.url)
        self.ready_timeout, self.proc = ready_timeout, None
        self.command = command or [anvil, "--fork-url", source_url, "--fork-block-number", str(pin["number"]), "--host", "127.0.0.1", "--port", str(self.port),
                                   "--auto-impersonate", "--base-fee", "0", "--gas-price", "0", "--silent"]

    def __enter__(self):
        self.proc = subprocess.Popen(self.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise ForkRefused(f"anvil exited with {self.proc.returncode}")
            try:
                self.rpc.chain_id()
                return self
            except RpcError:
                time.sleep(0.3)
        raise ForkRefused("anvil did not come up")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def verify(self):
        """Refuse unless every property that makes writes safe holds. Raises ForkRefused; on success the fork accepts the two writes."""
        u = urlparse(self.rpc.url)
        if u.hostname != "127.0.0.1" or u.port != self.port or self.rpc.url != self.url:
            raise ForkRefused(f"the fork URL {self.rpc.url} is not the loopback anvil this process spawned on port {self.port}")
        if self.proc is None or self.proc.poll() is not None:
            raise ForkRefused("the spawned anvil is not running")
        if self.source_url.rstrip("/") == self.rpc.url.rstrip("/"):
            raise ForkRefused("the fork URL is the source node's URL")
        try:
            cid = self.rpc.chain_id()
            blk = self.rpc.block(self.pin["number"])
        except RpcError as e:
            raise ForkRefused(f"the fork does not answer: {e}") from e
        if cid != self.pin["chainId"]:
            raise ForkRefused(f"the fork's chain id {cid} is not the pinned {self.pin['chainId']}")
        if blk["hash"].lower() != self.pin["hash"].lower():
            raise ForkRefused(f"the fork serves block {self.pin['number']} as {blk['hash']}, not the pinned {self.pin['hash']}")
        self.rpc.verified = True
        return {"port": self.port, "pid": self.proc.pid, "chainId": cid, "blockHash": blk["hash"]}


def _read_result(rpc, election, custody, inp_cursor_before):
    """The state the election left on the fork, as the compared fields."""
    r = lambda sig, *a: words(rpc.call(election, calldata(sig, *a), "latest"))  # noqa: E731
    cursor = r("attemptCursor()")[0]
    open_result = r("openResult()")[0].to_bytes(32, "big")
    out = {"attemptCursorAfter": cursor, "openResultAfter": "0x" + open_result.hex()}
    if cursor == inp_cursor_before:
        return out
    rid = r("lastAttemptResult()")[0].to_bytes(32, "big")
    res = r("result(bytes32)", rid)
    out.update(resultID="0x" + rid.hex(), reason=REASONS[res[1]], attempt=res[2], progress=res[3], ucTime=res[4], policyID=res[5], origin=abi.hexw(res[6]),
               predecessor=abi.hexw(res[7]), assignmentID=abi.hexw(res[8]), snapshotDigest=abi.hexw(res[9]), state=res[0])
    out["frozen"], out["members"], out["publication"], out["reservation"] = [], [], None, None
    if res[0] == 1:  # Reserved
        out["frozen"] = [{"id": x[0], "generation": x[1], "weight": x[2], "raw": x[3], "bindingHash": abi.hexw(x[4])}
                         for x in dyn_struct_array(r("frozenMembers(bytes32)", rid), 0, 5)]
        pw = r("publication(bytes32)", rid)
        out["publication"] = {"incumbent": abi.hexw(pw[2]), "incumbentExposureDigest": abi.hexw(pw[3]), "incumbentKeyDigest": abi.hexw(pw[4]),
                              "policyDigest": abi.hexw(pw[5]), "contractsDigest": abi.hexw(pw[6]), "kCommit": abi.hexw(pw[1]), "snapshotDigest": abi.hexw(pw[7]),
                              "assignmentID": abi.hexw(pw[8]), "attempt": pw[12]}
        aw = words(rpc.call(custody, calldata("assignments(bytes32)", res[8]), "latest"))
        out["reservation"] = {"state": aw[0], "lineage": abi.hexw(aw[1]), "rootEpoch": aw[2], "evmEpoch": aw[3], "policyID": aw[15]}
        for eid in dyn_array(words(rpc.call(custody, calldata("assignmentExposures(bytes32)", res[8]), "latest")), 0):
            e = words(rpc.call(custody, calldata("exposures(bytes32)", eid), "latest"))
            lots = dyn_array(words(rpc.call(custody, calldata("exposureLots(bytes32)", eid), "latest")), 0)
            out["members"].append({"id": e[1], "rootKeyHash": abi.hexw(e[5]), "evmKeyHash": abi.hexw(e[6]), "payee": abi.addr(e[7]), "weight": e[3], "rawWeight": e[4],
                                   "lots": lots})
    else:
        out.update(frozen=[], members=[], publication=None, reservation=None, policyID=0)
    return out


def simulate(source_url, pin, modules, origin, cursor_before, anvil="anvil", system_caller=SYSTEM_CALLER, fork_factory=Fork):
    """Run the election on a fork of `pin` and return (contract output, fork evidence). `origin` is the 32-byte origin identity the hook would pass."""
    with fork_factory(source_url, pin, anvil=anvil) as fk:
        evidence = fk.verify()
        election, custody = modules["election"], modules["custody"]
        data = calldata("elect(bytes32)", origin)
        outcome = OUTCOMES[words(fk.rpc.call_from(system_caller, election, data))[0]]
        status = fk.rpc.send(system_caller, election, data)
        if status != 1:
            raise RpcError("the simulated elect transaction reverted on the fork")
        out = _read_result(fk.rpc, election, custody, cursor_before)
        out["outcome"] = outcome
        out.setdefault("reason", "None")
        return out, evidence
