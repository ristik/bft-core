"""Reading the chain for the shadow adapter. `ReadOnlyRpc` can call and read only: the authoritative node is never written to by this tool, by construction
(there is no send method). `ForkRpc` may send, and only after `verify()` proved that its URL is the loopback anvil this process spawned, on the pinned chain
id, serving the pinned block hash."""
import json
import time
import urllib.request

READ_METHODS = frozenset({"eth_call", "eth_getBlockByNumber", "eth_getStorageAt", "eth_getCode", "eth_chainId", "eth_blockNumber", "web3_clientVersion"})


class RpcError(Exception):
    pass


class ReadOnlyRpc:
    def __init__(self, url, timeout=20):
        self.url, self.timeout, self._id = url, timeout, 0

    def _post(self, method, params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.load(r)
        except OSError as e:
            raise RpcError(f"{method}: {e}") from e
        if "error" in out:
            raise RpcError(f"{method}: {out['error']}")
        return out["result"]

    def request(self, method, params):
        if method not in READ_METHODS:
            raise RpcError(f"{method} is not a read method: this endpoint is read-only")
        return self._post(method, params)

    def chain_id(self):
        return int(self.request("eth_chainId", []), 16)

    def block(self, tag):
        b = self.request("eth_getBlockByNumber", [tag if isinstance(tag, str) else hex(tag), False])
        if b is None:
            raise RpcError(f"no block {tag}")
        return b

    def call(self, to, data, block):
        return bytes.fromhex(self.request("eth_call", [{"to": to, "data": "0x" + data.hex()}, block])[2:])

    def storage(self, addr, slot, block):
        return bytes.fromhex(self.request("eth_getStorageAt", [addr, "0x" + slot.hex(), block])[2:].rjust(64, "0"))

    def code(self, addr, block):
        return bytes.fromhex(self.request("eth_getCode", [addr, block])[2:])


class ForkRpc(ReadOnlyRpc):
    """The disposable fork. Everything of ReadOnlyRpc plus the two writes the simulation needs; refuses them until verified."""
    WRITE_METHODS = frozenset({"eth_sendTransaction", "eth_getTransactionReceipt", "evm_mine"})

    def __init__(self, url, **kw):
        super().__init__(url, **kw)
        self.verified = False

    def request(self, method, params):
        if method in self.WRITE_METHODS:
            if not self.verified:
                raise RpcError(f"{method} refused: the fork endpoint is not verified")
            return self._post(method, params)
        return super().request(method, params)

    def call_from(self, frm, to, data, block="latest"):
        out = self.request("eth_call", [{"from": frm, "to": to, "data": "0x" + data.hex()}, block])
        return bytes.fromhex(out[2:])

    def send(self, frm, to, data, wait=20.0):
        """A transaction on the (verified) fork from an impersonated account; polls for the receipt (anvil mines a moment after accepting it) and returns its
        status (1 = success). A receipt that never arrives is an RpcError."""
        txh = self.request("eth_sendTransaction", [{"from": frm, "to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000), "gasPrice": "0x0"}])
        deadline = time.monotonic() + wait
        while True:
            rec = self.request("eth_getTransactionReceipt", [txh])
            if rec is not None:
                return int(rec["status"], 16)
            if time.monotonic() > deadline:
                raise RpcError(f"no receipt for {txh} within {wait}s")
            time.sleep(0.2)
