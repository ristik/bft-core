#!/usr/bin/env python3
"""Self-test for the finality monitor's failure classification: only a failure to reach an endpoint (TransportError) may be
excused by a planned restart or restore; a finality violation must stay a plain CheckError. Run from the repository root."""

import importlib.util
import json
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

spec = importlib.util.spec_from_file_location("finality_rpc", Path(__file__).with_name("finality-rpc.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FINAL_HASH = "0x" + "ab" * 32


class Stub(BaseHTTPRequestHandler):
    mode = "violation"

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.mode == "garbage":
            data = b"not json"
        elif self.mode == "null":
            data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": None}).encode()
        else:
            tag = body["params"][0]
            block = {"number": "0x5", "hash": FINAL_HASH if tag == "finalized" else "0x" + "cd" * 32}
            data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": block}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # operator status
        data = json.dumps({"certifiedTip": {"height": 9, "hash": "0x" + "ee" * 32}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def expect(kind, fn, label):
    try:
        fn()
    except kind as exc:
        if kind is mod.CheckError and isinstance(exc, mod.EXCUSABLE):
            sys.exit(f"FAIL {label}: a finality violation was classified as excusable: {exc}")
        print(f"PASS {label}: {type(exc).__name__}")
        return
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"FAIL {label}: wrong error {type(exc).__name__}: {exc}")
    sys.exit(f"FAIL {label}: no error")


server = HTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=server.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{server.server_port}"
with tempfile.TemporaryDirectory() as tmp:
    log = Path(tmp) / "debug.log"
    log.write_text("")  # the finalized candidate has no certificate-admitted record

    dead = f"http://127.0.0.1:{closed_port()}"
    expect(mod.TransportError, lambda: mod.check_finalized(dead, base, log), "an unreachable RPC is a transport error")
    expect(mod.TransportError, lambda: mod.check_finalized(base, dead, log), "an unreachable status listener is a transport error")
    expect(mod.CheckError, lambda: mod.check_finalized(base, base, log), "an uncertified finalized candidate is a finality violation")
    Stub.mode = "null"
    expect(mod.NotReadyError, lambda: mod.check_finalized(base, base, log), "a restored client with no finalized block yet is not-ready, which is excusable")
    Stub.mode = "garbage"
    expect(mod.CheckError, lambda: mod.check_finalized(base, base, log), "a malformed answer is a finality violation, not an outage")
print("finality monitor classification OK")
