#!/usr/bin/env python3
"""Small local JSON-RPC proxy with a file-controlled proof fault mode."""

import argparse
import json
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--listen", required=True)
parser.add_argument("--target", required=True)
parser.add_argument("--control", required=True)
parser.add_argument("--log", required=True)
args = parser.parse_args()
control = Path(args.control)
log_path = Path(args.log)
METHODS = {"debug_getRawHeader", "eth_getProof"}


def log(message):
    with log_path.open("a") as stream:
        stream.write(f"{time.time():.3f} {message}\n")


def flip_hex(value):
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 4:
        return None
    char = value[2].lower()
    flipped = "1" if char == "0" else "0"
    return "0x" + flipped + value[3:]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        request_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        request = json.loads(request_body)
        method = request.get("method", "") if isinstance(request, dict) else ""
        state = json.loads(control.read_text()) if control.exists() else {"mode": "pass"}
        active = method in METHODS and time.time() < float(state.get("until", 0))
        mode = state.get("mode", "pass") if active else "pass"
        if mode == "outage":
            log(f"drop method={method}")
            answer = {"jsonrpc": "2.0", "id": request.get("id"),
                      "error": {"code": -32098, "message": "D2C injected proof RPC outage"}}
            self._send(json.dumps(answer).encode())
            return
        try:
            req = urllib.request.Request(args.target, request_body,
                                         {"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as response:
                payload = response.read()
        except (OSError, urllib.error.URLError) as exc:
            self.send_error(502, str(exc))
            return
        if mode == "corrupt":
            answer = json.loads(payload)
            result = answer.get("result")
            if method == "debug_getRawHeader":
                result, changed = flip_hex(result), flip_hex(result) is not None
            else:
                changed = False
                if isinstance(result, dict):
                    proof_nodes = result.get("accountProof") or []
                    if not proof_nodes and result.get("storageProof"):
                        proof_nodes = result["storageProof"][0].get("proof", [])
                    if proof_nodes:
                        flipped = flip_hex(proof_nodes[0])
                        if flipped is not None:
                            proof_nodes[0] = flipped
                            changed = True
            if changed:
                answer["result"] = result
                payload = json.dumps(answer).encode()
                log(f"corrupt method={method}")
            else:
                log(f"unable-to-corrupt method={method}")
        self._send(payload)

    def _send(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


listen_host, listen_port = args.listen.rsplit(":", 1)
server = ThreadingHTTPServer((listen_host, int(listen_port)), Handler)
log(f"listening={args.listen} target={args.target}")
server.serve_forever()
