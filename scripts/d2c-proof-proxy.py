#!/usr/bin/env python3
"""Local JSON-RPC proxy with controlled proof outage and corruption modes."""

import argparse
import hashlib
import itertools
import json
import threading
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
sequence = itertools.count(1)
sequence_lock = threading.Lock()
log_lock = threading.Lock()


def log(message):
    with log_lock, log_path.open("a") as stream:
        stream.write(f"{time.time():.6f} {message}\n")


def read_control():
    try:
        return json.loads(control.read_text())
    except (OSError, json.JSONDecodeError):
        return {"mode": "pass"}


def request_ref(method, params):
    if not isinstance(params, list) or not params:
        return "unknown"
    selector = params[0] if method == "debug_getRawHeader" else params[-1]
    if isinstance(selector, dict):
        selector = selector.get("blockHash", selector.get("blockNumber", "unknown"))
    if isinstance(selector, str):
        return selector.removeprefix("0x").lower()
    return "unknown"


def flip_hex(value):
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 4:
        return None
    flipped = "1" if value[2].lower() == "0" else "0"
    return "0x" + flipped + value[3:]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        request_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        request = json.loads(request_body)
        method = request.get("method", "") if isinstance(request, dict) else ""
        params = request.get("params", [])
        reference = request_ref(method, params)
        with sequence_lock:
            trace = str(next(sequence))
        state = read_control()
        now = time.time()
        active = method in METHODS and now < float(state.get("until", 0))
        mode = state.get("mode", "pass") if active else "pass"
        released = {str(item) for item in state.get("release", [])}
        if active and state.get("hold") and trace not in released:
            mode = "hold"

        if method in METHODS:
            log(f"fetch trace={trace} method={method} id={request.get('id')} parent={reference} "
                f"params={json.dumps(params, separators=(',', ':'), sort_keys=True)} mode={mode}")

        if mode == "hold" and method in METHODS:
            log(f"held trace={trace} method={method} parent={reference}")
            deadline = min(float(state.get("until", now + 120)), now + 120)
            while time.time() < deadline:
                state = read_control()
                if trace in {str(item) for item in state.get("release", [])}:
                    mode = ("pass" if trace in {str(item) for item in state.get("pass_release", [])}
                            else state.get("mode", "pass"))
                    if time.time() >= float(state.get("until", 0)):
                        mode = "pass"
                    log(f"release trace={trace} method={method} parent={reference} mode={mode}")
                    break
                if not state.get("hold", False):
                    mode = state.get("mode", "pass")
                    if time.time() >= float(state.get("until", 0)):
                        mode = "pass"
                    log(f"release trace={trace} method={method} parent={reference} mode={mode}")
                    break
                time.sleep(0.02)
            else:
                self.send_error(504, "D2C held proof request was not released")
                log(f"hold-timeout trace={trace} method={method} parent={reference}")
                return

        if mode == "outage" and method in METHODS:
            log(f"drop trace={trace} method={method} id={request.get('id')} parent={reference} "
                f"params={json.dumps(params, separators=(',', ':'), sort_keys=True)}")
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

        if mode == "corrupt" and method in METHODS:
            try:
                answer = json.loads(payload)
            except json.JSONDecodeError:
                log(f"unable-to-corrupt trace={trace} method={method} parent={reference} reason=invalid-json")
            else:
                result = answer.get("result")
                changed = False
                if method == "debug_getRawHeader":
                    changed_value = flip_hex(result)
                    if changed_value is not None:
                        result, changed = changed_value, True
                elif isinstance(result, dict):
                    proof_nodes = result.get("accountProof") or []
                    if not proof_nodes and result.get("storageProof"):
                        proof_nodes = result["storageProof"][0].get("proof", [])
                    if proof_nodes:
                        changed_value = flip_hex(proof_nodes[0])
                        if changed_value is not None:
                            proof_nodes[0] = changed_value
                            changed = True
                if changed:
                    answer["result"] = result
                    payload = json.dumps(answer).encode()
                    digest = hashlib.sha256(payload).hexdigest()
                    log(f"mutate trace={trace} mutation={trace} method={method} id={request.get('id')} "
                        f"parent={reference} params={json.dumps(params, separators=(',', ':'), sort_keys=True)} "
                        f"response_sha256={digest}")
                else:
                    log(f"unable-to-corrupt trace={trace} method={method} parent={reference}")
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
