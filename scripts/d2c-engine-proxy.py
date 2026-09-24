#!/usr/bin/env python3
"""Forward one leader's Engine API and mutate one armed built payload."""

import argparse
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from Crypto.Hash import keccak


parser = argparse.ArgumentParser()
parser.add_argument("--listen", required=True)
parser.add_argument("--target", required=True)
parser.add_argument("--control", required=True)
parser.add_argument("--log", required=True)
args = parser.parse_args()
control = Path(args.control)
log_path = Path(args.log)
state_lock = threading.Lock()
log_lock = threading.Lock()
armed_payload_id = None
sequence = 0
payload_attributes = {}

EMPTY_ROOT = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
EMPTY_UNCLES = bytes.fromhex("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")


def log(message):
    with log_lock, log_path.open("a") as stream:
        stream.write(f"{time.time():.6f} {message}\n")


def control_armed():
    try:
        state = json.loads(control.read_text())
        return state.get("armed") is True
    except (OSError, json.JSONDecodeError):
        return False



def rlp_bytes(value):
    if len(value) == 1 and value[0] < 0x80:
        return value
    if len(value) < 56:
        return bytes([0x80 + len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([0xb7 + len(length)]) + length + value


def rlp_int(value):
    return rlp_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rlp_list(items):
    body = b"".join(items)
    if len(body) < 56:
        return bytes([0xc0 + len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0xf7 + len(length)]) + length + body


def payload_header_hash(payload, attributes, gas_used):
    if payload.get("transactions") != [] or payload.get("withdrawals") != []:
        raise ValueError("hostile gasUsed mutation expects the empty-transaction, empty-withdrawal lane")

    def data(name):
        return bytes.fromhex(payload[name].removeprefix("0x"))

    def quantity(name, override=None):
        value = payload[name] if override is None else override
        return int(value, 16) if isinstance(value, str) else int(value)

    parent_beacon_root = attributes.get("parentBeaconBlockRoot")
    if not isinstance(parent_beacon_root, str):
        raise ValueError("build attributes lack parentBeaconBlockRoot")
    fields = [
        rlp_bytes(data("parentHash")),
        rlp_bytes(EMPTY_UNCLES),
        rlp_bytes(data("feeRecipient")),
        rlp_bytes(data("stateRoot")),
        rlp_bytes(EMPTY_ROOT),
        rlp_bytes(data("receiptsRoot")),
        rlp_bytes(data("logsBloom")),
        rlp_int(0),
        rlp_int(quantity("blockNumber")),
        rlp_int(quantity("gasLimit")),
        rlp_int(gas_used),
        rlp_int(quantity("timestamp")),
        rlp_bytes(data("extraData")),
        rlp_bytes(data("prevRandao")),
        rlp_bytes(bytes(8)),
        rlp_int(quantity("baseFeePerGas")),
        rlp_bytes(EMPTY_ROOT),
        rlp_int(quantity("blobGasUsed")),
        rlp_int(quantity("excessBlobGas")),
        rlp_bytes(bytes.fromhex(parent_beacon_root.removeprefix("0x"))),
    ]
    digest = keccak.new(digest_bits=256)
    digest.update(rlp_list(fields))
    return "0x" + digest.hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        global armed_payload_id, sequence
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return
        method = request.get("method", "") if isinstance(request, dict) else ""
        params = request.get("params", [])
        with state_lock:
            sequence += 1
            trace = sequence
        payload_id = (str(params[0]).lower() if method == "engine_getPayloadWithSealV1"
                      and isinstance(params, list) and params else None)
        log(f"request trace={trace} method={method} id={request.get('id')} payloadId={payload_id or '-'}")

        headers = {key: value for key, value in self.headers.items()
                   if key.lower() in {"content-type", "authorization"}}
        req = urllib.request.Request(args.target, body, headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                payload = response.read()
                response_headers = response.headers
                status = response.status
        except (OSError, urllib.error.URLError) as exc:
            log(f"upstream-error trace={trace} method={method} error={type(exc).__name__}")
            self.send_error(502, str(exc))
            return

        mutate = False
        if method == "engine_forkchoiceUpdatedWithSealV1" and control_armed():
            try:
                answer = json.loads(payload)
                result = answer.get("result", {})
                payload_status = result.get("payloadStatus", {}).get("status")
                candidate_id = result.get("payloadId")
                if payload_status == "VALID" and isinstance(candidate_id, str):
                    params = request.get("params", [])
                    attrs = params[1] if isinstance(params, list) and len(params) > 1 else {}
                    with state_lock:
                        if control_armed() and armed_payload_id is None:
                            armed_payload_id = candidate_id.lower()
                            payload_attributes[candidate_id.lower()] = attrs
                    log(f"build-bound trace={trace} payloadId={candidate_id.lower()} status=VALID")
            except (json.JSONDecodeError, AttributeError):
                pass

        if method == "engine_getPayloadWithSealV1" and payload_id:
            with state_lock:
                if armed_payload_id == payload_id and control_armed():
                    mutate = True
                    armed_payload_id = None
        if mutate:
            try:
                answer = json.loads(payload)
                result = answer["result"]
                execution_payload = result["executionPayload"]
                old_gas_used = int(execution_payload["gasUsed"], 16)
                new_gas_used = old_gas_used + 1
                old_block_hash = execution_payload["blockHash"]
                attrs = payload_attributes.pop(payload_id, {})
                computed_original = payload_header_hash(execution_payload, attrs, old_gas_used)
                if computed_original.lower() != old_block_hash.lower():
                    raise ValueError(f"header hash reconstruction mismatch: expected {old_block_hash}, "
                                     f"computed {computed_original}")
                execution_payload["gasUsed"] = hex(new_gas_used)
                execution_payload["blockHash"] = payload_header_hash(execution_payload, attrs, new_gas_used)
                payload = json.dumps(answer, separators=(",", ":")).encode()
                digest = hashlib.sha256(payload).hexdigest()
                log(f"MUTATED pending-release trace={trace} method={method} id={request.get('id')} payloadId={payload_id} "
                    f"blockHash={old_block_hash}->{execution_payload['blockHash']} "
                    f"gasUsed={old_gas_used}->{new_gas_used} "
                    f"response_sha256={digest}")
                release_deadline = time.monotonic() + 30
                while time.monotonic() < release_deadline:
                    try:
                        if json.loads(control.read_text()).get("release_mutation") is True:
                            log(f"MUTATION-RELEASED trace={trace} payloadId={payload_id}")
                            break
                    except (OSError, json.JSONDecodeError):
                        pass
                    time.sleep(0.02)
                else:
                    log(f"MUTATION-RELEASE-TIMEOUT trace={trace} payloadId={payload_id}")
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                log(f"MUTATION-FAILED trace={trace} payloadId={payload_id} error={exc}")

        self.send_response(status)
        self.send_header("Content-Type", response_headers.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


host, port = args.listen.rsplit(":", 1)
server = ThreadingHTTPServer((host, int(port)), Handler)
log(f"listening={args.listen} target={args.target}")
server.serve_forever()
