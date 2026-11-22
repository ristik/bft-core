#!/usr/bin/env python3
"""Loopback RPC for the on-host validator operator, with bounded registration log reads."""
import argparse
import http.client
import ipaddress
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from gateway import LOG_BLOCK_RANGE, MAX_BODY, MAX_RESULT_BYTES, check_log_filter


def operator_request(request, forward):
    if request.get('method') != 'eth_getLogs':
        return forward(request)
    params = request.get('params')
    if not (isinstance(params, list) and len(params) == 1 and isinstance(params[0], dict)
            and params[0].get('toBlock') == 'latest'):
        return forward(request)
    bounds = params[0]
    if 'blockHash' in bounds:
        raise ValueError('log filter mixes a block hash and a range')
    status, head = forward({'jsonrpc': '2.0', 'id': 0, 'method': 'eth_blockNumber', 'params': []})
    if status != 200 or 'result' not in head:
        raise ValueError('could not resolve latest')
    first, last = int(bounds['fromBlock'], 16), int(head['result'], 16)
    if first > last:
        raise ValueError('log range begins after latest')
    logs = []
    size = 0
    for start in range(first, last + 1, LOG_BLOCK_RANGE):
        page = {**bounds, 'fromBlock': hex(start), 'toBlock': hex(min(start + LOG_BLOCK_RANGE - 1, last))}
        check_log_filter([page])
        status, response = forward({**request, 'params': [page]})
        if status != 200 or 'result' not in response:
            return status, response
        size += len(json.dumps(response['result']))
        if size > MAX_RESULT_BYTES:
            raise ValueError('registration log responses exceed the operator RPC limit')
        logs.extend(response['result'])
    return 200, {'jsonrpc': '2.0', 'id': request.get('id'), 'result': logs}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gateway-port', type=int, default=8545)
    p.add_argument('--listen-port', type=int, default=18485)
    p.add_argument('--client-ip', type=ipaddress.ip_address, default=ipaddress.ip_address('127.0.0.1'))
    a = p.parse_args()
    last = 0.0

    def forward(obj):
        nonlocal last
        # Leave room for the gateway's per-client and heavy-read limits.
        interval = 0.55 if obj.get('method') == 'eth_getLogs' else 0.14
        time.sleep(max(0.0, last + interval - time.monotonic()))
        last = time.monotonic()
        conn = http.client.HTTPConnection('127.0.0.1', a.gateway_port, timeout=20)
        try:
            conn.request('POST', '/', json.dumps(obj), {'X-Forwarded-For': str(a.client_ip), 'Content-Type': 'application/json'})
            response = conn.getresponse()
            return response.status, json.loads(response.read(MAX_RESULT_BYTES + 1024))
        finally:
            conn.close()

    class Handler(BaseHTTPRequestHandler):
        timeout = 20

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if self.path != '/' or not 0 < length <= MAX_BODY:
                    raise ValueError('expected a bounded JSON-RPC request')
                status, body = operator_request(json.loads(self.rfile.read(length)), forward)
            except (ValueError, TypeError, KeyError, AttributeError, OSError, http.client.HTTPException) as error:
                status, body = 503, {'error': str(error)}
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    with HTTPServer(('127.0.0.1', a.listen_port), Handler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
