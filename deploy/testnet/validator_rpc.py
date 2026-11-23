#!/usr/bin/env python3
"""Loopback RPC for the on-host validator operator, with bounded registration log reads."""
import argparse
import http.client
import ipaddress
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

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
    p.add_argument('--upstream', help='the public HTTPS RPC, or a private loopback HTTP gateway')
    p.add_argument('--allow-private-http', action='store_true', help='private rehearsal access to an IPv4 bridge gateway')
    p.add_argument('--listen-port', type=int, default=18485)
    p.add_argument('--listen-ip', type=ipaddress.IPv4Address, default=ipaddress.IPv4Address('127.0.0.1'))
    p.add_argument('--client-ip', type=ipaddress.ip_address, default=ipaddress.ip_address('127.0.0.1'))
    a = p.parse_args()
    if not (a.listen_ip.is_loopback or (a.allow_private_http and a.listen_ip.is_private and not a.listen_ip.is_unspecified)):
        p.error('the operator adapter must listen on loopback or a private rehearsal gateway')
    upstream = urlsplit(a.upstream or f'http://127.0.0.1:{a.gateway_port}/')
    private = upstream.hostname == '127.0.0.1'
    if not private and a.allow_private_http:
        try:
            private = ipaddress.IPv4Address(upstream.hostname).is_private
        except (TypeError, ValueError):
            pass
    if (not upstream.hostname or upstream.username or upstream.password or upstream.query or upstream.fragment
            or (upstream.scheme != 'https' and (upstream.scheme != 'http' or not private))):
        p.error('upstream must be HTTPS or an allowed private HTTP gateway')
    last = 0.0

    def forward(obj):
        nonlocal last
        # Leave room for the gateway's per-client and heavy-read limits.
        interval = 0.55 if obj.get('method') == 'eth_getLogs' else 0.14
        time.sleep(max(0.0, last + interval - time.monotonic()))
        last = time.monotonic()
        connection = http.client.HTTPSConnection if upstream.scheme == 'https' else http.client.HTTPConnection
        conn = connection(upstream.hostname, upstream.port, timeout=20)
        try:
            conn.request('POST', upstream.path or '/', json.dumps(obj), {'X-Forwarded-For': str(a.client_ip), 'Content-Type': 'application/json'})
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

    with HTTPServer((str(a.listen_ip), a.listen_port), Handler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
